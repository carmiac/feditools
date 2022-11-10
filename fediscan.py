#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

# Mastodon Network Analyzer
import argparse
import argcomplete
import concurrent.futures
import random
from threading import Lock
import time
import yaml
import os
from mastodon import Mastodon
import signal

# TODO: Add a way resume a scan from a previous run.
# TODO: Better progress bar
# TODO: Improve visualization - probably seperate tool


class MastodonScanner:
    def __init__(
        self,
        host_limit=None,
        peer_limit=None,
        verbose=False,
        progress=False,
        workers=None,
        timeout=300,
    ):
        self.starting_hosts = set()
        self.host_limit = host_limit
        self.peer_limit = peer_limit
        self.verbose = verbose
        self.progress = progress
        self.workers = workers
        self.timeout = timeout
        self.peer_results = {}  # {host: [peer1, peer2, ...], ...}
        self.instance_info = {}  # {host: instance_info, ...}
        self.start_time = None
        self.end_time = None
        self.scans_total = 0  # Total number of scans to perform, either host_limit or len(peers_scanned) + len(hosts_to_scan)
        self.scans_completed = 0  # Number of scans completed successfully
        self.scans_failed = 0  # Number of scans that failed (timeout, etc)
        self.scans_remaining = 0  # Number of scans remaining to be completed, either host_limit - scans_completed or len(hosts_to_scan)
        self.scans_this_round = 0  # Number of scans to perform this round
        self.keep_scanning = False  # Whether to keep scanning or not
        self._scan_futures = []  # List of futures for the current round of scans
        self._unscanned_hosts = set()  # {host1, host2, ...}

    def _get_instance_info_and_peers(self, url):
        """Get instance info and peers from a single mastodon instance."""
        mastodon = Mastodon(api_base_url=url, request_timeout=self.timeout)
        try:
            instance = mastodon.instance()
        except Exception as e:
            if self.verbose:
                print(f"Failed to get instance info from {url}: {e}")
            instance = None
        try:
            peers = mastodon.instance_peers()
        except Exception as e:
            if self.verbose:
                print(f"Failed to get peers from {url}: {e}")
            peers = None
        return instance, peers

    def _print_progress_update(self, host):
        """Print current scanning progress."""
        self.elapsed_time = time.time() - self.start_time
        time_per_task = (
            self.elapsed_time / self.scans_completed if self.scans_completed else 0
        )
        time_remaining = time_per_task * self.scans_remaining

        print(f"Scanned: {self.scans_completed} ", end="")
        print(f"P Results: {len(self.peer_results)} ", end="")
        print(f"I Results: {len(self.instance_info)} ", end="")
        print(f"Failed: {self.scans_failed} ", end="")
        print(f"Remaining: {self.scans_remaining} ", end="")
        print(f"Est Remaining Time: {time_remaining:.1f} seconds ", end="")
        print(f"Host: {host}")

    def _get_hosts_for_round(self):
        if self.host_limit:
            hosts_this_round = set()
            while (
                len(hosts_this_round) < (self.host_limit - len(self.peer_results))
                and self._unscanned_hosts
            ):
                hosts_this_round.add(self._unscanned_hosts.pop())
            self.scans_this_round = len(hosts_this_round)
            self.scans_remaining_this_round = self.scans_this_round
            self.scans_remaining = self.host_limit - len(self.peer_results)
            self.scans_total = len(self.peer_results) + self.scans_remaining
        else:
            hosts_this_round = self._unscanned_hosts
            self._unscanned_hosts = set()
            self.scans_this_round = len(hosts_this_round)
            self.scans_remaining_this_round = self.scans_this_round
            self.scans_remaining = self.scans_this_round + len(self._unscanned_hosts)
            self.scans_total = len(self.peer_results) + self.scans_remaining
        return hosts_this_round

    def cancel_scan(self):
        """Cancel the current round of scans."""
        self.keep_scanning = False
        for future in self._scan_futures:
            future.cancel()

    def scan(self, host_list):
        self.start_time = time.time()
        self.keep_scanning = True
        # Create an initial set of hosts to scan
        self._unscanned_hosts = set(host_list)
        self.starting_hosts = set(host_list)
        # Start scanning the set of unscanned hosts.
        while self._unscanned_hosts and self.keep_scanning:
            if self.verbose:
                print(f"Total known unscanned hosts: {len(self._unscanned_hosts)}")
                print(f"Total scanned hosts: {len(self.peer_results)}")
            # Get the hosts for this round of scanning and update task counters.
            hosts_this_round = self._get_hosts_for_round()
            # Print the current progress.
            if self.verbose:
                print(f"Scanning {self.scans_this_round} hosts this round.")
                print(f"Total scans remaining: {self.scans_remaining}")
                print(f"Total scans to perform: {self.scans_total}")

            # Scan the hosts in parallel using concurrent.futures.
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.workers
            ) as executor:
                self._scan_futures = {
                    executor.submit(self._get_instance_info_and_peers, host): host
                    for host in hosts_this_round
                }
                try:
                    for future in concurrent.futures.as_completed(
                        self._scan_futures, timeout=self.timeout
                    ):
                        host = self._scan_futures[future]
                        self.scans_remaining_this_round -= 1
                        try:
                            instance, peers = future.result()
                        except Exception as exc:
                            self.scans_failed += 1
                            if self.verbose:
                                print(f"Error: {host} generated an exception: {exc}")
                        else:
                            self.scans_completed += 1
                            self.process_scan_result(host, instance, peers)
                        if self.progress:
                            self._print_progress_update(host)
                except concurrent.futures.TimeoutError:
                    # Count the remaining tasks as failed.
                    self.scans_failed += self.scans_remaining_this_round
                    if self.verbose:
                        print(
                            f"Timeout Error:{self.scans_remaining_this_round} hosts timed out."
                        )
            # Check if we reached the host limit.
            if self.host_limit and len(self.peer_results) >= self.host_limit:
                if self.verbose:
                    print(f"Reached host limit of {self.host_limit}")
                break
        self.end_time = time.time()

    def process_scan_result(self, host, instance, peers):
        """Process the results of a single scan."""
        if not peers and not instance:
            self.scans_failed += 1
            return
        if peers:
            self.scans_remaining -= 1
            if self.verbose:
                print(f"{host} has {len(peers)} peers")
            # Limit the number of peers if requested.
            if self.peer_limit:
                peers = random.sample(peers, min(self.peer_limit, len(peers)))
            # Add the peers to the results and the hosts to scan.
            self.peer_results[host] = peers
            for peer in peers:
                if peer not in self.peer_results:
                    self._unscanned_hosts.add(peer)
        else:
            if self.verbose:
                print(f"{host} has no peers")
        if instance:
            self.instance_info[host] = instance


def write_results_to_file(scanner, directory):
    """Write the results of the scan to several files."""
    # Create the directory if it doesn't exist.
    os.makedirs(directory, exist_ok=True)
    # Write the run metadata to a file.
    with open(os.path.join(directory, "run_metadata.yaml"), "w") as f:
        yaml.dump(
            {
                "starting_hosts": scanner.starting_hosts,
                "start_time": scanner.start_time,
                "end_time": scanner.end_time,
                "elapsed_time": scanner.end_time - scanner.start_time,
                "host_limit": scanner.host_limit,
                "peer_limit": scanner.peer_limit,
                "workers": scanner.workers,
                "timeout": scanner.timeout,
                "verbose": scanner.verbose,
                "scans_completed": scanner.scans_completed,
                "scans_failed": scanner.scans_failed,
                "scans_remaining": scanner.scans_remaining,
                "scans_total": scanner.scans_total,
                "hosts_with_peers": len(scanner.peer_results),
                "hosts_with_instance_info": len(scanner.instance_info),
            },
            f,
            indent=4,
        )
    # Write the peer results to a file.
    with open(os.path.join(directory, "peers.csv"), "w", encoding="utf-8") as f:
        # Write the results in a CSV format that can be used by networkx
        f.write("source,target\n")
        for host, peers in scanner.peer_results.items():
            for peer in peers or []:
                f.write(f"{host},{peer}\n")
    # Write the instance info to a file.
    with open(os.path.join(directory, "instances.yaml"), "w", encoding="utf-8") as f:
        yaml.dump(scanner.instance_info, f, indent=4)


def print_stats(scanner):
    """Print the results of the scan."""
    print(f"Scan completed in {scanner.end_time - scanner.start_time:.1f} seconds.")
    hosts = set()
    for host, peers in scanner.peer_results.items():
        if peers:
            hosts.add(host)
    for host, instance in scanner.instance_info.items():
        if instance:
            hosts.add(host)
    print(f"Scanned {len(hosts)} total unique hosts.")
    print(f"Total hosts with instance info: {len(scanner.instance_info)}")
    print(f"Total hosts with peer info: {len(scanner.peer_results)}")
    print(f"Total scans completed: {scanner.scans_completed}")
    print(f"Total scans failed: {scanner.scans_failed}")
    print(f"Total scans remaining: {scanner.scans_remaining}")
    print(f"Total scans attempted: {scanner.scans_total}")


def print_results(scanner):
    hosts = set()
    for host, peers in scanner.peer_results.items():
        if peers:
            hosts.add(host)
    for host, instance in scanner.instance_info.items():
        if instance:
            hosts.add(host)
    for host in hosts:
        print(f"Host: {host}")
        if host in scanner.instance_info:
            print(f"  Instance Info:")
            print(f"    URI: {scanner.instance_info[host]['uri']}")
            print(f"    Title: {scanner.instance_info[host]['title']}")
            print(f"    Description: {scanner.instance_info[host]['description']}")
            print(f"    Email: {scanner.instance_info[host]['email']}")
            print(f"    Version: {scanner.instance_info[host]['version']}")
            print(f"    Stats:")
            print(
                f"      User Count: {scanner.instance_info[host]['stats']['user_count']}"
            )
            print(
                f"      Status Count: {scanner.instance_info[host]['stats']['status_count']}"
            )
            print(
                f"      Domain Count: {scanner.instance_info[host]['stats']['domain_count']}"
            )
        if host in scanner.peer_results:
            print(f"  Peers for host: {host}")
            for peer in peers or ["No peers found"]:
                print(f"\t{peer}")


def main(args):
    print(f"Scanning the mastodon federation network starting from: {args.host_list}")
    scanner = MastodonScanner(
        host_limit=args.host_limit,
        peer_limit=args.peer_limit,
        verbose=args.verbose,
        progress=args.progress,
        workers=args.workers,
        timeout=args.timeout,
    )
    # Create a sigterm handler to stop the scanner and register it.
    def sigterm_handler(_signo, _stack_frame):
        print(f"Stopping scanner. This may take up to {args.timeout} seconds.")
        scanner.cancel_scan()

    signal.signal(signal.SIGINT, sigterm_handler)

    scanner.scan(args.host_list)

    print(f"Done!")
    if args.stats:
        print_stats(scanner)
    if args.results:
        print_results(scanner)

    # Output the results in a nice format that can be used by other programs.
    if args.output:
        print(f"Writing results to {args.output}")
        write_results_to_file(scanner, args.output)

    # Create a graph of the network using networkx and pyvis
    if args.graph:
        import networkx as nx
        from pyvis.network import Network

        G = nx.from_dict_of_lists(scanner.peer_results, create_using=nx.DiGraph)
        net = Network(notebook=False)
        net.from_nx(G)
        net.show("test.html")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mastodon Network Analyzer")
    parser.add_argument("-v", "--verbose", help="Verbose mode.", action="store_true")
    parser.add_argument(
        "host_list",
        type=str,
        nargs="+",
        help="Starting Mastodon hosts, e.g. mas.to mastodon.social",
    )
    parser.add_argument(
        "--host_limit",
        type=int,
        help="Maximum number of hosts to scan. Default is unlimited.",
        default=None,
    )
    parser.add_argument(
        "--peer_limit",
        type=int,
        help="Limit number of peers to add to scanning list from each host. Default is unlimited.",
        default=None,
    )
    parser.add_argument(
        "--workers",
        type=int,
        help="Number of workers to use. Default is the number of CPUs + 4.",
        default=None,
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Timeout for mastodon connections in seconds. Default %(default)s",
        default=30,
    )
    parser.add_argument(
        "--output", type=str, help="Output run data to given directory.", default=None
    )
    parser.add_argument(
        "--stats",
        help="Print run stats default: %(default)s",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument(
        "--progress",
        help="Print progress default: %(default)s",
        action=argparse.BooleanOptionalAction,
        default=True,
    )

    parser.add_argument("--results", help="Print run results", action="store_true")
    parser.add_argument("--graph", help="Graph the network", action="store_true")

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    main(args)
