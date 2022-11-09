#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

# Mastodon Network Analyzer
import argparse
import argcomplete
import concurrent.futures
import random
from threading import Lock
import time

from mastodon import Mastodon

# TODO: Better handle timeouts and ctrl-c
# TODO: Add a way to save partial results to disk and resume from them
# TODO: Add a way to save the results to a database?
# TODO: Improve graph visualization


def get_instance_info_and_peers(url, timeout=10):
    # Create a new mastodon client with timeout if requested.
    if timeout:
        mastodon = Mastodon(api_base_url=url, request_timeout=timeout)
    else:
        mastodon = Mastodon(api_base_url=url)
    try:
        instance = mastodon.instance()
    except Exception as e:
        # print(f"Error: {url} generated an exception: {e} while getting instance info.")
        instance = None
    try:
        peers = mastodon.instance_peers()
    except Exception as e:
        # print(f"Error: {url} generated an exception: {e} while getting peers.")
        peers = None
    return instance, peers


progress_info = {
    "tasks_total": 0,
    "tasks_completed": 0,
    "start_time": 0,
    "progress_lock": Lock(),
}


# Print status updates as the scan progresses
def progress_indicator(future):
    global progress_info
    with progress_info["progress_lock"]:
        # Get the host name from the future.
        instance, peers = future.result()
        if instance:
            host = instance["uri"]
        else:
            host = "No instance info"
        try:
            remaining_time = (
                (time.time() - progress_info["start_time"])
                / progress_info["tasks_completed"]
                * (progress_info["tasks_total"] - progress_info["tasks_completed"])
            )
        except ZeroDivisionError:
            remaining_time = 0
        print(
            f"{progress_info['tasks_completed']}/{progress_info['tasks_total']} hosts scanned. ",
            end="",
        )
        print(
            f"Elapsed: {time.time() - progress_info['start_time']:.1f} sec  ",
            end="",
        )
        print(f"Est remaining: {remaining_time:.1f} seconds.  ", end="")
        print(f"Host: {host}")


def scan(url, host_limit=0, peer_limit=0, verbose=False, workers=None, timeout=None):
    global progress_info
    progress_info["start_time"] = time.time()
    # Create an initial set of hosts to scan
    hosts_to_scan = set(url)
    # Create empty dicts to store the peer results and the instance info
    peer_results = {}
    instance_info = {}
    # Start scanning the network.
    # We will use a thread pool executor to scan the network in parallel.
    while hosts_to_scan:
        if verbose:
            print(f"Total known unscanned hosts: {len(hosts_to_scan)}")
            print(f"Total scanned hosts: {len(peer_results)}")
        # Get the hosts for the next round of scanning.
        hosts = set()
        if host_limit:
            for i in range(min(len(hosts_to_scan), host_limit - len(peer_results))):
                hosts.add(hosts_to_scan.pop())
        else:
            hosts = hosts_to_scan
            hosts_to_scan = set()
        if verbose:
            print(f"Scanning {len(hosts)} hosts")
        with progress_info["progress_lock"]:
            progress_info["tasks_total"] = host_limit if host_limit else len(hosts)
            progress_info["tasks_completed"] = len(peer_results)
        # Scan the hosts in parallel using concurrent.futures.
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(get_instance_info_and_peers, host, timeout): host
                for host in hosts
            }
            for future in futures:
                future.add_done_callback(progress_indicator)
            try:
                for future in concurrent.futures.as_completed(futures, timeout=timeout):
                    host = futures[future]
                    try:
                        instance, peers = future.result()
                    except Exception as exc:
                        print(f"Error: {host} generated an exception: {exc}")
                    else:
                        if peers:
                            # Limit the number of peers if requested.
                            if peer_limit:
                                peers = random.sample(
                                    peers, min(peer_limit, len(peers))
                                )
                            # Add the peers to the results and the hosts to scan.
                            peer_results[host] = peers
                            for peer in peers:
                                if (
                                    peer not in peer_results
                                    and peer not in hosts_to_scan
                                ):
                                    hosts_to_scan.add(peer)
                            with progress_info["progress_lock"]:
                                progress_info["tasks_completed"] = len(peer_results)
                        if instance:
                            instance_info[host] = instance
            except concurrent.futures.TimeoutError:
                if verbose:
                    print("Timeout Error: One or more hosts timed out.")
        # Check if we reached the host limit
        if host_limit and len(peer_results) >= host_limit:
            break

    return instance_info, peer_results


def main(args):
    print(f"Starting scanning the mastodon federation network from urls: {args.url}")
    instance_info, peer_results = scan(
        url=args.url,
        host_limit=args.host_limit,
        peer_limit=args.peer_limit,
        verbose=args.verbose,
        workers=args.workers,
        timeout=args.timeout,
    )

    # Output the results in a nice format that can be used by other programs.
    # In particular, we should output the results in a format that can be used by
    # the networkx library to create a graph of the network.
    if args.csv:
        with open(args.output, "w") as f:
            # Write the results in a CSV format that can be used by networkx
            f.write("source,target")
            for host, peers in peer_results.items():
                for peer in peers or []:
                    f.write(f"{host},{peer}")

    # Get set of all hosts that returned either peers or instance info
    hosts = set()
    for host, peers in peer_results.items():
        if peers:
            hosts.add(host)
    for host, instance in instance_info.items():
        if instance:
            hosts.add(host)
    print(f"Scan complete. Total hosts with peers or instance info: {len(hosts)}")
    if args.print:
        # For each host, print the instance info and the peers
        for host in hosts:
            print(f"Host: {host}")
            if host in instance_info:
                print(f"  Instance Info:")
                print(f"    URI: {instance_info[host]['uri']}")
                print(f"    Title: {instance_info[host]['title']}")
                print(f"    Description: {instance_info[host]['description']}")
                print(f"    Email: {instance_info[host]['email']}")
                print(f"    Version: {instance_info[host]['version']}")
                print(f"    Stats:")
                print(f"      User Count: {instance_info[host]['stats']['user_count']}")
                print(
                    f"      Status Count: {instance_info[host]['stats']['status_count']}"
                )
                print(
                    f"      Domain Count: {instance_info[host]['stats']['domain_count']}"
                )
            if host in peer_results:
                print(f"  Peers for host: {host}")
                for peer in peers or ["No peers found"]:
                    print(f"\t{peer}")

    # Create a graph of the network using networkx and pyvis
    if args.graph:
        import networkx as nx
        from pyvis.network import Network

        G = nx.from_dict_of_lists(peer_results, create_using=nx.DiGraph)
        net = Network(notebook=False)
        net.from_nx(G)
        net.show_buttons(filter_=["physics"])
        net.show("test.html")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mastodon Network Analyzer")
    parser.add_argument("-v", "--verbose", help="Verbose mode.", action="store_true")
    parser.add_argument(
        "url", type=str, nargs="+", help="Starting Mastodon instance URLs"
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
    parser.add_argument("--csv", type=str, help="Output CSV file name.", default=None)
    parser.add_argument("--print", help="Print the results", action="store_true")
    parser.add_argument("--graph", help="Graph the network", action="store_true")
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    main(args)
