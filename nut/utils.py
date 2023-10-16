import logging
from collections import defaultdict
from ipaddress import ip_address
from textwrap import shorten
from typing import Collection, Optional

from nessus import NessusAPI
from netaddr import (
    AddrFormatError,
    IPAddress,
    IPGlob,
    IPNetwork,
    IPSet,
    iter_nmap_range,
    valid_glob,
    valid_ipv4,
    valid_nmap_range,
)
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from nut.settings import config

# Disable warnings for insecure connections
disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Create a central NessusAPI instance
nessus = NessusAPI(
    config["nessus"]["url"],
    access_key=config["nessus"]["access_key"],
    secret_key=config["nessus"]["secret_key"],
    username=config["nessus"]["username"],
    password=config["nessus"]["password"],
)


def resolve_scan_ids(scans: list[str], folders: list[str]) -> list[int]:
    """
    Resolves lists of scan and folder ids or names into a list of unique scan ids.
    """

    # Fetch list of all scans and folders
    data = nessus.scans_list()

    # Maps folder names to ids
    folder_map = {f["name"]: f["id"] for f in data["folders"]}

    # Set of all valid scan ids
    valid_scan_ids = set()

    # Maps scan names to id(s)
    scan_map = defaultdict(set)

    # Maps folder ids to scan ids it contains
    folder_scans_map = defaultdict(set)

    for scan in data["scans"]:
        scan_id = scan["id"]
        valid_scan_ids.add(scan_id)

        scan_name = scan["name"]
        scan_map[scan_name].add(scan_id)

        folder_id = scan["folder_id"]
        folder_scans_map[folder_id].add(scan_id)

    # Set to collect all scan ids
    scan_ids = set()

    for folder in folders:
        # It's either the folder id (cast to int) or name (resolve id)
        folder_id = int(folder) if folder.isdigit() else folder_map.get(folder)

        # Check if the folder name could be resolved
        if folder_id is None:
            logger.error(f"Folder '{folder}' doesn't exist")
            continue

        # Check if the folder exists/contains scans
        folder_scans = folder_scans_map[folder_id]
        if not folder_scans:
            logger.error(f"Folder '{folder}' doesn't exist or is empty")
            continue

        scan_ids.update(folder_scans)

    for scan in scans:
        # If it's a scan id just check if it's valid and add it
        if scan.isdigit():
            scan_id = int(scan)

            # Check if the scan id is valid
            if scan_id not in valid_scan_ids:
                logger.error(f"Scan '{scan}' doesn't exist")
                continue

            scan_ids.add(scan_id)

        # If it's a scan name we need to check if it's unique, otherwise we
        # skip it just in case
        else:
            # Truncate the scan name for log messages, so they're not too long
            _name = shorten(scan, width=48, placeholder="...")

            possible_ids = scan_map.get(scan)

            # Check if the scan name could be resolved
            if possible_ids is None:
                logger.error(f"Scan '{_name}' doesn't exist")
                continue

            # Check if the scan name is unique
            if len(possible_ids) > 1:
                logger.error(f"Scan '{_name}' is not unique, could be {possible_ids}")
                continue

            scan_ids.update(possible_ids)

    scan_ids = list(scan_ids)

    logger.info(f"Scan IDs: {scan_ids}")

    return scan_ids


def _split_targets(targets: list) -> tuple[IPSet, set[str]]:
    """
    Splits targets into IPs and hostnames.
    """

    ips, hosts = IPSet(), set()

    for target in targets:
        # NOTE: The order of the checks is important. Unfortunately, there's no
        #   'valid_cidr()' function, so we can't use continuous if/elif/else
        #   statements and have to use 'continue' and 'try/except'.

        # Check if the target is a single IP address
        if valid_ipv4(target):
            ips.add(IPAddress(target))

            # Every address is also a valid CIDR network, so explicitly skip
            continue

        # Check if the target is a network in CIDR notation
        # IMPORTANT: This check **needs** to come before the nmap and glob
        #   checks, because they do not recognize the network and broadcast
        #   addresses!
        try:
            network = IPNetwork(target)

            for ip in network.iter_hosts():
                ips.add(ip)

            # Every network is also a valid nmap/glob range, so explicitly skip
            continue

        except AddrFormatError:
            pass

        # Check if the target is a valid nmap range
        if valid_nmap_range(target):
            for ip in iter_nmap_range(target):
                ips.add(ip)

        # Check if the target is a valid glob notation
        elif valid_glob(target):
            for ip in IPGlob(target):
                ips.add(ip)

        # All other targets are presumably hostnames
        else:
            hosts.add(target)

    return ips, hosts


def resolve_targets(targets: list, exclusions: Optional[list] = None) -> list[str]:
    """
    Filters a list of IPs and hostnames and returns a condensed list of targets.
    """

    target_ips, target_hosts = _split_targets(targets)

    if exclusions is not None:
        exclude_ips, exclude_hosts = _split_targets(exclusions)

        target_ips -= exclude_ips
        target_hosts -= exclude_hosts

    target_defs = []

    for iprange in target_ips.iter_ipranges():
        # To avoid ranges like 192.168.0.1-192.168.0.1, check the length of the
        # range and if it's 1, only add the first (and only) item
        if len(iprange) == 1:
            target_defs.append(str(iprange[0]))

        else:
            target_defs.append(str(iprange))

    # Sort the list of hosts and append them to the target definitions
    target_defs.extend(sorted(target_hosts))

    return target_defs


def uniqify(seq):
    """
    Removes duplicates from the sequence while preserving order.

    References:
        https://www.peterbe.com/plog/uniqifiers-benchmark
    """

    seen = {}
    result = []
    for item in seq:
        if item in seen:
            continue
        seen[item] = 1
        result.append(item)
    return result


def sort_hosts(hostlist: Collection[str], unique: bool = True) -> list[str]:
    """
    Sorts a list of hostnames and/or IP addresses.

    Accepts the following formats:
      - 10.0.0.1
      - 10.0.0.1:22
      - 10.0.0.1:22/tcp
      - 10.0.0.1:53/udp
      - example.com
      - example.com:80
      - example.com:80/tcp
    """

    def _sort(target):
        # Returns a tuple (type, host, port) that is used for sorting

        # Split target into host and port
        host, _, port = target.partition(":")

        if port:
            port, _, proto = port.partition("/")
            port = int(port)
        else:
            port, proto = 0, ""

        # Try to parse the host portion as an IP address
        try:
            ip = ip_address(host)
            return 0, int(ip), port, proto

        # If it fails it is a domain/hostname
        except ValueError:
            return 2, host, port, proto

    result = sorted(hostlist, key=_sort)
    if unique:
        result = uniqify(result)

    return result
