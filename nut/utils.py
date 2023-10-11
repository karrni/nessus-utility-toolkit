import logging
from collections import defaultdict
from textwrap import shorten

from nessus import NessusAPI
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from nut.config import settings

disable_warnings(InsecureRequestWarning)
logger = logging.getLogger(__name__)

nessus = NessusAPI(settings.config["nessus"]["url"])


def setup_nessus():
    logger.info("Connecting to Nessus")

    conf = settings.config["nessus"]

    if conf["username"] and conf["password"]:
        nessus.add_credentials(conf["username"], conf["password"])

    elif conf["access_key"] and conf["secret_key"]:
        nessus.add_keys(conf["access_key"], conf["secret_key"])


def resolve_scan_ids(scans: list[str], folders: list[str]) -> list[int]:
    """
    Resolves a list of scans and folders into a list of unique scan ids.
    """

    # Fetch list of all scans and folders
    data = nessus.scans_list()

    # Dict that maps folder name to id
    folder_map = {f["name"]: f["id"] for f in data["folders"]}

    # Set of all valid scan ids
    valid_scan_ids = set()

    # Dict that maps scan name to id(s)
    scan_map = defaultdict(set)

    # Dict that maps folder id to scan ids
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
