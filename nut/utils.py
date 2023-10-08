import logging
from collections import defaultdict

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


def collect_scan_ids(scans: list[int], folders: list[str]) -> list[int]:
    # Fetch list of scans and folders once to reduce API hits
    data = nessus.scans_list()

    # Dict that maps folder name to id
    folder_map = {f["name"]: f["id"] for f in data["folders"]}

    # Dict that maps folder id to scans
    folder_scans_map = defaultdict(set)
    valid_scan_ids = set()

    for scan in data["scans"]:
        scan_id = scan["id"]
        valid_scan_ids.add(scan_id)

        folder_id = scan["folder_id"]
        folder_scans_map[folder_id].add(scan_id)

    # Collect all unique scan IDs
    scan_ids = set()

    for scan in scans:
        if scan in valid_scan_ids:
            scan_ids.add(scan)
        else:
            logger.error(f"Scan '{scan}' doesn't exist")

    for folder in folders:
        # Convert the folder id to int or get it from the folder name
        folder_id = int(folder) if folder.isdigit() else folder_map.get(folder)

        if folder_id is None:
            logger.error(f"Folder '{folder}' doesn't exist")
            continue

        folder_scans = folder_scans_map[folder_id]
        if not folder_scans:
            logger.error(f"Folder '{folder}' doesn't exist or is empty")
            continue

        for scan_id in folder_scans:
            scan_ids.add(scan_id)

    scan_ids = list(scan_ids)

    logger.info(f"Scan IDs: {scan_ids}")

    return scan_ids
