from pathlib import Path

from nut.modules.logger import NUTAdapter
from nut.modules.nessus import nessus

logger = NUTAdapter()


def get_scan_ids(scans, folders):
    logger.info("Gathering Scan IDs")
    scan_ids = set()

    for s in scans:
        if nessus.get_scan_details(s):
            scan_ids.add(s)
        else:
            logger.error(f"Scan with ID {s} doesn't exist")

    for f in folders:
        if not f.isdigit():
            f_id = nessus.get_folder_id(f)
            if not f_id:
                logger.error(f"Folder {f} doesn't exist")
                continue
        else:
            f_id = f

        for s in nessus.get_folder_scans(f_id):
            scan_ids.add(s["id"])

    scan_ids = list(scan_ids)
    logger.success(f"Scan IDs: {scan_ids}")
    return scan_ids


def secure_filename(filename):
    keep = (" ", ".", "_", "&", "+")
    return "".join(c for c in filename if c.isalnum() or c in keep).rstrip()


def mkdir(path):
    Path(path).mkdir(parents=True, exist_ok=True)
