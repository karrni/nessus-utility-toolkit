import logging

from nut.settings import args
from nut.utils import nessus

logger = logging.getLogger(__name__)


def start_scans(scan_ids: list[int]) -> int:
    """Start the specified scans and return the number of scans started."""

    scans_started = 0

    for scan_id in scan_ids:
        try:
            logger.info(f"Starting scan with ID {scan_id}")
            nessus.scans_launch(scan_id)
            scans_started += 1
        except Exception as e:
            logger.error(f"Failed to start scan {scan_id}: {e}")

    return scans_started


def run():
    """Start all scans specified in command line arguments."""

    logger.info(f"Starting {len(args.scan_ids)} scan(s)")
    scans_started = start_scans(args.scan_ids)
    logger.info(f"Successfully started {scans_started} scan(s)")
