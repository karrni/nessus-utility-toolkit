import logging
from datetime import datetime

from pathvalidate import sanitize_filename, sanitize_filepath

from nut.settings import args
from nut.utils import nessus

logger = logging.getLogger(__name__)


def run():
    basedir = args.outdir
    scan_ids = args.scan_ids

    if args.merge:
        logger.info("Exporting and merging scans")

        scan_name = "Merged Export"
        exported_scan = nessus.export_merged_scan(scan_ids, scan_name)

        timestamp = datetime.today().strftime("%Y-%m-%dT%H%M%S")
        filename = f"{timestamp} - {scan_name} {scan_ids}.nessus"
        outfile = basedir / sanitize_filename(filename)

        basedir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Writing merged scan to '{outfile}'")
        with outfile.open("wb") as fp:
            fp.write(exported_scan.read())

    else:
        data = nessus.scans_list()

        # Dicts that map scan and folder ids to names
        scan_map = {s["id"]: (s["name"], s["folder_id"]) for s in data["scans"]}
        folder_map = {f["id"]: f["name"] for f in data["folders"]}

        for scan_id in scan_ids:
            logger.info(f"Exporting scan '{scan_id}'")

            exported_scan = nessus.export_scan(scan_id)

            scan_name, folder_id = scan_map[scan_id]
            folder_name = folder_map[folder_id]

            outdir = basedir / folder_name
            outfile = outdir / f"{scan_name} [{scan_id}].nessus"
            outfile = sanitize_filepath(outfile)

            outdir.mkdir(parents=True, exist_ok=True)

            logger.info(f"Writing scan to '{outfile}'")
            with outfile.open("wb") as fp:
                fp.write(exported_scan.read())
