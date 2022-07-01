import argparse
import logging
import os

from nut.config import settings
from nut.modules.create import create
from nut.modules.export import export
from nut.modules.logger import NUTAdapter, setup_logger
from nut.modules.nessus import nessus
from nut.modules.urls import urls
from nut.modules.utils import get_scan_ids


def main():
    # arguments that every parser has in common
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--debug", action="store_true", default=False)

    # scan and folder input arguments
    scans_parser = argparse.ArgumentParser(add_help=False)
    scans_parser.add_argument("-s", "--scans", nargs="*", type=int, default=[], help="One or more scan IDs")
    scans_parser.add_argument("-f", "--folders", nargs="*", default=[], help="One or more folder IDs or names")
    scans_parser.set_defaults(scans_required=True)  # this is used to determine if the module needs scans/folders

    # the main argument parser
    main_parser = argparse.ArgumentParser(
        description=f"""
      _____
     / _ \\ \\        N.U.T.                                    
    ( (_) )-)  Nessus Utility Toolkit
     \\___/_/  
    """,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = main_parser.add_subparsers(dest="module", required=True)

    # export module
    export_parser = subparsers.add_parser("export", parents=[common_parser, scans_parser])
    export_parser.add_argument("--merge", action="store_true", default=False, help="Merge all scans into one")
    export_parser.add_argument("-o", metavar="DIRECTORY", dest="outdir", default=None, help="Output directory")

    # urls module
    urls_parser = subparsers.add_parser("urls", parents=[common_parser, scans_parser])
    urls_parser.add_argument("-o", metavar="FILE", dest="outfile", default=None, help="Output file")

    # create module
    create_parser = subparsers.add_parser("create", parents=[common_parser])
    create_parser.add_argument("-i", metavar="FILE", dest="infile", help="Input file")
    create_parser.add_argument("-l", "--list-policies", action="store_true", default=False, help="List all policies")

    args = main_parser.parse_args(namespace=settings.args)

    setup_logger(logging.DEBUG if settings.args.debug else logging.INFO)
    logger = NUTAdapter()

    logger.debug(f"args: {args}")

    # initialize nessus
    nessus.init(
        os.environ.get("NESSUS_URL", settings.config["nessus"]["url"]),
        os.environ.get("NESSUS_ACCESS_KEY", settings.config["nessus"]["access_key"]),
        os.environ.get("NESSUS_SECRET_KEY", settings.config["nessus"]["secret_key"]),
    )

    # generate list of scan ids from the scans and folders if the module requires them
    scan_ids = []
    if getattr(args, "scans_required", False):
        if not args.scans and not args.folders:
            logger.error("This module requires scans or folders, but none were given")
            return

        scan_ids = get_scan_ids(args.scans, args.folders)
        if not scan_ids:
            logger.error("No valid scan IDs found - did you make a typo?")
            return

    if args.module == "export":
        export(scan_ids)

    if args.module == "urls":
        urls(scan_ids)

    if args.module == "create":
        create()


if __name__ == "__main__":
    main()
