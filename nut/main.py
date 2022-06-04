#!/usr/bin/env python
# -*- coding:utf-8 -*-

import argparse
import logging
import os
from argparse import RawTextHelpFormatter

from nut.config import settings
from nut.modules.export import export
from nut.modules.logger import NUTAdapter, setup_logger
from nut.modules.nessus import nessus
from nut.modules.urls import urls
from nut.modules.utils import get_scan_ids


def main():
    # common args that all subparsers inherit from
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--debug", action="store_true", default=False)
    common_parser.add_argument("-s", "--scan", nargs="*", type=int, default=[], help="One or more scan IDs")
    common_parser.add_argument("-f", "--folder", nargs="*", default=[], help="One or more folder IDs or names")

    # main parser
    parser = argparse.ArgumentParser(
        description=f"""
      _____
     / _ \\ \\        N.U.T.                                    
    ( (_) )-)  Nessus Utility Toolkit
     \\___/_/  
    """,
        formatter_class=RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    # Export

    export_parser = subparsers.add_parser("export", parents=[common_parser])
    export_parser.add_argument("--merge", action="store_true", default=False, help="Merge all scans into one")
    export_parser.add_argument("-o", metavar="DIRECTORY", dest="out", default=None, help="Output directory")

    urls_parser = subparsers.add_parser("urls", parents=[common_parser])
    urls_parser.add_argument("-o", metavar="FILE", dest="out", default=None, help="Output file")

    args = parser.parse_args()
    settings.args = args

    # set up logger after parsing the args, so we can enable debug output or not
    setup_logger(logging.DEBUG if args.debug else logging.INFO)
    logger = NUTAdapter()

    # we need either scans or folders
    if not args.scan and not args.folder:
        logger.error("No scans or folders specified")
        return

    # initialize nessus after parsing
    nessus.init(
        os.environ.get("NESSUS_URL", settings.config["nessus"]["url"]),
        os.environ.get("NESSUS_ACCESS_KEY", settings.config["nessus"]["access_key"]),
        os.environ.get("NESSUS_SECRET_KEY", settings.config["nessus"]["secret_key"]),
    )

    # generate list of scan ids from the specified scans and folders
    scan_ids = get_scan_ids(args.scan, args.folder)
    if not scan_ids:
        logger.error("No valid scan ids found - did you make a typo?")
        return

    # if we want to export
    if args.action == "export":
        export(scan_ids, args.merge)

    # if we want a url list
    elif args.action == "urls":
        urls(scan_ids)

    logger.success("All done :3")


if __name__ == "__main__":
    main()
