import argparse
import logging

from nut.config import settings
from nut.logger import setup_logging
from nut.modules.list import ListModule
from nut.utils import collect_scan_ids, setup_nessus


def main():
    parser_description = """
      _____
     / _ \\ \\        N.U.T.
    ( (_) )-)  Nessus Utility Toolkit
     \\___/_/
    """

    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--debug", action="store_true", default=False, help="Enable debug output")

    scans_parser = argparse.ArgumentParser(add_help=False)
    scans_parser.add_argument("-s", "--scans", nargs="*", type=int, default=[])
    scans_parser.add_argument("-f", "--folders", nargs="*", default=[])
    scans_parser.set_defaults(scans_required=True)  # used to determine if the module needs scan ids

    # the main argument parser
    parser = argparse.ArgumentParser(
        description=parser_description,
        formatter_class=argparse.RawTextHelpFormatter,
        parents=[common_parser],
    )
    subparsers = parser.add_subparsers(dest="module", required=True)

    # parser for the 'list' module
    list_parser = subparsers.add_parser(
        "list",
        parents=[common_parser],
        help="List available folders, scans, and policies.",
        description="List available folders, scans, and policies.",
    )

    list_parser.add_argument(
        "--scans",
        action="store_true",
        default=False,
        help="Include scans when listing folders",
    )

    list_parser.add_argument(
        "--policies",
        action="store_true",
        default=False,
        help="List available policies",
    )

    # parser for the 'export' module
    export_parser = subparsers.add_parser(
        "export",
        parents=[common_parser, scans_parser],
        help="Export scans as .nessus files.",
        description="Export scans as .nessus files.",
    )
    export_parser.add_argument("--merge", action="store_true", default=False, help="Merge the scans into one")
    export_parser.add_argument("-o", metavar="FILE", dest="outfile", default=None, help="Output file")

    # ==============================

    args = parser.parse_args(namespace=settings.args)

    # set up logging
    setup_logging(logging.DEBUG if args.debug else logging.INFO)
    logger = logging.getLogger(__name__)

    logger.debug(f"Arguments: {args=}")

    # initialize the nessus instance
    setup_nessus()

    # check if the chosen module requires scans
    scans_required = getattr(args, "scans_required", False)

    if scans_required:
        if not args.scans and not args.folders:
            logger.error("You need to specify scans and/or folders")
            return

        settings.args.scan_ids = collect_scan_ids(args.scans, args.folders)
        if not settings.args.scan_ids:
            logger.error("No valid scan IDs, check the arguments")
            return

    if args.module == "list":
        ListModule().handle()


if __name__ == "__main__":
    main()
