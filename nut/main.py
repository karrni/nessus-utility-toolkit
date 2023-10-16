import argparse
import logging
from argparse import ArgumentTypeError
from pathlib import Path

from colorama import Fore, Style
from nessus.exceptions import NessusException

from nut.settings import args
from nut.utils import resolve_scan_ids

logger = logging.getLogger(__name__)


class CustomFormatter(logging.Formatter):
    """Custom formatter that colors the level name."""

    # Define the colors for each log level
    level_color = {
        logging.DEBUG: Fore.MAGENTA,
        logging.INFO: Fore.BLUE,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        # Get the color for the log level
        color = self.level_color[record.levelno]

        # Overwrite 'levelname' with a colored version
        record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"

        return super().format(record)


def setup_logging(level: int):
    """Configure the logging."""

    # Custom formatter and message format
    formatter = CustomFormatter("[%(levelname)s] %(message)s")

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logging.root.addHandler(handler)
    logging.root.setLevel(level)

    # Overwrite the default log level names
    logging.addLevelName(logging.DEBUG, "DBG")
    logging.addLevelName(logging.INFO, "INF")
    logging.addLevelName(logging.WARNING, "WRN")
    logging.addLevelName(logging.ERROR, "ERR")
    logging.addLevelName(logging.CRITICAL, "CRT")

    # Explicitly set the log level for noisy packages
    logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)


def path_file(string):
    """Returns the string path as a Path object after checking that it exists."""

    path = Path(string)
    if not path.exists():
        raise ArgumentTypeError(f"{string} doesn't exist")
    return path


def parse_args():
    """Parse command line arguments."""

    # --- Common Arguments ---

    # common arguments that all parsers share
    _common = argparse.ArgumentParser(add_help=False)
    _common.add_argument("-v", dest="loglevel", action="store_const", const=logging.DEBUG, default=logging.INFO)
    _common.set_defaults(uses_scans=False)

    # arguments for modules that work with scans
    _scans = argparse.ArgumentParser(add_help=False)
    _scans.add_argument("-s", "--scans", metavar="SCAN", nargs="*", default=[], type=str, help="Scan ID or name")
    _scans.add_argument("-f", "--folders", metavar="FOLDER", nargs="*", default=[], type=str, help="Folder ID or name")
    _scans.set_defaults(uses_scans=True)  # indicates that the module uses scans
    _scans.set_defaults(scan_ids=[])

    # --- Main Parser ---

    # nut -h -> module.help, nut [module] -h -> module.description
    parser = argparse.ArgumentParser(prog="nut", parents=[_common])
    subparsers = parser.add_subparsers(dest="module", required=True)

    # --- Create ---
    _text = "Create scans and folders defined in a .yml file"
    parser_create = subparsers.add_parser("create", parents=[_common], help=_text, description=_text)
    parser_create.add_argument("file", type=path_file, help="Yaml file with the scan definitions")

    # --- Exploits ---
    _text = "List vulnerabilities with known exploits"
    parser_exploits = subparsers.add_parser("exploits", parents=[_common, _scans], help=_text, description=_text)
    framework_group = parser_exploits.add_mutually_exclusive_group()
    framework_group.set_defaults(framework=None)
    framework_group.add_argument("-ms", "--metasploit", action="store_const", dest="framework", const="metasploit")
    framework_group.add_argument("-co", "--core-impact", action="store_const", dest="framework", const="core")

    # --- Export ---
    _text = "Export scans as .nessus files"
    parser_export = subparsers.add_parser("export", parents=[_common, _scans], help=_text, description=_text)
    parser_export.add_argument("-m", "--merge", action="store_true", help="Merge all scans into one")
    parser_export.add_argument("-o", "--outdir", type=Path, default=Path())

    # --- List ---
    _text = "List folders, scans, and scan policies"
    parser_list = subparsers.add_parser("list", parents=[_common], help=_text, description=_text)
    list_group = parser_list.add_mutually_exclusive_group()
    list_group.add_argument("-s", "--scans", action="store_true", help="Include scans in each folder")
    list_group.add_argument("-p", "--policies", action="store_true", help="List available scan policies")

    # --- URLs ---
    _text = "Create a list of all identified web servers"
    parser_urls = subparsers.add_parser("urls", parents=[_common, _scans], help=_text, description=_text)
    parser_urls.add_argument("-o", "--output", metavar="FILE", dest="outfile", type=Path, default=Path("urls.txt"))

    parser.parse_args(namespace=args)

    # Ensure that scans/folders were passed if the module uses scans ids
    if args.uses_scans and not (args.scans or args.folders):
        parser.error("at least one of the following arguments is required: scans, folders")


def main():
    parse_args()

    setup_logging(args.loglevel)
    logger.debug(f"{args=}")

    logger.info("Connecting to Nessus")

    if args.uses_scans:
        logger.debug("Resolving scan ids")

        args.scan_ids = resolve_scan_ids(args.scans, args.folders)
        if not args.scan_ids:
            logger.error("No valid scan ids found, please check your input")
            return

    # --- Modules ---
    from nut.modules import create, exploits, export, list, urls

    if args.module == "create":
        create.run()
    elif args.module == "exploits":
        exploits.run()
    elif args.module == "export":
        export.run()
    elif args.module == "list":
        list.run()
    elif args.module == "urls":
        urls.run()


if __name__ == "__main__":
    try:
        main()
    except NessusException as e:
        logger.error(f"Error from Nessus: {e}")
