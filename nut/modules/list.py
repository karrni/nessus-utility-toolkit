import logging
from textwrap import shorten

from prettytable import PrettyTable

from nut.config import settings
from nut.utils import nessus

logger = logging.getLogger(__name__)


# Custom field format functions for PrettyTable
def _fmt_folder(_, value):
    """Truncate folder names to 20 characters."""
    return shorten(value, width=20, placeholder="...")


def _fmt_scan(_, value):
    """Truncate scan names to 36 characters."""
    return shorten(value, width=36, placeholder="...")


def get_folders_table():
    """Prints a table with available folders."""

    logger.info("Listing available folders")

    table = PrettyTable()
    table.title = "Folders"
    table.field_names = ["ID", "Name"]
    table.align["ID"] = "r"
    table.align["Name"] = "l"
    table.custom_format = {"Name": _fmt_folder}

    for folder in nessus.get_folders():
        table.add_row([folder["id"], folder["name"]])

    return table


def get_scans_table():
    """Prints a table with available folders and scans."""

    logger.info("Listing available folders and scans")

    # Get all scans and folders
    data = nessus.scans_list()

    # Create a mapping for folder ids to names
    folder_map = {f["id"]: f["name"] for f in data["folders"]}

    # Create rows with folder id, name, scan id, name
    rows = []
    for scan in data["scans"]:
        folder_id = scan["folder_id"]
        folder_name = folder_map[folder_id]

        rows.append([folder_id, folder_name, scan["id"], scan["name"]])

    # Sort by folder id and scan id
    rows.sort(key=lambda x: (x[0], x[3]))

    table = PrettyTable()
    table.title = "Folders and Scans"
    table.field_names = ["FID", "Folder", "SID", "Scan"]
    table.custom_format = {"Folder": _fmt_folder, "Scan": _fmt_scan}

    table.align["FID"] = "r"
    table.align["Folder"] = "l"
    table.align["SID"] = "r"
    table.align["Scan"] = "l"

    curr_folder = None

    for i, row in enumerate(rows):
        # If the current row has a new folder show its id and name
        if row[0] != curr_folder:
            table.add_row(row)

            # Add a bottom divider to the previous line to separate folders
            if curr_folder is not None:  # skip the first folder
                table._dividers[i - 1] = True

            # Update the current folder variable
            curr_folder = row[0]

        # If the folder is the same hide its id and name
        else:
            table.add_row(["", "", row[2], row[3]])

    return table


def get_policies_table():
    """Prints a table with available policies."""

    logger.info("Listing available policies")

    table = PrettyTable()
    table.title = "Policies"
    table.field_names = ["ID", "Name"]
    table.align["ID"] = "r"
    table.align["Name"] = "l"

    for policy in nessus.get_policies():
        table.add_row([policy["id"], policy["name"]])

    return table


def run():
    if settings.args.policies:
        table = get_policies_table()
    elif settings.args.scans:
        table = get_scans_table()
    else:
        table = get_folders_table()

    print(f"\n{table.get_string()}\n")
