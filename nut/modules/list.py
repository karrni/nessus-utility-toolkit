import logging

from prettytable import PrettyTable

from nut.config import settings
from nut.utils import nessus

from .base import Module

logger = logging.getLogger(__name__)


class ListModule(Module):
    @staticmethod
    def list_folders():
        """Prints a table with available folders."""

        logger.info("Listing available folders")

        table = PrettyTable()
        table.title = "Folders"
        table.field_names = ["ID", "Name"]
        table.align["ID"] = "r"
        table.align["Name"] = "l"

        for folder in nessus.get_folders():
            table.add_row([folder["id"], folder["name"]])

        print()
        print(table.get_string())
        print()

    @staticmethod
    def list_scans():
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

        print()
        print(table.get_string())
        print()

    @staticmethod
    def list_policies():
        """Prints a table with available policies."""

        logger.info("Listing available policies")

        table = PrettyTable()
        table.title = "Policies"
        table.field_names = ["ID", "Name"]
        table.align["ID"] = "r"
        table.align["Name"] = "l"

        for policy in nessus.get_policies():
            table.add_row([policy["id"], policy["name"]])

        print()
        print(table.get_string())
        print()

    def handle(self):
        args = settings.args

        if args.policies:
            self.list_policies()
        elif args.scans:
            self.list_scans()
        else:
            self.list_folders()
