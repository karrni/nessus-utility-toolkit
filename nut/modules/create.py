import copy
from pathlib import Path

import yaml

from nut.config import settings
from nut.modules.logger import Logger
from nut.modules.nessus import nessus
from nut.modules.utils import resolve_scope

logger = Logger()


def list_policies():
    policies = nessus.get_policies()

    id_len, nm_len = 0, 0
    for p in policies:
        id_len = max(id_len, len(str(p["id"])))
        nm_len = max(nm_len, len(p["name"]))

    print("\nScan Policies:\n")
    print(f"  {'ID':>{id_len}} | Name")
    print(f"  {'-'*id_len}-+-{'-'*nm_len}")
    for p in policies:
        print(f"  {p['id']:{id_len}} | {p['name']}")
    print()


def resolve_policy_id(policy):
    # int means it's the policy ID
    if isinstance(policy, int):
        logger.debug("Policy ID was provided")
        policy_id = policy

    # if it's a string, it's the policy name and needs to be resolved
    elif isinstance(policy, str):
        logger.debug("Policy name was provided")
        policy_id = nessus.get_policy_id(policy)
        logger.debug(f"Resolved policy ID is {policy_id}")
        if not policy_id:
            logger.error(f'Invalid policy name "{policy}"')
            return

    # anything else is invalid lol
    else:
        logger.error("The policy is invalid")
        return

    return policy_id


def resolve_template_uuid(policy_id):
    template_uuid = nessus.get_policy_uuid(policy_id)
    logger.debug(f"Template UUID is {template_uuid}")
    if not template_uuid:
        logger.error(f"Could not resolve template UUID for policy ID {policy_id}")
        return

    return template_uuid


def resolve_folder(folder):
    if isinstance(folder, int):
        return folder

    if isinstance(folder, str):
        return nessus.get_folder_id(folder) or nessus.create_folder(folder)

    else:
        logger.error("The folder is invalid")
        return


def create():
    # list all available policies (-l)
    if settings.args.list_policies:
        list_policies()
        return

    # ensure the input file exists and is valid

    if not settings.args.infile:
        logger.error("Input file needs to be set")
        return

    infile = Path(settings.args.infile)
    if not infile.is_file():
        logger.error("Input file doesn't exist or isn't a file")
        return

    # yaml is a superset of json, so it can parse both
    with open(infile, "r") as stream:
        try:
            data = yaml.safe_load(stream)
        except yaml.scanner.ScannerError:
            logger.error("Error while parsing input file - is it valid?")
            return

    # format checks
    if "scans" not in data or not data["scans"]:
        logger.error('Missing "scans" key in input file')
        return

    # go through all scans

    defaults = data.get("defaults", {})
    for name, details in data["scans"].items():
        # copy defaults and merge with current scan, overwriting the defaults
        current_scan = {**copy.deepcopy(defaults), **details}

        # Policy - required

        policy = current_scan.get("policy")
        if not policy:
            logger.error(f'Scan "{name}" is missing the policy - skipping')
            continue

        policy_id = resolve_policy_id(policy)
        if not policy_id:
            logger.error(f'Scan "{name}" has an invalid policy - skipping')
            continue

        template_uuid = resolve_template_uuid(policy_id)
        if not template_uuid:
            return

        # Folder - required

        folder = current_scan.get("folder")
        if not folder:
            logger.error(f'Scan "{name}" is missing the folder - skipping')
            continue

        folder_id = resolve_folder(folder)
        if not folder_id:
            return

        # Targets - required

        targets = current_scan.get("targets")
        if not targets:
            logger.error(f'Scan "{name}" is missing the targets - skipping')
            continue

        exclusions = current_scan.get("exclusions", [])  # These are optional

        target_list = resolve_scope(targets, exclusions)
        if not target_list:
            return

        text_targets = ",".join(target_list)

        # Description - optional

        description = current_scan.get("description")
        if description is not None and not isinstance(description, str):
            logger.error(f'Scan "{name}" has an invalid description - ignoring')
            description = None

        # Creating the Scan

        nessus.create_scan(
            template_uuid,
            name,
            text_targets,
            description,
            policy_id,
            folder_id,
        )
