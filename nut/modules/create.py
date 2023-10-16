import copy
import logging
from typing import Optional, Union

import yaml
from nessus.models import ScanCreateSettings
from yaml.scanner import ScannerError

from nut.settings import args
from nut.utils import nessus, resolve_targets

logger = logging.getLogger(__name__)


class FolderPolicyCache:
    """Utility class for caching names and ids of folders and policies."""

    def __init__(self):
        self.folder_map = {}
        self.policy_map = {}
        self.uuid_map = {}

    def resolve_folder(self, folder: Union[int, str]) -> Optional[int]:
        if isinstance(folder, int):
            return folder

        if isinstance(folder, str):
            # Try to get it from the cache
            folder_id = self.folder_map.get(folder)

            # If unsuccessful, try to get it from Nessus
            if folder_id is None:
                folder_id = nessus.get_folder_id(folder)

            # If unsuccessful, create it
            if folder_id is None:
                logger.info(f"Creating folder '{folder}'")
                response = nessus.folders_create(folder)
                folder_id = response.get("id")

            if folder_id is not None:
                # Cache the name -> id
                self.folder_map[folder] = folder_id
                return folder_id

    def resolve_policy(self, policy: Union[int, str]) -> Optional[int]:
        if isinstance(policy, int):
            return policy

        if isinstance(policy, str):
            policy_id = self.policy_map.get(policy)

            if policy_id is None:
                policy_id = nessus.get_policy_id(policy)

            if policy_id:
                # Cache the name -> id
                self.policy_map[policy] = policy_id
                return policy_id

    def get_policy_uuid(self, policy_id: int) -> Optional[int]:
        policy_uuid = self.uuid_map.get(policy_id)

        if policy_uuid is None:
            policy_uuid = nessus.get_policy_uuid(policy_id)

        if policy_uuid:
            # Cache the id -> uuid
            self.uuid_map[policy_id] = policy_uuid
            return policy_uuid


def create_scans(definitions: dict):
    """Creates the scans and folders as per the supplied definitions."""

    logger.info(f"Parsing scan definitions")

    # Basic sanity checks
    scan_defs = definitions.get("scans")
    if not scan_defs:
        logger.error("Missing key 'scans' in definitions")
        return

    if not isinstance(scan_defs, dict):
        logger.error("Invalid key 'scans' in definitions, not a dict")
        return

    cache = FolderPolicyCache()
    defaults = definitions.get("defaults", {})
    scans_created = 0

    for name, details in scan_defs.items():
        if not isinstance(details, dict):
            logger.error(f"Scan '{name}' has invalid definitions, skipping")
            continue

        # Exclusions should be combined and not overwritten, so we pop them
        # before merging the defaults with the current scan's definitions
        exclusions = details.pop("exclusions", [])

        # Copy the default values and overwrite them with the current ones
        scan = {**copy.deepcopy(defaults), **details}

        # Add the previously popped exclusions
        scan_exclusions = scan.setdefault("exclusions", [])
        scan_exclusions.extend(exclusions)

        # Policy (required)
        policy = scan.get("policy")
        if policy is None:
            logger.error(f"Scan '{name}' is missing the policy, skipping")
            continue

        policy_id = cache.resolve_policy(policy)
        if policy_id is None:
            logger.error(f"Scan '{name}' has an invalid policy, skipping")
            continue

        logger.debug(f"Scan '{name}' has policy id '{policy_id}'")

        template_uuid = cache.get_policy_uuid(policy_id)
        if template_uuid is None:
            logger.error(f"Scan '{name}' has a policy with an invalid editor template, skipping")
            continue

        logger.debug(f"Scan '{name}' has template UUID '{template_uuid}'")

        # Folder (required)
        folder = scan.get("folder")
        if folder is None:
            logger.error(f"Scan '{name}' is missing the folder, skipping")
            continue

        folder_id = cache.resolve_folder(folder)
        if folder_id is None:
            logger.error(f"Scan '{name}' has an invalid folder, skipping")
            continue

        logger.debug(f"Scan '{name}' has folder id '{folder_id}'")

        # Targets (required)
        targets = scan.get("targets")
        if targets is None:
            logger.error(f"Scan '{name}' is missing the targets, skipping")
            continue

        # Exclusions (optional)
        exclusions = scan.get("exclusions", [])

        target_list = resolve_targets(targets, exclusions)
        if not target_list:
            logger.error(f"Scan '{name}' has no targets in scope, skipping")
            continue

        text_targets = ", ".join(target_list)
        logger.debug(f"Scan '{name}' has targets '{text_targets}'")

        # Description (optional)
        description = scan.get("description")
        if description is not None:
            description = str(description)  # just to be sure

        # Create the scan
        scan_settings = ScanCreateSettings(
            name=name,
            text_targets=text_targets,
            description=description,
            policy_id=policy_id,
            folder_id=folder_id,
        )

        logger.info(f"Creating scan '{name}'")
        nessus.scans_create(template_uuid, scan_settings)
        scans_created += 1

    logger.info(f"Created {scans_created} scans")


def run():
    # Load the input file definitions
    with args.file.open("r") as fp:
        try:
            definitions = yaml.safe_load(fp)
        except ScannerError:
            logger.error("Couldn't parse input file, is it valid yaml?")
            return

    if definitions is None:
        logger.error("The input file is empty")
        return

    create_scans(definitions)
