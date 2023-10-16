import copy
import logging
from typing import Optional, Union

import yaml
from nessus.models import ScanCreateSettings
from yaml.scanner import ScannerError

from nut.config import settings
from nut.utils import nessus, resolve_scope

logger = logging.getLogger(__name__)


class CreateCache:
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


def run():
    infile = settings.args.file

    with infile.open("r") as fp:
        try:
            data = yaml.safe_load(fp)
        except ScannerError:
            logger.error("Couldn't parse input file, is it valid yaml?")
            return

    if data is None:
        logger.error("The input file is empty")
        return

    logger.info(f"Parsing scan definitions from '{infile}'")

    # Basic sanity check
    if not data.get("scans"):
        logger.error("Missing key 'scans' in input file")
        return

    # Get the default values
    defaults = data.get("defaults", {})

    cache = CreateCache()
    scans_created = 0

    for name, details in data["scans"].items():
        if not isinstance(details, dict):
            logger.error(f"Scan '{name}' has invalid definitions, skipping")
            continue

        # Copy the default values and overwrite them with the current ones
        scan = {**copy.deepcopy(defaults), **details}

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

        target_list = resolve_scope(targets, exclusions)
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
