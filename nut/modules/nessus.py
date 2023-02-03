import json
import sys
import time
from urllib.parse import urljoin

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from nut.modules.logger import NUTAdapter

urllib3.disable_warnings(InsecureRequestWarning)

logger = NUTAdapter()


class NessusError(Exception):
    def __init__(self, message):
        self.message = message


def locked(func):
    """Descriptor for locked API endpoints.

    If the API hasn't been unlocked, it will call unlock().
    """

    def _unlock(self, *args, **kwargs):
        if not self.unlocked:
            logger.info("Alright, we hit a locked endpoint - getting the token")
            self.unlock()
        return func(self, *args, **kwargs)

    return _unlock


class Nessus:
    def __init__(self):
        self.url = None
        self.headers = None
        self.initialized = False
        self.unlocked = False

    def init(self, url, access_key, secret_key):
        self.url = url
        self.headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key};"}
        self.initialized = True

    def unlock(self):
        # Nessus has restricted API endpoints that are "only usable in Nessus Manager".
        # However, the web frontend uses the same API as this module, including the restricted
        # endpoints. When accessing through the web, the nessus6.js file sets an API Token Header
        # which essentially unlocks the restricted API. So this is exactly what is done here.
        js_url = urljoin(self.url, "nessus6.js")
        ness_js = requests.get(js_url, verify=False).content
        token = str(ness_js).split('getApiToken",value:function(){return"', 1)[1].split('"', 1)[0]
        self.headers["X-API-Token"] = token
        self.unlocked = True

    def action(
        self,
        method,
        path,
        params=None,
        data=None,
        files=None,
        json_req=True,
        download=False,
    ):
        if not self.initialized:
            raise NessusError("Not yet initialized")

        logger.debug(f"{method} {path}")
        if params:
            logger.debug(f"  params: {params}")
        if data:
            logger.debug(f"  data:: {data}")

        # The .copy() is necessary to truly copy the dict. Otherwise, we would set "Content-Type" and "Accept"
        # globally for every request which would break the file upload
        headers = self.headers.copy()
        if json_req:
            headers.update({"Content-Type": "application/json", "Accept": "text/plain"})

        url = urljoin(self.url, path)

        try:
            res = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                json=data,
                files=files,
                verify=False,
            )
        except requests.exceptions.MissingSchema:
            logger.error("Missing schema when connecting to Nessus. Is the config correct? (~/.config/nut.conf)")
            sys.exit(1)
        except requests.exceptions.ConnectionError:
            logger.error(
                "Could not connect to Nessus. Is it reachable and is the config correct? (~/.config/nut.conf)"
            )
            sys.exit(1)

        if download:
            return res.content

        elif res.text:
            # Try decoding the response as json and if it fails, return the raw text
            try:
                ret = res.json()

                # Nessus passes errors within the "error" key, so we check if it exists
                # and handle it properly
                if "error" in ret:
                    logger.debug(f"Error from Nessus: {ret['error']}")
                    # This typically means that the requested scan does not exist
                    if ret["error"] == "The requested file was not found.":
                        logger.debug("It seems like the current scan doesn't exist")
                        return None

                    # TODO error logging
                    if ret["error"] == "Invalid Credentials":
                        logger.error("Invalid Nessus credentials. Please update the config file.")
                        sys.exit(1)
                    else:
                        raise NessusError(ret["error"])
                return ret

            except json.decoder.JSONDecodeError:
                return res.text

        # Typically, this shouldn't happen lol
        else:
            logger.error("Something fucky is going on with Nessus")

    # Folders

    def get_folders(self):
        return self.action("GET", "/folders")["folders"]

    def get_scan_folder(self, scan_id):
        logger.debug(f"Getting folder for scan {scan_id}")
        return self.get_scan_details(scan_id)["info"]["folder_id"]

    def get_folder_name(self, folder_id):
        logger.debug(f"Getting folder name for id {folder_id}")
        for folder in self.get_folders():
            if folder["id"] == folder_id:
                return folder["name"]
        return None

    def get_folder_id(self, folder_name):
        logger.debug(f"Getting folder id for name {folder_name}")
        for folder in self.get_folders():
            if folder["name"] == folder_name:
                return folder["id"]
        return None

    def create_folder(self, folder_name):
        logger.info(f'Creating folder "{folder_name}"')
        return self.action("POST", "/folders", data={"name": folder_name})["id"]

    # Scans

    def get_scans(self):
        return self.action("GET", "/scans")["scans"]

    def get_folder_scans(self, folder_id):
        return self.action("GET", "/scans", params={"folder_id": folder_id})["scans"]

    def get_scan_name(self, scan_id):
        return self.action("GET", f"/scans/{scan_id}")["info"]["name"]

    def get_scan_details(self, scan_id):
        return self.action("GET", f"/scans/{scan_id}")

    def get_plugin_details(self, scan_id, plugin_id):
        return self.action("GET", f"/scans/{scan_id}/plugins/{plugin_id}")

    @locked
    def create_scan(self, template_uuid, name, targets, description=None, policy_id=None, folder_id=None):
        logger.info(f'Creating scan "{name}" in folder ID {folder_id}')
        data = {
            "uuid": template_uuid,
            "settings": {
                "name": name,
                "text_targets": targets,
                "description": description,
                "policy_id": policy_id,
                "folder_id": folder_id,
            },
        }
        return self.action("POST", f"/scans", data=data)

    # Templates

    def get_scan_templates(self):
        return self.action("GET", "/editor/scan/templates")["templates"]

    def get_policy_templates(self):
        return self.action("GET", "/editor/policy/templates")["templates"]

    # Policies

    def get_policies(self):
        return self.action("GET", "/policies")["policies"]

    def get_policy_details(self, policy_id):
        return self.action("GET", f"/policies/{policy_id}")

    def get_policy_uuid(self, policy_id):
        logger.debug(f"Getting UUID for policy {policy_id}")
        return self.get_policy_details(policy_id)["uuid"]

    def get_policy_id(self, policy_name):
        logger.debug(f"Getting policy ID for name {policy_name}")
        matches = filter(lambda p: p["name"] == policy_name, self.get_policies())
        return next(matches, None)["id"]

    # Common tasks

    def export_scan(self, scan_id, history_id):
        logger.debug(f"Exporting scan {scan_id}, history item {history_id}")
        res = self.action(
            "POST",
            f"/scans/{scan_id}/export",
            params={"history_id": history_id},
            data={"format": "nessus"},
        )

        # TODO error checking if file exists because it doesn't when the scan can't be exported

        export_url = f"/scans/{scan_id}/export/{res['file']}"
        while self.action("GET", f"{export_url}/status")["status"] != "ready":
            time.sleep(3)
        return self.action("GET", f"{export_url}/download", download=True)

    @locked
    def import_scan(self, filename, file_stream, folder_id):
        files = {"Filedata": (filename, file_stream)}
        res = self.action("POST", "/file/upload", files=files, json_req=False)

        tmp_filename = res["fileuploaded"]
        return self.action("POST", "/scans/import", data={"file": tmp_filename, "folder_id": folder_id})


nessus = Nessus()
