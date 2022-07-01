import xml.etree.cElementTree as etree
from datetime import datetime
from pathlib import Path

from nut.config import settings
from nut.modules.logger import NUTAdapter
from nut.modules.nessus import nessus
from nut.modules.utils import mkdir, secure_filename

logger = NUTAdapter()


class ScanExportXml:
    def __init__(self):
        self._tree = None
        self._report = None  # The "Report" element contains the actual hosts
        self._seen = dict()  # To keep track of all indexed hosts and vulns to avoid duplicates

    def add(self, xml_export):
        cur_tree = etree.ElementTree(etree.fromstring(xml_export))
        cur_report = cur_tree.find("Report")

        # If the current export is the first one, just use it as the base export and add to it
        if not self._tree:
            self._tree = cur_tree
            self._report = cur_report

            # Cycle through every host and create a list of all findings that will be
            # tracked in the _seen variable.
            for host in cur_report.findall(".//ReportHost"):
                findings = set()
                for item in host.findall("ReportItem"):
                    findings.add(item.attrib["port"] + "-" + item.attrib["pluginID"])
                self._seen[host.attrib["name"]] = findings
            return

        # When adding a new export, cycle through all the hosts
        else:
            for host in cur_report.findall(".//ReportHost"):
                hostname = host.attrib["name"]

                # If the current host has not been seen before, just copy everything
                if hostname not in self._seen:
                    self._report.append(host)
                    findings = set()
                    for item in host.findall("ReportItem"):
                        findings.add(item.attrib["port"] + "-" + item.attrib["pluginID"])
                    self._seen[hostname] = findings

                # If it has been seen, cycle through the findings and only add the ones that have not been seen before
                else:
                    report_host = self._tree.find(".//ReportHost[@name='" + hostname + "']")
                    for item in host.findall("ReportItem"):
                        key = item.attrib["port"] + "-" + item.attrib["pluginID"]
                        if key not in self._seen[hostname]:
                            report_host.append(item)
                            self._seen[hostname].add(key)

    def write(self, file, name=None):
        if name:
            self._report.attrib["name"] = name

        self._tree.write(file)


def export_scan(scan_ids, scan_name, file):
    """Download and merge all scan IDs into one and write it to file."""
    scan_export = ScanExportXml()
    success = False

    for scan_id in scan_ids:
        scan_details = nessus.get_scan_details(scan_id)

        # If the current scan doesn't have any history items it can't be exported because
        # it either hasn't been run, or it failed in some way we need to skip it
        if not scan_details["history"]:
            logger.error(f"Scan ID {scan_id} doesn't have a history - did it run and finish?")
            continue

        # Nessus scans can be run multiple times which will create multiple history items.
        # When exporting a scan properly (and completely) every history item needs to be
        # exported and merged into one.
        for history_item in scan_details["history"]:
            # Mocks:Issue #3 - only completed or imported scans
            # Mocks:Issue #12 - also cancelled scans
            if history_item["status"] in ["completed", "imported", "canceled"]:
                content = nessus.export_scan(scan_id, history_item["history_id"])
                scan_export.add(content)
                success = True

    # If there wasn't a single valid scan we inform the user and abort
    if not success:
        logger.error("No scans could be exported")
        return

    logger.info(f'Writing file "{file}"')
    mkdir(file.parent)
    scan_export.write(file, scan_name)


def export(scan_ids):
    outdir = settings.args.outdir or ""

    if settings.args.merge:
        logger.info("Exporting merged scan")

        scan_name = "Merged Scan"

        # add a timestamp and string with the scan ids to the filename
        t_str = datetime.today().strftime("%Y-%m-%d %H%M%S")
        file_name = f"{t_str} - {scan_name} - {scan_ids}"

        outfile = Path(outdir) / f"{secure_filename(file_name)}.xml"

        export_scan(scan_ids, scan_name, outfile)
    else:
        logger.info(f"Exporting scan{'s' if len(scan_ids) > 1 else ''}")
        for scan_id in scan_ids:
            scan_name = nessus.get_scan_name(scan_id)

            folder_id = nessus.get_scan_folder(scan_id)
            folder_name = nessus.get_folder_name(folder_id)

            outfile = Path(outdir) / folder_name / f"{secure_filename(scan_name)}.xml"

            export_scan([scan_id], scan_name, outfile)
