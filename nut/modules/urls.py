from nut.config import settings
from nut.modules.logger import NUTAdapter
from nut.modules.nessus import nessus

logger = NUTAdapter()


def urls(scan_ids):
    outfile = settings.args.outfile or "webservers.txt"

    logger.info("Generating list of web servers")
    url_list = set()

    def _add(_proto, _host, _port):
        # http implies port 80 and https implies port 443 so we can omit it
        if _proto == "https" and _port == 443 or _proto == "http" and _port == 80:
            url_list.add(f"{_proto}://{_host}")
        else:
            url_list.add(f"{_proto}://{_host}:{_port}")

    success = False

    for scan_id in scan_ids:
        # Service Detection - Plugin ID 22964
        #  Shows www as svc_name for both http and https, but the output text is different
        #   http: A web server is running on this port.
        #   https: A web server is running on this port through ...
        service_detection = nessus.get_plugin_details(scan_id, 22964)

        # If the scan hasn't been run, has failed, or if the plugin simply doesn't exist
        # we need to skip it
        if not service_detection or not service_detection["outputs"]:
            logger.error(f"Scan ID {scan_id} doesn't have service detection - did it run and finish?")
            continue

        for output in service_detection["outputs"]:
            p_out = output["plugin_output"]
            if not p_out.startswith("A web server is running"):
                continue

            # At this point we have a valid entry
            success = True

            proto = "https" if "through" in p_out else "http"
            for svc, hosts in output["ports"].items():
                port = int(svc.split(" / ", 1)[0])
                for host in hosts:
                    _add(proto, host["hostname"], port)

    # If there wasn't a single valid scan we inform the user and abort
    if not success:
        logger.error("None of the scans found a web server")
        return

    with open(outfile, "w") as fp:
        logger.info(f'Writing file "{outfile}"')
        fp.write("\n".join(url_list))
