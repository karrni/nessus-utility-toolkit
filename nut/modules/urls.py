import logging

from nut.config import settings
from nut.utils import nessus

logger = logging.getLogger(__name__)


def build_url(proto, host, port):
    # if the port is the default for the protocol we can omit it
    if (proto == "http" and port == 80) or (proto == "https" and port == 443):
        url = f"{proto}://{host}"
    else:
        url = f"{proto}://{host}:{port}"
    logger.debug(f"Found web server '{url}'")
    return url


def get_urls(scan_ids: list[int]) -> set[str]:
    logger.info("Searching scans for web servers")

    urls = set()

    for scan_id in scan_ids:
        logger.debug(f"Checking scan '{scan_id}'")
        # Get the output of the 'Service Detection' plugin
        service_detection = nessus.get_plugin_details(scan_id, 22964)

        if not service_detection:
            logger.error(f"Scan '{scan_id}' has no 'Service Detection', did it run and finish?")
            continue

        outputs = service_detection.get("outputs")
        if not outputs:
            logger.error(f"Scan '{scan_id}' has no 'Service Detection' results")
            continue

        # The 'Service Detection' plugin identifies both http and https as
        # 'www' in the 'svc_name' field, but the output text is different:
        #     http: A web server is running on this port.
        #     https: A web server is running on this port through [...]
        for output in outputs:
            plugin_output = output["plugin_output"]

            # We can use this to check if the current output is a web server
            if not plugin_output.startswith("A web server is running"):
                continue

            # And whether it's using http or https
            proto = "https" if "through" in plugin_output else "http"

            for svc, hosts in output["ports"].items():
                port = int(svc.split(" / ", 1)[0])
                for host in hosts:
                    urls.add(build_url(proto, host["hostname"], port))

    return urls


def run():
    urls = get_urls(settings.scan_ids)

    if not urls:
        logger.error("None of the scans detected a web server")
        return

    outfile = settings.args.outfile
    logger.info(f"Writing URLs to '{outfile}'")
    with outfile.open("w") as fp:
        fp.write("\n".join(urls))
