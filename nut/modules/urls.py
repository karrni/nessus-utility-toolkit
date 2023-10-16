import logging

from nut.settings import args
from nut.utils import nessus

logger = logging.getLogger(__name__)

SERVICE_DETECTION_PLUGIN_ID = 22964


def _build_url(proto, host, port):
    """Returns a URL from the supplied parts."""

    # if the port is the default for the protocol we can omit it
    if (proto == "http" and port == 80) or (proto == "https" and port == 443):
        return f"{proto}://{host}"

    return f"{proto}://{host}:{port}"


def get_urls(scan_ids: list[int]) -> set[str]:
    logger.info("Searching scans for webservers")

    urls = set()

    for scan_id in scan_ids:
        logger.debug(f"Searching scan '{scan_id}'")

        # Get the output of the 'Service Detection' plugin
        service_detection = nessus.get_plugin_details(scan_id, SERVICE_DETECTION_PLUGIN_ID)
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
                    url = _build_url(proto, host["hostname"], port)
                    logger.debug(f"Found web server '{url}'")
                    urls.add(url)

    return urls


def run():
    urls = get_urls(args.scan_ids)
    if not urls:
        logger.error("None of the scans detected a webserver")
        return

    outfile = args.outfile
    logger.info(f"Writing URLs to '{outfile}'")
    with outfile.open("w") as fp:
        fp.write("\n".join(urls))
