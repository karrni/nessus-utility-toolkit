from nut.modules.logger import NUTAdapter
from nut.modules.nessus import nessus

logger = NUTAdapter()


def urls(scan_ids, outfile=None):
    if not outfile:
        outfile = "webservers.txt"

    logger.info("Generating url list")
    url_list = set()

    def _add(_proto, _host, _port):
        # http implies port 80 and https implies port 443 so we can omit it
        if _proto == "https" and _port == 443 or _proto == "http" and _port == 80:
            url_list.add(f"{_proto}://{_host}")
        else:
            url_list.add(f"{_proto}://{_host}:{_port}")

    for scan_id in scan_ids:
        # Service Detection - Plugin ID 22964
        #  Shows www as svc_name for both http and https, but the output text is different
        #   http: A web server is running on this port.
        #   https: A web server is running on this port through ...
        service_detection = nessus.get_plugin_details(scan_id, 22964)
        # TODO: error handling
        for output in service_detection["outputs"]:
            p_out = output["plugin_output"]
            if not p_out.startswith("A web server is running"):
                continue

            proto = "https" if "through" in p_out else "http"

            for svc, hosts in output["ports"].items():
                port = int(svc.split(" / ", 1)[0])
                for host in hosts:
                    _add(proto, host["hostname"], port)

    with open(outfile, "w") as fp:
        fp.write("\n".join(url_list))
