import ipaddress
from pathlib import Path

from nut.modules.logger import NUTAdapter
from nut.modules.nessus import nessus

logger = NUTAdapter()


def get_scan_ids(scans, folders):
    logger.info("Gathering Scan IDs")
    scan_ids = set()

    # TODO we can actually just use this for everything I think
    # nessus_data = nessus.get_scans()

    # first we go through all the supplied scans. It's fairly straight forward
    # because they can only be the scans ID
    for s in scans:
        # to ensure it is valid we try to
        if nessus.get_scan_details(s):
            scan_ids.add(s)
        else:
            logger.error(f"Scan with ID {s} doesn't exist")

    for f in folders:
        if not f.isdigit():
            f_id = nessus.get_folder_id(f)
            if not f_id:
                logger.error(f"Folder {f} doesn't exist")
                continue
        else:
            f_id = f

        folder_scans = nessus.get_folder_scans(f_id)
        if not folder_scans:
            logger.error(f"Folder {f_id} either doesn't exist, or is empty")
            continue

        for s in folder_scans:
            scan_ids.add(s["id"])

    scan_ids = list(scan_ids)
    logger.success(f"Scan IDs: {scan_ids}")
    return scan_ids


def resolve_scope(targets, exclusions, as_text=True):
    _exclusions = set()
    for exclude in exclusions:
        host = ipaddress.ip_address(exclude)
        _exclusions.add(host)

    ranges = []

    for target in targets:
        try:
            host = ipaddress.ip_address(target)
            if host not in _exclusions:
                ranges.append(host)
                continue
        except ValueError:
            pass

        net = ipaddress.ip_network(target)

        # The goal is to create human-readable target ranges, so for example:
        #   target: 10.0.0.0/24, exclude: 10.0.0.17
        #     -> 10.0.0.1-16, 10.0.0.18-254
        #
        # So we start with the CIDR notation of a network and split it into ranges
        # that are limited by the exclusions. For this, we iterate over all hosts
        # while keeping track of the "first" one until we hit an exclusion. When we
        # do, we add the "first" element we've been keeping track of and the
        # previous element as a range. Afterwards, the first element that's not
        # excluded is the next "first" element of the range.

        # These keep track of the "first" and previous element
        first, prev = None, None

        # If the current network doesn't have a single exclusions, it's fine if we
        # add the CIDR notation to the list. For this we keep track of it:
        no_exclusions = True

        for host in net.hosts():

            # As explained above, when we hit an exclusion it means we can add the
            # range from current "first" to the previous element to our list
            if host in _exclusions:

                # If we have a first and last element for the current range we add
                # it to the list.
                if first and prev:
                    ranges.append((first, prev))

                    first, prev = None, None  # And we reset
                    no_exclusions = False  # It also means that we had exclusions

                # Regardless if we just added another range, skip the rest of the
                # loop of the current element is excluded
                continue

            # If we just had one or more exclusions, first will be reset. This
            # means that we just started a new range and need to keep track of
            # the current host.
            if not first:
                first = host

            # At the end of each loop, keep track of the "previous" element
            prev = host

        # We've finished iterating over all hosts. If we had no exclusions, we can
        # add the network itself. Otherwise, we have to add the last range.
        if no_exclusions:
            ranges.append(net)

        # We have to check this. Otherwise, if the last host was an exclusion, we
        # would add (None, None) to the list.
        elif first and prev:
            ranges.append((first, prev))

    if not as_text:
        return ranges

    text_ranges = []
    for item in ranges:
        if isinstance(item, tuple):
            text_ranges.append(f"{item[0]}-{item[1]}")
        else:
            text_ranges.append(f"{item}")

    return text_ranges


def print_table(d, cols=None, space=2):
    if not cols:
        cols = list(d[0].keys() if d else [])

    rows = [cols]
    for i in d:
        rows.append([str(i[col] if i[col] else "") for col in cols])

    width = [max(map(len, col)) for col in zip(*rows)]
    f_str = " | ".join(["{{:<{}}}".format(w) for w in width])

    rows.insert(1, ["-" * w for w in width])

    print()
    for row in rows:
        print(" " * space + f_str.format(*row))


def secure_filename(filename):
    keep = (" ", ".", "-", "_", "&", "+")
    return "".join(c for c in filename if c.isalnum() or c in keep).rstrip()


def mkdir(path):
    Path(path).mkdir(parents=True, exist_ok=True)
