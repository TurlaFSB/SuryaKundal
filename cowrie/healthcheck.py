"""Container healthcheck: is something listening on the SSH port?

Reads /proc/net/tcp instead of connecting. A connection would be logged by Cowrie as a
real session every few seconds and pollute the dataset.
"""

import sys

PORT_HEX = f"{2222:04X}"
LISTEN = "0A"


def listening(path: str) -> bool:
    try:
        with open(path, encoding="ascii") as handle:
            rows = handle.read().splitlines()[1:]
    except OSError:
        return False
    for row in rows:
        fields = row.split()
        if len(fields) > 3 and fields[1].endswith(":" + PORT_HEX) and fields[3] == LISTEN:
            return True
    return False


sys.exit(0 if listening("/proc/net/tcp") or listening("/proc/net/tcp6") else 1)
