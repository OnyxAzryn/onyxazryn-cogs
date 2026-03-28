from typing import Set

def read_hosts_file_domains(f) -> Set[str]:
    """
    Read a hosts file and return a list of all domain/host names it contains.

    Parameters
    ----------
    f
        A hosts file

    Returns
    -------
    set[str]
        All host names found, preserving order of appearance.
    """
    domains: Set[str] = set([])

    # Read the file line‑by‑line
    for raw_line in f.readlines():
        line = raw_line.strip()
        # ------------------------------------------------------------------
        # Skip blank lines and remove full‑line comments (lines that start with "#")
        # ------------------------------------------------------------------
        if not line or line.startswith("#"):
            continue

        # ------------------------------------------------------------------
        # Strip inline comments – everything after the first "#"
        # ------------------------------------------------------------------
        if "#" in line:
            line = line.split("#", 1)[0].strip()

        # ------------------------------------------------------------------
        # Split the remaining tokens:  IP  HOST1  HOST2 …
        # ------------------------------------------------------------------
        parts = line.split()
        if len(parts) < 2:
            # No host names on this line – ignore it
            continue

        # The first token is the IP address, the rest are host names
        host_names = parts[1:]

        # Append them to the result list
        domains.extend(host_names)

    return domains