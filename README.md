# pyvty

pyvty provides a single object that creates a terminal connection to a device over the diverse protocols of SSH and Telnet.

_Work in progress_

SSH and telnet libraries provide completely different interfaces to the user, and yet the goal for simple terminal functions are the same.  pyvty unifies the two so code logic can be written to a simple interface and be used across an array of devices that may have one or the other protocol available.

examples scripts:
port_security.py  # applies port security commands to access ports.
cdp_neighbors.py  # sets descriptions for interface with a cdp neighbor.
