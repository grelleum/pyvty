#!/usr/bin/env python

from __future__ import print_function
import fileinput
import sys
import time
import pyvty

usage = """
/// EARLY DEMO - DOES NOT APPLY CONFIGURATION ///

This script applies port-security configuration to access ports.

Will Prompt once for username and twice for password.
Assumes all switches will have same login credentials.

Specify each host in a file.  Provide filename at runtime.

"""

port_security = """
switchport port-security
switchport port-security maximum 3
switchport port-security violation restrict
switchport port-security mac-address sticky
""".strip().splitlines()


def FAKE_CONFIG(text):
    print('[FAKE_CONFIG] {0}'.format(text))


print(usage)
user = pyvty.get_username()
password = pyvty.get_password()

for host in fileinput.input():
    try:
        host = host.strip()
        if host == '' or host.startswith('#'):
            continue
        interfaces = list()
        
        print('\n{0}'.format('='*80))
        print('Connecting to host {0}'.format(host))
        term = pyvty.Terminal(host=host, username=user, password=password)

        # Gather interfaces.
        interface = None
        for line in term.send("show run all").splitlines():
            if line.startswith('interface '):
                interface = line.split(' ')[1]
            elif 'switchport access vlan' in line:
                if interface is not None:
                    interfaces.append(interface)
            elif not line.startswith(' '):
                interface = None                

        # Gather CDP neighbors.
        route_switch = False
        for line in term.send("show cdp neighbor detail").splitlines():
            if 'Capabilities:' in line:
                if 'Router' in line or 'Switch' in line:
                    route_switch = True
                else:
                    route_switch = False
            elif line.startswith('Interface:'):
                if route_switch:
                    interface = line.split()[1].rstrip(',')
                    if interface in interfaces:
                        interfaces.remove(interface)

        # Apply configuration to ports.  ### ONLY PRINTING TO SCREEN  ###
        FAKE_CONFIG("config term")
        for interface in interfaces:
            FAKE_CONFIG('interface {0}'.format(interface))
            for line in port_security:
                FAKE_CONFIG(line)
            FAKE_CONFIG('exit')
            FAKE_CONFIG('!')
        FAKE_CONFIG("end")
        FAKE_CONFIG("write mem")

        term.close()
        
    except pyvty.exceptions as error:
        print('Error connecting to {0}: {1}'.format(host, error))


