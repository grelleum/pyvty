#!/usr/bin/env python

from __future__ import print_function
import datetime
import fileinput
import re
import sys
import time
import pyvty
from pyvty import dual_print

VERSION = '0.11'

usage = '''
This script applies port-security configuration to access ports.

Will Prompt once for username and twice for password.
Assumes all switches will have same login credentials.

Specify each host in a file.  Provide filename at runtime.

'''

filelist = sys.argv[1:]
write_config = False
if '--write' in filelist:
    write_config = True
    filelist.remove('--write')

port_security = '''
switchport port-security maximum 3
switchport port-security violation restrict
switchport port-security mac-address sticky
switchport port-security
'''.strip().splitlines()

mac_addr_re = re.compile(r' [0-9A-F]{4}\.[0-9A-F]{4}\.[0-9A-F]{4} ', re.IGNORECASE)

print(usage)
user = pyvty.get_username()
password = pyvty.get_password()
filename = 'port_security_' + pyvty.filestamp() + '.txt'

try:
    output_file = open(filename, 'w')
except exception as error:
    output_file = None
    print('exception raise while trying to write to file {0}\n {1}'.format(
        filename, exception), file=sys.stderr)

for host in fileinput.input(filelist):
    try:
        host = host.strip()
        if host == '' or host.startswith('#'):
            continue

        interfaces = dict()
        logfile = 'ps_' + host + '.log'
        
        dual_print('\n{0}'.format('='*80))
        dual_print('Connecting to host {0}'.format(host))
        term = pyvty.Terminal(host=host, username=user, password=password, logfile=logfile)

        hostname = term.send('show run | i ^hostname').split()[-1]
        dual_print('! Hostname: {0}'.format(hostname), file=output_file)
        dual_print('! Host:     {0}'.format(host), file=output_file)

        # Gather interfaces.
        interface = None
        for line in term.send('show run | i ^interface|switchport'):
            if line.startswith('interface '):
                interface = line.split(' ')[1]
                interfaces[interface] = "No 'switchport mode access' found"
            elif 'switchport access vlan' in line:
                if interface is not None:
                    interfaces[interface] = None
            elif 'switchport mode access' in line:
                if interface is not None:
                    interfaces[interface] = None
            elif 'switchport mode trunk' in line:
                if interface is not None:
                    interfaces[interface] = 'switchport mode trunk'
            elif not line.startswith(' '):
                interface = None                

        ###Command rejected: GigabitEthernet1/2 is a dynamic port.

        # Check for interfaces with excessive MAC addresses.
        for interface in interfaces:
            mac_count = 0
            show_macs = 'show mac add interface {0}'.format(interface)
            for line in term.send(show_macs):
                if mac_addr_re.search(line):
                    mac_count += 1
            if int(mac_count) > 3:
                interfaces[interface] = 'too many MAC addresses seen: {0}'.format(mac_count)

        # Gather CDP neighbors.
        route_switch = False
        for line in term.send('show cdp neighbor detail'):
            if 'Capabilities:' in line:
                if 'Router' in line or 'Switch' in line:
                    route_switch = True
                else:
                    route_switch = False
            elif line.startswith('Interface:'):
                if route_switch:
                    interface = line.split()[1].rstrip(',')
                    interfaces[interface] = 'cdp neighbor'

        # Remove and report blacklisted interfaces
        dual_print('!', file=output_file)
        for interface in sorted(interfaces):
            if interfaces[interface] is not None:
                dual_print('! Skipping Interface: {0}, Reason: {1}'.format(
                    interface, interfaces[interface]), file=output_file)
        dual_print('!', file=output_file)

        # Apply configuration to ports. Only sends config is write_config is True.
        print(term.send('config term', send=write_config))
        for interface in interfaces:
            if interfaces[interface] is None:
                print(term.send('interface {0}'.format(interface), send=write_config))
                for command in port_security:
                    print(term.send(command, send=write_config))
                print(term.send('exit', send=write_config))
                print(term.send('!', send=write_config))
        print(term.send('end', send=write_config))
        print(term.send('write mem', send=write_config))
        
        term.close()
        
    except pyvty.exceptions as error:
        print('Error connecting to {0}: {1}'.format(host, error))

if output_file:
    output_file.close()
