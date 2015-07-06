#!/usr/bin/env python

import pyvty

user = 'admin'
password = 'password'

host = '10.36.65.227'
config_file = 'config.txt'  # name of text file containing config commands.
logfile = 'config_' + host + '.log'  # terminal output will be saved in this file.


try:
    input_file = open(config_file)
    commands = input_file.readlines()
    input_file.close()
except IOError as e:
    print(e)
    exit()


term = pyvty.Terminal(host=host, username=user, password=password, logfile=logfile)

term.send('config term')

for command in commands:
    results = term.send(command.rstrip())
    for line in results:
        print(line.rstrip())

# term.send('write mem')    ''' save configuration to disk '''
term.send('end')
term.write('exit')
