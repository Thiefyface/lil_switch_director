### Lilith's Switch Director (LSD) ###
## <(^.^)> ~ For when the grind gets tough, just use LSD ~ <(^.^)> ##

Usage: lsd.py <options>
 -u  --username=<username>               - Specify a username to login with
 
 -i  --instruction=<instruction>         - Only run a single set of commands
 
 -l  --list_file=<switches&cmds.txt>     - Parse the given switch/cmd file for instructions
 
 -a  --at=HR:MIN (0-23):(0-59)           - execute at time : AB:CD (24-hour format)
 
 -s  --sleep-mins=<minutes>              - Delay between instruction file lines (=> -l)
 
 -p  --port=<tcpport>                    - For those pesky non-22 ssh ports
 
 -r  --record=<dir>                  - log to files in ./logs/dir (name automatically genarated)
 
 -v  --verify                       - Wait for the switch to respond to ssh connect before moving on (=> -l)
 -t  --text                              - Send a text on failure (requires valid login to google mail )
 
 -f  --fail-count=<amt>                  - Max amount of times to retry Authentication
 
 -c  --single-command=<cmd>              - Run <cmd> over all IPs, overrides all other commands given

###Special commands: ###    (include w/ -c or in command-file)
enable                                  - authenticate w/enable password

newcreds                                - Prompt for username/pass again, clear enable password

enter                           - send \r (hit enter key)

saverunning                     - dump running config to file

###Instruction file format example:###

192.168.1.1,enable,conf t,int gi1/1,shut

192.168.2.2,en,sh run

192.168.3.4,en,download vlan.dat vlandat.bak,upload newvlan.dat vlan.dat