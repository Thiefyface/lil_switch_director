#!/usr/local/bin/python

import paramiko
import getopt
import getpass
import sys
import socket
import smtplib
import os
from colors import *
from time import asctime,sleep,localtime,time
from errno import *
from email.mime.text import MIMEText
from traceback import format_tb

RETRYLIMIT = 10
MAXFAIL = 3

port = 22 
username = ""
instr_list = [("",[])]
logfile=None
email_addresses = ["test@email.com"]
text_addresses = ["<number>@txt.att.net"]


flags = {
	'logging':False,
	'saverun':False,
	'switchverify':False,
	'configWritten':False,
	'verify':False,
	'enable':"",
	'text':False,
	'sleep_time':0,
	'single':False
}
switchstatus = ""

logbuff=["Arguments: " + str(sys.argv[1:])]
lsmtp_serv = "lsmtp.lol.com"
#so we don't have to flush() stdout whenever we want to print
sys.stdout = os.fdopen(sys.stdout.fileno(),'w',0)

# <(^.^)>
# # # # TODO # # # # # #
#  Interactive trip mode? Record/replay? Omg.  
#  Add Telnet support
#  More flexibility in IP's, besides just listing
#  multithreading over a single trip (if read only/different IP on each line)
#  resuming a failed trip
#  store alternate creds in dict (try last successful first)
#  what to do if it's not there in the first place
#  Implimentation of upload/download
#  Responding to output 

def usage():
	print underline("Lilith's Switch Director (LSD)", fg='black',bg='cyan')
	print black("<(^.^)> ~ For when the grind gets tough, just use LSD ~ <(^.^)>", bg='cyan')
	print 
	print red("Usage: lsd.py <options>",bg='black')
	print "-u  --username=<username> 		- Specify a username to login with"
	print "-i  --instruction=<instruction>		- Only run a single set of commands"
	print "-l  --list_file=<switches&cmds.txt>     - Parse the given switch/cmd file for instructions"
	print "-a  --at=HR:MIN (0-23):(0-59)	 	- execute at time : AB:CD (24-hour format)"
	print "-s  --sleep-mins=<minutes>		- Delay between instruction file lines (=> -l)" 
	print "-p  --port=<tcpport>			- For those pesky non-22 ssh ports"
	print "-r  --record=<dir>			- log to files in ./logs/dir (name automatically genarated)"
	print "-v  --verify				- Wait for the switch to respond to ssh connect before moving on (=> -l)"
	print "-t  --text				- Send a text on failure (requires valid login to google mail )"
	print "-f  --fail-count=<amt>			- Max amount of times to retry Authentication"
	print "-c  --single-command=<cmd>		- Run <cmd> over all IPs, overrides all other commands given"
	print
	print red("Special commands:     (include w/ -c or in command-file)",bg='black')
	#print "upload <localfile> <remotefile>		- checks for file on local computer, uploads to switch via http"
	#print "download <remotefile> <localfile>	- trys to grab file from switch via http"
	print "enable					- authenticate w/enable password"
	#print "repeat					- run same commands as the switch before"
	print "newcreds				- Prompt for username/pass again, clear enable password"
	print "enter				- send \\r (hit enter key)"
	print "saverunning			- dump running config to file"
	print
	print red("Instruction file format example:",bg='black')
	print "192.168.1.1,enable,conf t,int gi1/1,shut"
	print "192.168.2.2,en,sh run"
	print "192.168.3.4,en,download vlan.dat vlandat.bak,upload newvlan.dat vlan.dat"
	print 

	sys.exit(0)



def loglog(input):
	global logbuff
	global logfile

	if flags['logging']:
		try:
			logfile.write(input)
		except:
			logbuff.append("Unable to write buffer:")	
	logbuff.append(input)

# Find amount of seconds from current local time till the given input time 't'
# Input
# t - arbitrary time of day in 24-hr format (e.g. 23:55), must be 5 chars long 
# Output
# sleep_time - seconds from current time till the time given 't'
def find_delay(t):
	assert len(t) == 5, "[x.x] Invalid time given"	
	h,m = t.split(':')
	h = int(h)
	m = int(m)
	
	assert h in range(0,24) and m in range(0, 60), "[x.x] Invalid Hour/minut"
	hrs_till = ((h - localtime().tm_hour) % 24)  
	min_till = (m - localtime().tm_min) % 60
	if h == localtime().tm_hour and m < localtime().tm_min:
		hrs_till = 23
	
	
	print "%.2d:%.2d till %.2d:%.2d (curr time %.2d:%.2d)" % (hrs_till, min_till, h,m, localtime().tm_hour, localtime().tm_min)	
	return (60 * min_till) + (3600 * hrs_till)
	
#(b - time.localtime().tm_min) % 60
#(b - time.localtime().tm_hour) % 24

#Input  : filename = csv of format: switchip,cmd1,cmd2,...,cmdX\r\n switchip2,cmdx+1....
#Output : instr_list = list of tuples: [(switch1,[cmd1,cmd2...cmdX]),(switch2,[cmdY1,cmdY2,...])
def parse_instruction(instr):
	line = instr.split(',') 

	if not len(line[0]):
		if not flags['single'] and not len(line[1:]):
			raise Exception("No instructions given: %s")		

	#verify valid IP
	try: socket.inet_aton(line[0])
	except: usage() 

		
	#get rid of newlines
	for cmd in line:
		cmd = cmd.rstrip()	
	if flags['single']:
		
		return (line[0].rstrip(), [flags['single']])

	return (line[0], line[1:])	
		



def preprocess_commands(cmd_list):
	global flags	
	for c in cmd_list:
		try:
			if ["wr mem", "copy run start", "copy running-config startup-config", "wr"].index(c):
				flags['configWritten'] = True	
		except:
			pass

		if c == "saverunning":
			cmd_list[cmd_list.index("saverunning")] = "sh run"
			flags['saverun'] = True

		if c == "switchverify":
			cmd_list[cmd_list.index("switchverify")] = "sh switch"
			flags['switchverify'] = True

		#just send \r if enter command
		if c == "enter":
			cmd_list[cmd_list.index("enter")] = "\r"

		if (c == "enable" or c == "en"):
			if not flags['enable']:
				print "Currently :" + flags['enable']
				flags['enable'] = getpass.getpass(cyan("[O.O] Gimme yur enablz:"))
			cmd_list[cmd_list.index(c)] = "enable"

		if c == "reload":
			cmd_list[cmd_list.index(c)] = c + " Switch reload occurring due to LSD trip\r"

	#if we're verifying, we need a baseline of the switches before modification:
	if flags['verify']:
		cmd_list.insert(0,"sh switch")		

	return cmd_list


#Connect to switch/authenticate with switch
#send commands to the switch/preprocess the instruction macros	
def ssh_exec(ip, cmd_list, user="", passwd="", conn_test=0):
	global logfile
	global flags
	global switchstatus
	
	assert len(cmd_list) > 0	
	assert len(ip) in range(7,16)

	if not len(passwd) and not conn_test:
		user, passwd = new_credentials(user)

	switchstatus = ""
	retbuff = ""
	output = "x"

	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	print "['.'] Connecting to %s:%s, as user %s" % (ip,port,user)	
	client.connect(ip,port,username=user,password=passwd)	
		
	#if you want to do interactive shell, start looping here
	#and using something like sys.stdin.read() to do the input
	session = client.get_transport().open_session()	
	session.invoke_shell()
	session.settimeout(5)
	print green("[^.^] Authentication successful!!!")
	
	if conn_test:
		session.send("exit\r")

	retbuff+=session.recv(4096)
	print(retbuff)

	
	#get all the macros expanded/changed/flags set
	cmd_list = preprocess_commands(cmd_list)

	#Make sh commands display correctly on output:
	session.send("terminal length 0\r") 
	print cmd_list
	for c in cmd_list:
		
		if "software install" in c:
			session.settimeout(60)
		elif session.gettimeout == 60:
			session.settimeout(5)		
	
		if c == "reload" and not flags['configWritten']:	
				print yellow("[!.!] Pump your brakes kid, that config's a national treasure...(sending \"wr mem\")")
				session.send("wr mem\r")
				print yellow("[!.!] Reloading switch!")						
	
	
################## END instructions Macros########################

		#Normal command send			
		session.send(c + "\r")	
		print cyan(c)

	
		if c == "enable":
			session.send(flags['enable']+ "\r")
			loglog("['.'] Sent enable pass!\r\n")
			while len(output):
				try:
					session.recv(4096)
				except:
					break
		try:
			if c[0:6] == "reload":
				print yellow("[-.-] Hitting enter....")
				sleep(2)
				session.send("\r")
				session.send("\r")
		except:
			pass	

		while len(output):
			try:
				output = session.recv(4096)
				sys.stdout.write(output)				
				retbuff+=output	
				
				#grab our relevant sh switch info
				if flags['verify'] and c == "sh switch":
					start = retbuff.rfind("Switch#   Role")
					ending = retbuff.rfind("Ready\x20\x20\x20\x20")	
					switchstatus = retbuff[start:ending+5]	
					

				loglog(output)
				
			except socket.timeout:
				break	
			except:
				pass

	

	client.close()
		
	#Save run command
	if flags['saverun']:
		start = retbuff.find("Building configuration...")
		ending = retbuff.find("\r\nend\r\n")
		with open("%s_running.conf" % ip, 'w') as f:
			f.write(retbuff[start:ending+5])		
	


	flags['configWritten'] = False

	return retbuff	




#grab new credentials from user
def new_credentials(username=""):
	if not len(username):	
		username = raw_input(cyan("[^.^] Hi, what's your name? : "))
	password=getpass.getpass(magenta("[~.~] So uh, %s.... you got a pass for those things? :" % username))
	print "[c.c] \"Borrowing\" credentials, kekekeke...."
			
	return username, password

#Try to ssh to box with bad creds once a minute until we actually get auth fail
#After 60 failures (1 hour) send email notification and exit loop/stop instructions
def verify_switches(ip,username,password,oldswitch):
	failcount = 0

	#Switch doesn't shut off automatically....
	print yellow("[@.@] 15 second cooldown before we start ssh'in")
	sleep(30)
	print yellow("['.'] Beginning switch reload testing....")	
	
	
	while True:
		if failcount >= 60:
			print red("[>.>] I don't think it's coming back...Welp. Good luck!")
			print red("      Sending email and exiting!       ...~[>.>]")

			raise Exception("Failure count Maximum reached!")
		else:
			print yellow("[c.c] %d minutes since shutdown" % failcount)


		try:
			ssh_exec(ip,["sh switch"],username,password)			
			print green("[^.^] SSH on %s back up!" % ip)
			break
		except socket.error as sock:
			if sock.errno == ENETUNREACH:
				print yellow("[;.;] No route to host %s Careful..." % ip)	
			elif sock.errno == ETIMEDOUT: 
				print yellow("[x.x] Connection to %s timed out" % ip)
			
			failcount = failcount + 1
			sleep(60)
			continue
	
		except KeyboardInterrupt:
			print red("[-.-] Giving up on connections!")
			sys.exit(0)
		except paramiko.ssh_exception.AuthenticationException:
			print yellow("[?.?] SSH up, Auth failed, lol?")
			break
		except:#########
			print red("[?.?] Unknown error:")
			raise


	print yellow(oldswitch)
	print cyan(switchstatus)
	if oldswitch != switchstatus:
		raise Exception("Switch died on reload! Ending Trip!")	
	
	
def main():	

	global MAXFAIL	
	global port
	global logfile
	global flags
	global email
	
	username = ""
	password = ""
	instr_list = []
	retvalue = cyan("[;.;] I lost da things...")
	sleep_counter = 0
	time_delay = 0

	if not len(sys.argv[1:]):
		usage()

	try:
		opts, args = getopt.getopt(sys.argv[1:],"i:c:u:l:a:s:tp:r:ve:f:s:", 
				["instruction=", "username=", "instr-list=", "at=", "sleep-mins=", "port=", "record=", "verify", "fail-count=","single-command="])
	except getopt.GetoptError as err:
		print str(err)
		usage()


	for o,a in opts:
		#!print "o = %s, a = %s" % (o,a)
		if o in ("-h", "--help"):
			usage()

		elif o in ("-u", "--username"):
			username = a

		elif o in ("-i", "--instruction"):
			if len(instr_list):
				raise Exception("[x.x] Incompatible options, (-l | -i) & -c")
			instr_list.append(parse_instruction(a))

		elif o in ("-c", "--single-command"):
			flags['single'] = a
			if len(instr_list):
				tmp = []
				for ip,args in instr_list:
					tmp.append((ip,[a]))	
				instr_list = tmp	
				del tmp		


		elif o in ("-l", "--list-file"):
			if len(instr_list):
				raise Exception("[x.x] Incompatible options, -l & (-i | -c)")
			with open(a) as f:
				for line in f:
					#ignore comments
					if line[0] != "#":	
						instr_list.append(parse_instruction(line))			
		elif o in ("-a", "--at"):
			scheduled_time = a
			time_delay = find_delay(scheduled_time)
			sleepmsg = "[-.-] Sleeping for %d seconds" 

		elif o in ("-s", "--sleep-mins"):
			flags['sleep_time'] = int(a)	
			napstr = "[-.-] oh i's the sleepy one...(%s minute nap until next switch)"

		elif o in ("-p", "--port"):
			port = a
			assert port in range(1,65535), "[x.x] Invalid Port!"	

		elif o in ("-r", "--record"):
			flags['logging'] = True
			try:
				mkdir("logs")
			except:
				pass
			if a:
				flags['logging'] = a
		elif o in ("-v", "--verify"):	
			flags['verify'] = True

		elif o in ("-t", "--text"):
			continue	

		elif o in ("-f", "--fail-count"):
			try:
				MAXFAIL = int(a)
				if MAXFAIL < 0:
					MAXFAIL = 0
			except:
				pass
		
		else:
			print red("[O.<] U wanna do wut m8? Havin' urself a giggle thar?")		
			print red("[O.<] I ain't heard o' that, heres the menu:")	
			usage()	
	


	
	print underline("Lilith's Switch Director (LSD)", fg='magenta',bg='black')


	if not time_delay:	
		username, password = new_credentials(username)

	for ip,cmd_list in instr_list:
		filename=""
		print "IP=%s, cmd=%s" % (ip,str(cmd_list))
		failcount=0
		retrycount=0
		
		#if -r was passed with a folder name	
		try:
			filename = os.path.join("logs",flags['logging']) 
			os.mkdir(os.path.join(os.getcwd(), filename))
		except Exception as e:
			print e

		filename=os.path.join(filename,"%s_%d:%d:%d:%d.log" % (ip,localtime().tm_mon,localtime().tm_mday,localtime().tm_hour,localtime().tm_min))
		
			
		print "Filename!: %s" % filename	

		if flags['logging']:
			try:
				logfile = open(filename, 'w')		
			except:
				loglog("Unable to log for IP: %s" % ip)
		
		#Since it'd kinda suck to wake up to an "Authentication Failed" message, no?
		if (time_delay) and not len(password):
			print yellow("[>.<] Delaying for %d seconds" % time_delay)
			print "[c.c] But first, gimme yo' creds" 	
			while True:
				
				username, password = new_credentials(username)
				try:
					ssh_exec(ip,"?",username,password,conn_test=1)
					print green("[^.^] Yay, we could log into %s, nap time!" % ip)
					break
				except paramiko.ssh_exception.AuthenticationException:
					print red("[>.>] Yeah....no. Gimme your real creds.")
					continue		
		
			x = time_delay	
			while (x):
				sys.stdout.write(sleepmsg % x)	
				sleep(1)
				sys.stdout.write('\b' * len(sleepmsg))			
				x-=1
	
		if "newcreds" in cmd_list and len(cmd_list) > 1:
			flags["newcreds"] = True
			username, password = new_credentials(username)		
			flags["enable"] = False
			while "newcreds" in cmd_list:
				cmd_list.remove("newcreds")
		
	
		#iterate over each switch, run commands inside of cmd_list with username/password creds	
		while True:
			try:			
				ssh_exec(ip,cmd_list,username,password)
				break
			except paramiko.ssh_exception.AuthenticationException:
				if MAXFAIL == 0:
					break
				print red("[x.x] Authentication failed!")
				print yellow("[c.c] Lets try that again...")
				failcount = failcount + 1	
				if failcount > MAXFAIL:
					print red("[>.>] Alright there bucko, you've had enough....")
					print red("[!.!] Max login attempts reached, exiting!")
					sys.exit(0)
				else:
					username, password = new_credentials()

			except KeyboardInterrupt:
				print yellow("[!.!] Keyboard interrupt recevied, exiting!")
				sys.exit(0)
			except socket.error:
				print red("[>.<] Can't send on a closed socket, baka!")
				print yellow("[-.-] Trying again in a minute...")
				retrycount+=1
				if retrycount >= RETRYLIMIT:
					raise Exception("SSH retry limit reached! Switch is down!")				
				sleep(60)
				pass
			except:
				print red("[~.~] Unknown error!!!")
				raise	

		#to make sure switches come back after we're done ( -v option)	
		if flags['verify']:
			verify_switches(ip,username,password,switchstatus)		

		#time to sleep in between switches in our .trip file ( -s option )	
		# will probably also need time sync fix
		if flags['sleep_time']:
			sleep_counter = flags['sleep_time']
			
		while(sleep_counter):
			for second in range(0,60):
				sys.stdout.write(color( napstr % sleep_counter, fg=COLORS[second % 8]) + "\b" * len(napstr))
				sleep(1)
			if (sleep_counter==1):
				print cyan("[O.O] I\'M UP, LETS DO!!111!!!!11!~~11!!!1!!!!!!!!!!!!11111!!~~~~~~~")		
			
			sleep_counter-=1







## If we get an error, try writing to file, and also sending an email
if __name__ == '__main__':

	if "--text" in sys.argv or "-t" in sys.argv: 
		flags['text'] = True	
		user = raw_input("[*.*] Since texting, need some sort of valid google email address: ")
		password = getpass.getpass()


	try:
		main()
	except Exception as e:
		print e
		print logbuff

		tb = sys.exc_info()[2]
		errmsg="%s\r\n" % asctime()
		for l in format_tb(tb):
			errmsg+=l
		
		print errmsg
	
		errmsg+="\r\n%s\r\n" % e
		errmsg+="Logbuffer:\r\n"

		for l in logbuff:
			errmsg+=str(l)



		try:
			logfile = open("logs/lsd_error_%d.log" % time(), 'w')
			logfile.write(errmsg)
		except:
			pass
	

#Send detailed information via email	
		
		s=smtplib.SMTP("lsmtp.testing.com")
		emailmsg= MIMEText("<(X.x)> The following errors has occurred: %s" % errmsg)
		emailmsg['From'] = "Lsd.com"
		emailmsg['Subject'] = "Bad trip <(X.x)>" 

		s.sendmail(from_addr="lsd@lol.com",to_addrs=email_addresses,msg=emailmsg.as_string()) 

#Send brief Noti via text also
		if flags['text']:
			emailmsg= MIMEText("<(X.x)> Bad trip: %s" % str(format_tb(tb)).replace("\\n",""))
			emailmsg['From'] = user
			emailmsg['Subject'] = "Bad trip <(X.x)>" 
			
			s = smtplib.SMTP("smtp.test.com:587")
        		s.starttls()
        		s.login(user,password)
			s.sendmail(from_addr=user,to_addrs=text_addresses,msg=emailmsg.as_string()) 
