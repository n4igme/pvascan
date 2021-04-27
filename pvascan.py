#!/usr/bin/python

"""
Copyright (c) 2015, M Habib - STMIK Akakom, Yogyakarta
All rights reserved.
License : BSD-3-Clause
"""

try:
	from ConfigParser import ConfigParser
	import optparse, platform, csv, re, datetime
	import nmap, wget
except ImportError:
	print '[-]Python error, some library cannot imported.'
	print '| pvascan importing library : '
	print '|	python-nmap, wget, csv, re, platform, datetime,'
	print '|		ConfigParser, optparse'
	print '|__ Try to: pip install <python-library>\n'
	exit(0)

host	= ''
argu	= '-T4 -A'
cnfile	= 'config.ini'
dbfile	= ''
reslcan	= {}
osinf	= ''

def loadcnf():
	global dbfile
	config = ConfigParser()
	try:
		config.read(cnfile)
		dbfile = config.get('Configuration', 'database')
	except:
		print '[-]Missing configuration file,'
		print '|__ Please set configuration on file \''+cnfile+'\'\n'
		exit(0)

def editcnf(db):
	global dbfile
	config = ConfigParser()
	dbfile = db
	try:
		config.read(cnfile)
		config.remove_option('Configuration', 'database')
		config.set('Configuration', 'database', dbfile)
		with open(cnfile, 'wb') as conf:
			config.write(conf)
		print '[+]Configuration updated on file '+cnfile+'\n'
	except:
		print '[-]Error while updating configuration file!\n'
		exit(0)

def getdb():
	try:
		db = wget.download('https://raw.githubusercontent.com/offensive-'
		'security/exploit-database/master/files.csv') # Exploit-DB file.csv
		print ''
		editcnf(db)
	except:
		print '[-]Error while downloading file database!'
		exit(0)

def loadb():
	try:
		db = csv.DictReader(open(dbfile))
		return db
	except:
		print '[-]Vulnerability database is not selected.'
		print '|+]Downloading database file'
		getdb()

def vulnscan(banner):
	db = loadb()
	found = 0
	desc = {}
	url = {}
	if len(banner)>3:
		s = re.compile(banner, re.IGNORECASE)
		for row in db:
			c = s.findall(row['description'])
			if c:
				found+=1
				desc[found] = row['description']
				url[found] = row['id']				

	if found:
		print '| VULNERABLE DETECTED!'
		print '|- Description : '
		for x in desc.keys():
			print '|   ',x,''+desc[x]
			print '|    | For more information please visit url below'
			print '|    |_ https://www.exploit-db.com/exploits/'+url[x]+'/'
		print '|-',found,'exploits found,'			
		print '|__ Please contact the aplication\'s vendor to patch the vulnerable\n'

def osdetect():
	global osinf
	try:
		os = reslcan['scan'][host]['osclass']
		print 'OS detection accuracy '+os['accuracy']+'% \n'+\
			'Vendor : '+os['vendor']+', '+os['osfamily']+' '+os['osgen']
		osinf = os['osfamily']
	except:
		print 'For OS detection pvascan need root privillage'
		osinf = None
	return osinf

def portinf():
	porlis = reslcan['scan'][host]['tcp'].keys()
	oprt = reslcan['scan'][host]['tcp']
	print 'Discovered host ports [',len(porlis),']'
	for port in porlis:
		nserv	= oprt[port]['name']
		banner	= oprt[port]['product']+' '+oprt[port]['version']
		if (oprt[port]['state']=='open'):
			print '[+]PORT',port,'['+nserv+'] '+banner
			vulnscan(banner)
		else:
			print '[-]PORT',port,'[STATE:'+oprt[port]['state']+']'

def nmscan():
	global reslcan
	print 'From '+platform.uname()[0]+' '+platform.uname()[2]
	print 'On '+datetime.datetime.now().ctime()
	print 'Scanning for host '+host
	try:
		nm = nmap.PortScanner()
		reslcan = nm.scan(hosts=host, arguments=argu)
	except:
		print '[-]Error!!! Somethings wrong,'
		print '| (network trouble / nmap problem)'
		print '|__ Please try \'./pvascan.py -h\'\n'
		exit(0)

def optmenu():
	global host, argu
	parser = optparse.OptionParser('usage: ./pvascan.py -h')	
	parser.add_option('-H', '--host', dest='ip', type='string',
					help='IP of the target that will be scan\n'
						'for Vulnerability')		 
	parser.add_option('-p', '--port', dest='port', type='string', 
					help='Scan just the specific TCP port (1-65535)')
	parser.add_option('--getdb', action='store_true', dest='getdb',
					help='Download Exploit-DB files.csv as vulnerability\n'
						'database')
	parser.add_option('--dbs', dest='dbs', type='string',
					help='Select path where your database file is in\n'
						'with updating pvascan configuration file')

	(options, args) = parser.parse_args()
	host = options.ip
	if options.getdb:
		getdb()
		exit(0)
	if options.dbs:
		editcnf(options.dbs)
		exit(0)
	if (host == None):
		print parser.usage
		exit(0)
	if options.port:
		argu = '-p '+options.port+' -T4 -A' #'-p 1-65535 -T4 -A'
	loadb()	# checking vulnerability database

def main():
	loadcnf()
	optmenu()
	nmscan()
	try:
		ip = reslcan['scan'][host].keys()
		if ip:
			osdetect()
			portinf()
	except:
		print '[-] PVASCAN ERROR!!!'
		print '| problem while connect to target host'
		print '|__ Please try \'./pvascan.py -h\'\n'

if __name__ == '__main__':
	main()
