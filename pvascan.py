#!/usr/bin/python

"""
Copyright (c) 2015, M Habib - STMIK Akakom, Yogyakarta
All rights reserved.
License: BSD-3-Clause
"""

try:
    from configparser import ConfigParser  # Use configparser in Python 3
    import optparse
    import platform
    import csv
    import re
    import datetime
    import nmap
    import wget
except ImportError:
    print('[-] Python error, some library cannot be imported.')
    print('| pvascan importing library: ')
    print('|    python-nmap, wget, csv, re, platform, datetime,')
    print('|    configparser, optparse')
    print('|__ Try to: pip install <python-library>\n')
    exit(0)

host = ''
argu = '-T4 -A'
cnfile = 'config.ini'
dbfile = ''
reslcan = {}
osinf = ''


def loadcnf():
    global dbfile
    config = ConfigParser()
    try:
        config.read(cnfile)
        dbfile = config.get('Configuration', 'database')
    except Exception as e:
        print('[-] Missing configuration file,')
        print('|__ Please set configuration on file \'' + cnfile + '\'\n')
        exit(0)


def editcnf(db):
    global dbfile
    config = ConfigParser()
    dbfile = db
    try:
        config.read(cnfile)
        config.remove_option('Configuration', 'database')
        config.set('Configuration', 'database', dbfile)
        with open(cnfile, 'w') as conf:  # Use 'w' mode for writing in Python 3
            config.write(conf)
        print('[+] Configuration updated on file ' + cnfile + '\n')
    except Exception as e:
        print('[-] Error while updating configuration file!\n')
        exit(0)


def getdb():
    try:
        db = wget.download('https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv')
        print('')
        editcnf(db)
    except Exception as e:
        print('[-] Error while downloading file database!')
        exit(0)


def loadb():
    try:
        db = csv.DictReader(open(dbfile))
        return db
    except Exception as e:
        print('[-] Vulnerability database is not selected.')
        print('|+ Downloading database file')
        getdb()


def vulnscan(banner):
    db = loadb()
    found = 0
    desc = {}
    url = {}
    if len(banner) > 3:
        s = re.compile(banner, re.IGNORECASE)
        for row in db:
            c = s.findall(row['description'])
            if c:
                found += 1
                desc[found] = row['description']
                url[found] = row['id']

    if found:
        print('| VULNERABLE DETECTED!')
        print('|- Description: ')
        for x in desc.keys():
            print('|   ', x, '' + desc[x])
            print('|    | For more information please visit the URL below')
            print('|    |_ https://www.exploit-db.com/exploits/' + url[x] + '/')
        print('|-', found, 'exploits found,')
        print('|__ Please contact the application\'s vendor to patch the vulnerability\n')


def osdetect():
    global osinf
    try:
        os = reslcan['scan'][host]['osclass']
        print('OS detection accuracy ' + os['accuracy'] + '% \n' +
              'Vendor: ' + os['vendor'] + ', ' + os['osfamily'] + ' ' + os['osgen'])
        osinf = os['osfamily']
    except Exception as e:
        print('For OS detection pvascan needs root privilege')
        osinf = None
    return osinf


def portinf():
    porlis = reslcan['scan'][host]['tcp'].keys()
    oprt = reslcan['scan'][host]['tcp']
    print('Discovered host ports [', len(porlis), ']')
    for port in porlis:
        nserv = oprt[port]['name']
        banner = oprt[port]['product'] + ' ' + oprt[port]['version']
        if oprt[port]['state'] == 'open':
            print('[+] PORT', port, '[' + nserv + '] ' + banner)
            vulnscan(banner)
        else:
            print('[-] PORT', port, '[STATE:' + oprt[port]['state'] + ']')


def nmscan():
    global reslcan
    print('From ' + platform.uname()[0] + ' ' + platform.uname()[2])
    print('On ' + datetime.datetime.now().ctime())
    print('Scanning for host ' + host)
    try:
        nm = nmap.PortScanner()
        reslcan = nm.scan(hosts=host, arguments=argu)
    except Exception as e:
        print('[-] Error!!! Something\'s wrong,')
        print('| (network trouble / nmap problem)')
        print('|__ Please try \'./pvascan.py -h\'\n')
        exit(0)


def optmenu():
    global host, argu
    parser = optparse.OptionParser('usage: ./pvascan.py -h')
    parser.add_option('-H', '--host', dest='ip', type='string',
                      help='IP of the target that will be scanned\n'
                           'for Vulnerability')
    parser.add_option('-p', '--port', dest='port', type='string',
                      help='Scan just the specific TCP port (1-65535)')
    parser.add_option('--getdb', action='store_true', dest='getdb',
                      help='Download Exploit-DB files.csv as vulnerability\n'
                           'database')
    parser.add_option('--dbs', dest='dbs', type='string',
                      help='Select the path where your database file is in\n'
                           'with updating pvascan configuration file')

    (options, args) = parser.parse_args()
    host = options.ip
    if options.getdb:
        getdb()
        exit(0)
    if options.dbs:
        editcnf(options.dbs)
        exit(0)
    if host is None:
        print(parser.usage)
        exit(0)
    if options.port:
        argu = '-p ' + options.port + ' -T4 -A'
    loadb()  # checking vulnerability database


def main():
    loadcnf()
    optmenu()
    nmscan()
    try:
        ip = reslcan['scan'][host].keys()
        if ip:
            osdetect()
            portinf()
    except Exception as e:
        print('[-] PVASCAN ERROR!!!')
        print('| Problem while connecting to the target host')
        print('|__ Please try \'./pvascan.py -h\'\n')


if __name__ == '__main__':
    main()
