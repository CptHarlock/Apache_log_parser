#!/usr/bin/python3 -t
#This application searches for requested information in an apache log file, with "-n" it returns
#the number of unique IP addresses ,with "-tN" it lists the  top N IP addresses in the log file (where N is a number),
#with "-v" it returns the number of visits by an IP address, with "-L" it lists all of the requests made 
#by an IP address and with "-s" it shows the top IPs as potential hackers.
import getopt
import sys,re,os
import datetime,time
from datetime import datetime

def threats(inputfile): #This function searches for lines that include a 404 not found ,by excluding
	f = open(inputfile,"r")	#the ones with robots.txt and favicon.ico and creates a dicitonary with them.
	ips ={}
	for line in f:
		resu = re.search('HTTP\/1\.\d\" 404',line) 
		if resu:
			resu = re.search('robots.txt',line)
			if resu is None:
				resu = re.search('favicon.ico',line)
				if resu is None:
					ip = line.split()[0]
					if 6 < len(ip) <= 15:
						ips[ip] = ips.get(ip, 0) + 1
	return ips


def unique(inputfile): #This function finds the number of uniques IP addresses and
	f = open(inputfile,"r")#saves them in a dictionary
	ips ={}
	for line in f:
		ip = line.split()[0]
		if 6 < len(ip) <= 15:
			ips[ip] = ips.get(ip, 0) + 1
	return ips    

def headips(ips,n): #This function sorts out a dictionary by value and prints it.
	print ("%-20s   %10s" % ("IP", "REQUESTS"))
	for key, value in sorted(ips.items(),key=lambda x: x[1],reverse=True)[:int(n)]:
		print ("%-20s   %10d" % (key, value))

def visits(inputfile,ip):
	result=[]
	for line in open(inputfile,"r"):
		ipline = line.split()[0]
		if re.search(ip,ipline):
			result.append(line)
	return result

def timevisits(res): #This function compare times between requests to determinate the 
	times=[] #number of visits
	times2=[]
	pattern = re.compile('\d{2}[-/]\w{3}[-/]\d{4}[-:]\d{2}[-:]\d{2}')
	for i in res:#finds all timestamps
		match = re.findall('\d{2}[-/]\w{3}[-/]\d{4}[-:]\d{2}[-:]\d{2}[-:]\d{2}',i)
		if match:
			times.append(match)
	for i in times:
		i=str(i)
		i = i.strip('[]')
		i = i.strip('\'')
		j = datetime.strptime(i,'%d/%b/%Y:%H:%M:%S') #converts them in datetime in order to compare
		times2.append(j)
	resu = 1
	for i in range(0, len(times)-2,1):
		d = times2[i+1] - times2[i]
		if d.total_seconds() > 3600: #if between 2 requests an hour has passed then we count one visit
			resu= resu+1
	return resu

try: #Flag Handling
	opts, args = getopt.getopt(sys.argv[1:],"hl:nt:v:L:s:",["ifile="])
except getopt.GetoptError:
	print ("test.py -l <inputfile> -n -tN -r [IP] -v [IP] -tN")
	sys.exit(2)
for opt, arg in opts:
	if opt in "-h":
		print ('test.py -i <inputfile> -n -tN -r [IP] -v [IP] -tN')
		sys.exit()
	elif opt in "-l":
		inf = arg
	elif opt in "-n":
		print (len(unique(inf)))
	elif opt in "-t":
		n = arg
		ips = unique(inf)
		headips(ips,n)
	elif opt in "-L":
		v = arg
		res = visits(inf,v)
		for i in res:
			print (i)
	elif opt in "-v":
		v = arg
		result = visits(inf,v)
		print (timevisits(result))
	elif opt in "-s":
		n=arg
		ips = threats(inf)
		headips(ips,n)
	else:
		print( "unhandled option")

