#!/usr/bin/python
from __future__ import print_function
import socket
import sys

domain = sys.argv[1]
result = open(domain+'_hostlookup','w')
with open(domain) as f:
	for line in f:
		if "Original" in line:
			pass
		else:
			try:
				hostname = line.strip().split()[1]
				perm_type = line.strip().split()[0]
				ip = socket.gethostbyname(hostname)
				if ip == "92.242.140.21":
					print (str(hostname)+" "+str(perm_type)+" "+"NXDOMAIN")
					print (str(hostname)+" "+str(perm_type)+" "+"NXDOMAIN", file=result)
				else:
					print (str(hostname)+" "+str(perm_type)+" "+str(ip))
					print (str(hostname)+" "+str(perm_type)+" "+str(ip), file=result)
			except:
				pass
f.close()