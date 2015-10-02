#!/usr/bin/python
from __future__ import print_function
import socket
import sys

domain = sys.argv[1].split('_')[0]
name = domain.split('.')[0]
result = open(domain+'_rdns','w')
with open(domain+'_hostlookup') as f:
	for line in f:
		if "NXDOMAIN" in line:
			pass
		else:
			try:
				host = line.strip().split()[0]
				addr = line.strip().split()[2]
				perm_type = line.strip().split()[1]
				rdns = socket.gethostbyaddr(addr)
				rdns = rdns[0]
				is_match = True
				if name in rdns:
					print (str(host)+" "+str(addr)+" "+str(perm_type)+" "+str(rdns)+" "+str(is_match))
					print (str(host)+" "+str(addr)+" "+str(perm_type)+" "+str(rdns)+" "+str(is_match), file=result)
				else:
					is_match = False
					print (str(host)+" "+str(addr)+" "+str(perm_type)+" "+str(rdns)+" "+str(is_match))
					print (str(host)+" "+str(addr)+" "+str(perm_type)+" "+str(rdns)+" "+str(is_match), file=result)
			except:
				pass
f.close()