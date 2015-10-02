## Written by Brian Warehime (@brian_warehime, nullsecure.org) and Ethan Dodge (@__eth0, dodgesec.com)

#!/usr/bin/python
from __future__ import print_function
import socket
import sys
from ipwhois import IPWhois

domain = sys.argv[1].split('_')[0]
name = domain.split('.')[0]
result = open(domain+'_whois','w')
with open(domain+'_hostlookup') as f:
	for line in f:
		if "NXDOMAIN" in line:
			pass
		else:
			try:
				host = line.strip().split()[0]
				addr = line.strip().split()[2]
				perm_type = line.strip().split()[1]
				whois = IPWhois(addr)
				whois = whois.lookup()
				whois = whois['nets']
				int = len(whois)
				whois = whois[int - 1]['description']
				who = str.lower(whois)
				is_match = True
				if name in who:
					print (str(host)+" "+str(addr)+" "+str(perm_type)+" "+str(whois)+" "+str(is_match))
					print (str(host)+" "+str(addr)+" "+str(perm_type)+" "+str(whois)+" "+str(is_match), file=result)
				else:
					is_match = False
					print (str(host)+" "+str(addr)+" "+str(perm_type)+" "+str(whois)+" "+str(is_match))
					print (str(host)+" "+str(addr)+" "+str(perm_type)+" "+str(whois)+" "+str(is_match), file=result)
			except:
				pass
f.close()