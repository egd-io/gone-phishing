#!/usr/bin/env python
#
__author__ = 'Marcin Ulikowski'
__version__ = '20150920'
__email__ = 'marcin@ulikowski.pl'

import re
import sys
import socket
import signal
import argparse
try:
	import dns.resolver
	module_dnspython = True
except:
	module_dnspython = False
	pass
try:
	import GeoIP
	module_geoip = True
except:
	module_geoip = False
	pass
try:
	import whois
	module_whois = True
except:
	module_whois = False
	pass
try:
	import ssdeep
	module_ssdeep = True
except:
	module_ssdeep = False
try:
	import requests
	module_requests = True
except:
	module_requests = False
	pass

if sys.platform != 'win32' and sys.stdout.isatty():
	FG_RED = '\x1b[31m'
	FG_YELLOW = '\x1b[33m'
	FG_GREEN = '\x1b[32m'
	FG_MAGENTA = '\x1b[35m'
	FG_CYAN = '\x1b[36m'
	FG_BLUE = '\x1b[34m'
	FG_RESET = '\x1b[39m'

	ST_BRIGHT = '\x1b[1m'
	ST_RESET = '\x1b[0m'
else:
	FG_RED = ''
	FG_YELLOW = ''
	FG_GREEN = ''
	FG_MAGENTA = ''
	FG_CYAN = ''
	FG_BLUE = ''
	FG_RESET = ''

	ST_BRIGHT = ''
	ST_RESET = ''

def display(text):
	global args
	if not args.csv:
		sys.stdout.write(text)
		sys.stdout.flush()

def display_csv(text):
	global args
	if args.csv:
		sys.stdout.write(text)

def sigint_handler(signal, frame):
	sys.stdout.write(FG_RESET + ST_RESET)
	sys.exit(0)

# Internationalized domains not supported
def validate_domain(domain):
	if len(domain) > 255:
		return False
	if domain[-1] == '.':
		domain = domain[:-1]
	allowed = re.compile('\A([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\Z', re.IGNORECASE)
	return allowed.match(domain)

def http_banner(ip, vhost):
	try:
		http = socket.socket()
		http.settimeout(1)
		http.connect((ip, 80))
		http.send('HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % str(vhost))
		response = http.recv(1024)
		http.close()
	except:
		pass
	else:
		if '\r\n' in response: sep = '\r\n'
		else: sep = '\n'
		headers = response.split(sep)
		for field in headers:
			if field.startswith('Server: '):
				return field[8:]
		return 'HTTP %s' % headers[0].split(' ')[1]

def smtp_banner(mx):
	try:
		smtp = socket.socket()
		smtp.settimeout(1)
		smtp.connect((mx, 25))
		response = smtp.recv(1024)
		smtp.close()
	except:
		pass
	else:
		if '\r\n' in response: sep = '\r\n'
		else: sep = '\n'
		hello = response.split(sep)[0]
		if hello.startswith('220'):
			return hello[4:].strip()
		return hello[:40]

def bitsquatting(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]
	masks = [1, 2, 4, 8, 16, 32, 64, 128]

	for i in range(0, len(dom)):
		c = dom[i]
		for j in range(0, len(masks)):
			b = chr(ord(c) ^ masks[j])
			o = ord(b)
			if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
				out.append(dom[:i] + b + dom[i+1:] + '.' + tld)

	return out

def homoglyph(domain):
	glyphs = {
	'd':['b', 'cl'], 'm':['n', 'nn', 'rn'], 'l':['1', 'i'], 'o':['0'],
	'w':['vv'], 'n':['m'], 'b':['d'], 'i':['1', 'l'], 'g':['q'], 'q':['g']
	}
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for ws in range(0, len(dom)):
		for i in range(0, (len(dom)-ws)+1):
			win = dom[i:i+ws]

			j = 0
			while j < ws:
				c = win[j]
				if c in glyphs:
					for g in glyphs[c]:
						win = win[:j] + g + win[j+1:]

						if len(g) > 1:
							j += len(g) - 1
						out.append(dom[:i] + win + dom[i+ws:] + '.' + tld)

				j += 1

	return list(set(out))

def repetition(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for i in range(0, len(dom)):
		if dom[i].isalpha():
			out.append(dom[:i] + dom[i] + dom[i] + dom[i+1:] + '.' + tld)

	return list(set(out))

def transposition(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for i in range(0, len(dom)-1):
		if dom[i+1] != dom[i]:
			out.append(dom[:i] + dom[i+1] + dom[i] + dom[i+2:] + '.' + tld)

	return out

def replacement(domain):
	keys = {
	'1':'2q', '2':'3wq1', '3':'4ew2', '4':'5re3', '5':'6tr4', '6':'7yt5', '7':'8uy6', '8':'9iu7', '9':'0oi8', '0':'po9',
	'q':'12wa', 'w':'3esaq2', 'e':'4rdsw3', 'r':'5tfde4', 't':'6ygfr5', 'y':'7uhgt6', 'u':'8ijhy7', 'i':'9okju8', 'o':'0plki9', 'p':'lo0',
	'a':'qwsz', 's':'edxzaw', 'd':'rfcxse', 'f':'tgvcdr', 'g':'yhbvft', 'h':'ujnbgy', 'j':'ikmnhu', 'k':'olmji', 'l':'kop',
	'z':'asx', 'x':'zsdc', 'c':'xdfv', 'v':'cfgb', 'b':'vghn', 'n':'bhjm', 'm':'njk'
	}
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for i in range(0, len(dom)):
		if dom[i] in keys:
			for c in range(0, len(keys[dom[i]])):
				out.append(dom[:i] + keys[dom[i]][c] + dom[i+1:] + '.' + tld)

	return out

def omission(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for i in range(0, len(dom)):
		out.append(dom[:i] + dom[i+1:] + '.' + tld)

	return list(set(out))

def hyphenation(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for i in range(1, len(dom)):
		if dom[i] not in ['-', '.'] and dom[i-1] not in ['-', '.']:
			out.append(dom[:i] + '-' + dom[i:] + '.' + tld)

	return out

def subdomain(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for i in range(1, len(dom)):
		if dom[i] not in ['-', '.'] and dom[i-1] not in ['-', '.']:
			out.append(dom[:i] + '.' + dom[i:] + '.' + tld)

	return out

def insertion(domain):
	keys = {
	'1':'2q', '2':'3wq1', '3':'4ew2', '4':'5re3', '5':'6tr4', '6':'7yt5', '7':'8uy6', '8':'9iu7', '9':'0oi8', '0':'po9',
	'q':'12wa', 'w':'3esaq2', 'e':'4rdsw3', 'r':'5tfde4', 't':'6ygfr5', 'y':'7uhgt6', 'u':'8ijhy7', 'i':'9okju8', 'o':'0plki9', 'p':'lo0',
	'a':'qwsz', 's':'edxzaw', 'd':'rfcxse', 'f':'tgvcdr', 'g':'yhbvft', 'h':'ujnbgy', 'j':'ikmnhu', 'k':'olmji', 'l':'kop',
	'z':'asx', 'x':'zsdc', 'c':'xdfv', 'v':'cfgb', 'b':'vghn', 'n':'bhjm', 'm':'njk'
	}
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for i in range(1, len(dom)-1):
		if dom[i] in keys:
			for c in range(0, len(keys[dom[i]])):
				out.append(dom[:i] + keys[dom[i]][c] + dom[i] + dom[i+1:] + '.' + tld)
				out.append(dom[:i] + dom[i] + keys[dom[i]][c] + dom[i+1:] + '.' + tld)

	return out

def fuzz_domain(domain):
	domains = []

	domains.append({ 'type':'Original*', 'domain':domain })

	for i in bitsquatting(domain):
		domains.append({ 'type':'Bitsquatting', 'domain':i })
	for i in homoglyph(domain):
		domains.append({ 'type':'Homoglyph', 'domain':i })
	for i in repetition(domain):
		domains.append({ 'type':'Repetition', 'domain':i })
	for i in transposition(domain):
		domains.append({ 'type':'Transposition', 'domain':i })
	for i in replacement(domain):
		domains.append({ 'type':'Replacement', 'domain':i })
	for i in omission(domain):
		domains.append({ 'type':'Omission', 'domain':i })
	for i in hyphenation(domain):
		domains.append({ 'type':'Hyphenation', 'domain':i })
	for i in insertion(domain):
		domains.append({ 'type':'Insertion', 'domain':i })
	for i in subdomain(domain):
		domains.append({ 'type':'Subdomain', 'domain':i })

	domains[:] = [x for x in domains if validate_domain(x['domain'])]

	return domains

def main():
	parser = argparse.ArgumentParser(
	description='''Find similar-looking domains that adversaries can use to attack you.  
	Can detect fraud, phishing attacks and corporate espionage. Useful as an additional 
	source of targeted threat intelligence.''',
	epilog='''Questions? Complaints? You can reach the author at <marcin@ulikowski.pl>'''
	)

	parser.add_argument('domain', help='domain name to check')
	parser.add_argument('-c', '--csv', action='store_true', help='print output in CSV format')
	parser.add_argument('-r', '--registered', action='store_true', help='show only registered domain names')
	parser.add_argument('-w', '--whois', action='store_true', help='perform lookup for WHOIS creation/modification date (slow)')
	parser.add_argument('-g', '--geoip', action='store_true', help='perform lookup for GeoIP location')
	parser.add_argument('-b', '--banners', action='store_true', help='determine HTTP and SMTP service banners')
	parser.add_argument('-s', '--ssdeep', action='store_true', help='fetch web pages and compare fuzzy hashes to evaluate similarity')

	if len(sys.argv) < 2:
		parser.print_help()
		sys.exit(0)

	global args
	args = parser.parse_args()

	if not validate_domain(args.domain):
		sys.stderr.write('ERROR: invalid domain name!\n')
		sys.exit(-1)

	domains = fuzz_domain(args.domain.lower())

	if not module_dnspython:
		sys.stderr.write('NOTICE: Missing module: dnspython - DNS features limited!\n')
	if not module_geoip and args.geoip:
		sys.stderr.write('NOTICE: Missing module: GeoIP - geographical location not available!\n')
	if not module_whois and args.whois:
		sys.stderr.write('NOTICE: Missing module: whois - database not accessible!\n')
	if not module_ssdeep and args.ssdeep:
		sys.stderr.write('NOTICE: Missing module: ssdeep - fuzzy hashes not available!\n')
	if not module_requests and args.ssdeep:
		sys.stderr.write('NOTICE: Missing module: Requests - web page downloads not possible!\n')

	if args.ssdeep and module_ssdeep and module_requests:
		display('Fetching web page from: http://' + args.domain.lower() + '/ [following redirects] ... ')
		try:
			req = requests.get('http://' + args.domain.lower(), timeout=2)
		except:
			display('Failed!\n')
			args.ssdeep = False			
			pass
		else:
			display('%d %s (%d bytes)\n' % (req.status_code, req.reason, len(req.text)))
			orig_domain_ssdeep = ssdeep.hash(req.text)


	signal.signal(signal.SIGINT, sigint_handler)

	total_hits = 0

	for i in range(0, len(domains)):
		if module_dnspython:
			pass
		else:
			pass

		if module_whois and args.whois:
			pass

		if module_geoip and args.geoip:
			pass

		if args.banners:
			pass

		if module_ssdeep and module_requests and args.ssdeep:
			if 'a' in domains[i]:
				try:
					req = requests.get('http://' + domains[i]['domain'], timeout=1)
					fuzz_domain_ssdeep = ssdeep.hash(req.text)
				except:
					pass
				else:
					domains[i]['ssdeep'] = ssdeep.compare(orig_domain_ssdeep, fuzz_domain_ssdeep)


	display_csv('Generator,Domain,A,AAAA,MX,NS,Country,Created,Updated,SSDEEP\n')

	for i in domains:
		info = ''

		#if 'a' in i:
		#	info += i['a']
	#		if 'country' in i:
#				info += FG_CYAN + '/' + i['country'] + FG_RESET
#			if 'banner-http' in i:
#				info += ' %sHTTP:%s"%s"%s' % (FG_GREEN, FG_CYAN, i['banner-http'], FG_RESET)
#		elif 'ns' in i:
#			info += '%sNS:%s%s%s' % (FG_GREEN, FG_CYAN, i['ns'], FG_RESET)

#		if 'aaaa' in i:
#			info += ' ' + i['aaaa']

#		if 'mx' in i:
#			info += ' %sMX:%s%s%s' % (FG_GREEN, FG_CYAN, i['mx'], FG_RESET)
#			if 'banner-smtp' in i:
#				info += ' %sSMTP:%s"%s"%s' % (FG_GREEN, FG_CYAN, i['banner-smtp'], FG_RESET)
#
#		if 'created' in i and 'updated' in i and i['created'] == i['updated']:
#			info += ' %sCreated/Updated:%s%s%s' % (FG_GREEN, FG_CYAN, i['created'], FG_RESET)
#		else:
#			if 'created' in i:
#				info += ' %sCreated:%s%s%s' % (FG_GREEN, FG_CYAN, i['created'], FG_RESET)
#			if 'updated' in i:
#				info += ' %sUpdated:%s%s%s' % (FG_GREEN, FG_CYAN, i['updated'], FG_RESET)

#		if 'ssdeep' in i:
#			if i['ssdeep'] > 0:
#				info += ' %sSSDEEP:%s%d%%%s' % (FG_GREEN, FG_CYAN, i['ssdeep'], FG_RESET)

#		if not info:
#			info = '-'

		if (args.registered and info != '-') or not args.registered:
			display('%s%-15s%s %-15s %s\n' % (FG_BLUE, i['type'], FG_RESET, i['domain'], info))
			display_csv(
			'%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' % (i.get('type'), i.get('domain'), i.get('a', ''),
			i.get('aaaa', ''), i.get('mx', ''), i.get('ns', ''), i.get('country', ''),
			i.get('created', ''), i.get('updated', ''), str(i.get('ssdeep', '')))
			)

	display(FG_RESET + ST_RESET)

	return 0

if __name__ == '__main__':
	main()
