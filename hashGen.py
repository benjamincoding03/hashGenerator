#!/usr/bin/python
import sys, argparse, hashlib

def main():
	try:
		p = argparse.ArgumentParser(description='Hash generator')
		req = p.add_argument_group('required arguments')
		req.add_argument('-s', '--string', dest='string', help='String to encrypt')
		req.add_argument('-t', '--type', dest='type', help='Hash type (sha256, sha1, md5)')
		args = p.parse_args()
		# parses arguments

		string = args.string
		type = args.type.lower()

		if type == 'sha256':
			obj = hashlib.sha256(string)

		elif type == 'sha1':
			obj = hashlib.sha1(string)

		elif type == 'md5':
			obj = hashlib.md5(string)

		else:
			print 'Invalid hash type'
			sys.exit()

		hash = obj.hexdigest()
		print hash
		sys.exit()

	except AttributeError:
		print 'Invalid argument'
		sys.exit()

	except KeyboardInterrupt:
		sys.exit()

main()
