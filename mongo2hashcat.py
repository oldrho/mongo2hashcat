#!/usr/bin/env python3

import argparse
import base64
import bson

def decode(path, cred_type, hc_type):
    data = bson.decode_all(open(path, 'rb').read())

    for user in data:
        cred = user['credentials'][cred_type]

        out = [
            '$mongodb-scram$',
            str(hc_type),
            base64.b64encode(user['_id'].encode('utf-8')).decode(),
            str(cred['iterationCount']),
            cred['salt'],
            cred['serverKey']
            ]

        yield '*'.join(out)

def main():
    parser = argparse.ArgumentParser(description='Parse a MongoDB system.users.bson file and output the hashes in hashcat format\n\n\tSCRAM-SHA-1 = hash mode 24100\n\tSCRAM-SHA-256 = hash mode 24200', formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('path', help='Path to system.users.bson file')
    parser.add_argument('-0', '--sha1', action='store_true', help='Output SCRAM-SHA-1 hashes')
    parser.add_argument('-1', '--sha256', action='store_true', help='Output SCRAM-SHA-256 hashes')

    args = parser.parse_args()

    if args.sha1:
        for h in decode(args.path, 'SCRAM-SHA-1', 0):
            print(h)
    if args.sha256:
        for h in decode(args.path, 'SCRAM-SHA-256', 1):
            print(h)

if __name__ == '__main__':
    main()