#!/usr/bin/env python3
# RIPE Policy Proposal 2018-06 Analyser
#
# Copyright (C) 2018-2019 Job Snijders <job@ntt.net>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from collections import OrderedDict
from ipaddress import ip_network
from operator import itemgetter
from .rpkitools import validation_state

import argparse
import zlib
import json
import os
import pprint
import radix
import requests
import ripe_proposal_2018_06
import sys


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-c', dest='cache',
                        default="https://rpki.gin.ntt.net/api/export.json",
                        type=str,
                        help="""Location of the RPKI Cache in JSON format
(default: https://rpki.gin.ntt.net/api/export.json)""")

    parser.add_argument('-i', dest='irr',
                        default="default",
                        type=str,
                        help="""Location of the IRR database
(default: https://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route.gz)""")

    parser.add_argument('--afi', dest='afi', type=str, required=False,

                        default='mixed', help="""[ ipv4 | ipv6 | mixed ]
(default: mixed""")

    parser.add_argument('-a', dest='asns', type=str, required=False,
                        default=None, help='[ ASNs ] comma separated')

    parser.add_argument('-p', dest='prefix', type=str, default=None,
                        help='Prefix')

    parser.add_argument('-s', dest='state', type=str, default="invalid",
                        help="""RPKI Origin Validation State [ valid | invalid | unknown | all ]
(default: invalid)""")

    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s ' + ripe_proposal_2018_06.__version__)

    args = parser.parse_args()

    if args.asns:
        asns = list(map(int, args.asns.split(',')))
    else:
        asns = None

    if args.afi not in ["ipv4", "ipv6", "mixed"]:
        print("ERROR: afi must be 'ipv4', 'ipv6' or 'mixed'")
        sys.exit(2)

    if 'http' in args.cache:
        r = requests.get(args.cache, headers={'Accept': 'text/json'})
        validator_export = r.json()
    else:
        validator_export = json.load(open(args.cache, "r"))

    if args.afi == "ipv4" and args.irr == "default":
        irr_url = "https://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route.gz"
    elif args.afi == "ipv4" and args.irr == "default":
        irr_url = "https://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route6.gz"
    else:
        irr_url = args.irr

    if 'http' in irr_url:
        r = requests.get(irr_url).content
    else:
        r = open(args.irr, "rb").read()

    if args.irr[-3:] == ".gz":
        irr_data = zlib.decompress(r, 16 + zlib.MAX_WBITS)
    else:
        irr_data = r

    irr_raw = []
    for line in irr_data.splitlines():
        line = line.decode('ascii')
        if line.startswith("route:") or line.startswith("route6:"):
            irr_raw.append(line.split()[1])
        if line.startswith("origin:"):
            irr_raw.append(int(line.split()[1][2:]))
    irr = [(irr_raw[i], irr_raw[i+1]) for i in range(0, len(irr_raw), 2)]

    tree = create_vrp_index(args.afi, validator_export, asns)

    for route in irr:
        res = validation_state(tree, *route)

        if res['state'] == "invalid" and args.state in ["invalid", "all"]:
            print("INVALID! RIPE-NONAUTH route object \"%s AS%s\" conflicts \
with these ROAs:" % route)
            for roa in res['roas']:
                print("    ROA: %s, MaxLength: %s, Origin AS%s (%s)"
                      % (roa['roa'], roa['maxlen'], roa['origin'], roa['ta']))

        if res['state'] == "valid" and args.state in ["valid", "all"]:
            print("OK: RIPE-NONAUTH route object \"%s AS%s\" matches ROA %s \
MaxLength %s Origin AS%s (%s)" % (*route, roa['roa'], roa['maxlen'],
                                  roa['origin'], roa['ta']))

        if args.state in ["unknown", "all"]:
            print("UNKNOWN: RIPE-NONAUTH route object \"%s AS%s\" is not \
covered by any ROAs" % route)


def create_vrp_index(afi, export, asns):
    """
    :param afi:     which address family to filter for
    :param export:  the JSON blob with all ROAs
    """

    roa_list = []
    tree = radix.Radix()

    """ each roa tuple has these fields:
        asn, prefix, maxLength, ta
    """

    for roa in export['roas']:
        prefix_obj = ip_network(roa['prefix'])
        if afi == "ipv4":
            if prefix_obj.version == 6:
                continue
        elif afi == "ipv6":
            if prefix_obj.version == 4:
                continue

        try:
            asn = int(roa['asn'].replace("AS", ""))
            if not 0 <= asn < 4294967296:
                raise ValueError
        except ValueError:
            print("ERROR: ASN malformed", file=sys.stderr)
            print(pprint.pformat(roa, indent=4), file=sys.stderr)
            continue

        prefix = str(prefix_obj)
        prefixlen = prefix_obj.prefixlen
        maxlength = int(roa['maxLength'])
        ta = roa['ta']

        if asns:
            if asn in asns:
                roa_list.append((prefix, prefixlen, maxlength, asn, ta))
        else:
            roa_list.append((prefix, prefixlen, maxlength, asn, ta))

    for roa in set(roa_list):
        if not asns or int(roa[3]) in asns:
            rnode = tree.search_exact(roa[0])
            if not rnode:
                rnode = tree.add(roa[0])
                rnode.data["roas"] = [{'maxlen': roa[2], 'origin': roa[3],
                                       'ta': roa[4]}]
            else:
                rnode.data["roas"].append({'maxlen': roa[2], 'origin': roa[3],
                                           'ta': roa[4]})

    return tree

if __name__ == "__main__":
    main()
