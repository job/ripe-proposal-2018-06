#!/usr/bin/env python3
# This file is part of the RIPE Policy Proposal 2018-06 Analyser
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

from ipaddress import ip_network


def validation_state(tree, prefix, origin):
    """
    tree is a radix.Radix() object
    prefix is the to-be-tested prefix
    origin is the origin asn to be used in the test
    """

    if not tree.search_best(prefix):
        return {"state": "unknown"}

    p = ip_network(prefix)
    s = tree.search_worst(prefix).prefix
    vrps = tree.search_covered(s)
    passback_roas = []
    for vrp in vrps:
        r = ip_network(vrp.prefix)
        if not (p.network_address >= r.network_address and p.broadcast_address <= r.broadcast_address):
            continue

        for roa in vrp.data["roas"]:
            passback_roas.append({"roa": vrp.prefix, "maxlen": roa['maxlen'],
                                  "origin": roa['origin'],
                                  "ta": roa['ta']})

            if vrp.prefixlen <= p.prefixlen <= roa['maxlen']:
                if origin == roa['origin']:
                    return {"state": "valid", "roa": {"roa": vrp.prefix,
                                                      "maxlen": roa['maxlen'],
                                                      "origin": roa['origin'],
                                                      "ta": roa['ta']}}
    return {"state": "invalid", "roas": passback_roas}
