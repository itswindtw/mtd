from pyretic.lib.corelib import *
from pyretic.lib.std import *

import random
from collections import NamedTuple

class MTDConnection(object):
    def __init__(self, srcip, dstip, target):
        self.srcip = srcip
        self.dstip = dstip
        self.target = target
        self.timeout = 2

class MTDIPPrefixes(object):
    def __init__(self, prefixes):
        self.prefixes = map(MTDIPPrefix, prefixes)
        self.total_masklen = reduce(
                lambda acc, x: acc+x.masklen, self.prefixes, 0)

    def rand_ip_addr(self):
        prefix = self.rand_ip_prefix()
        return prefix.rand_ip_addr()
    
    def rand_ip_prefix(self):
        draw = random.randint(1, self.total_masklen)
        for p in self.prefixes:
            draw -= p.masklen
            if draw <= 0:
                return p

class MTDIPPrefix(IPPrefix):
    def rand_ip_addr(self):
        rbitslen = 32 - self.masklen
        rbits = bin(random.getrandbits(rbitslen))[2:]
        return IPAddr((self.prefix + rbits.zfill(rbitslen)).tobytes())

class MTDController(DynamicPolicy):
    def __init__(self, hosts, prefixes):
        super(MTDController, self).__init__()

        self.mapping = {}
        self.hosts = hosts
        self.prefixes = MTDIPPrefixes(prefixes)

        self.connections = [] # FIXME: data structure

        self.flush_all_assignments()
        self.update_policy()
    
    def flush_all_assignments(self):
        def next_ip_addr(used):
            ip_addr = self.prefixes.rand_ip_addr()
            while ip_addr in used:
                ip_addr = self.prefixes.rand_ip_addr()
            return ip_addr

        used_ipaddrs = set(self.mapping.keys())
        next_mapping = {}
        for host in self.hosts:
            new_ip_addr = next_ip_addr(used_ipaddrs)
            next_mapping[new_ip_addr] = host
            
        self.mapping = next_mapping

        self.query = packets(1, ['srcip', 'dstip'])
        self.query.register_callback(self.establish_conn)

    def update_policy(self):
        # TODO: build policy from connections
        self.policy = flood

    def establish_conn(self, pkt):
        # TODO
        # add conn to connections
        # update policy if changed
        pass

    # TODO: we need a timeout mechanism(Threading.Timer?) to clean up connections
    # TODO: we need a timeout mechanism to flush assignments
    # TODO: we need a counting mechanism to flush an assignment

def main():
    hosts = [IPAddr('100.0.0.7')]
    networks = ['140.0.0.0/16',
                '150.0.0.0/8',
                '160.0.0.0/8',
                '170.0.0.0/8']

    # TODO: just flood hosts connection (172.)
    return MTDController(networks)

