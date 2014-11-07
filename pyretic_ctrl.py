from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

import random
from collections import namedtuple

MTDConnection = namedtuple('MTDConnection', ['srcip', 'dstip'])

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

        self.connections = {}

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

        print "Current mapping: ", self.mapping

        self.query = packets(1, ['srcip', 'dstip'])
        self.query.register_callback(self.establish_conn)

    def update_policy(self):
        # TODO: build policy from connections
        policies = [self.query]
        for k, v in self.connections.iteritems():
            policies.append(match(srcip=k.srcip, dstip=k.dstip) >> modify(dstip=v) >> flood())
            policies.append(match(srcip=v, dstip=k.srcip) >> modify(srcip=k.dstip) >> flood())

        self.policy = union(policies)

        print "Policy updated..."

    def establish_conn(self, pkt):
        # TODO: a load balancing mechanism to trigger flush assignment
        # add conn to connections
        # update policy if changed

        print "Establishing..."
        key = MTDConnection(pkt['srcip'], pkt['dstip'])
        conn = self.connections.get(MTDConnection(key, None))
        if conn is None and pkt['dstip'] in self.mapping:
            real_dstip = self.mapping[pkt['dstip']]
            self.connections[key] = real_dstip
            self.update_policy()

        return pkt

    # TODO: we need a timeout mechanism(Threading.Timer?) to clean up connections
    # TODO: we need a timeout mechanism to flush assignments
    # TODO: we need a counting mechanism to flush an assignment

def main():
    hosts = [IPAddr('100.0.0.7')]
    networks = ['140.0.0.0/16',
                '150.0.0.0/8',
                '160.0.0.0/8',
                '170.0.0.0/8']

    return if_(match(dstip=IPAddr('172.0.0.1')) | match(dstip=IPAddr('172.0.0.11')),
        flood(), 
        MTDController(hosts, networks))

