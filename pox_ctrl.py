import random
from bitarray import bitarray

from pox.core import core
from pox.lib.revent import *
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of

from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

RULE_DURATION_SEC = 30.0
ASSIGNMENT_DURATION_SEC = 15.0
STATS_PERIOD_SEC = 10.0
LOAD_BALANCE_NUM = 2 

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

    def __contains__(self, ipaddr):
        return any([ipaddr in prefix for prefix in self.prefixes])

class MTDIPPrefix(object):
    def __init__(self, pattern):
        parts = pattern.split("/")
        if len(parts) != 2:
            raise TypeError
        
        self.masklen = int(parts[1])
        self.pattern = IPAddr(parts[0])

        bits = bitarray()
        bits.frombytes(self.pattern.toRaw())
        self.prefix = bits[:self.masklen]

    def rand_ip_addr(self):
        rbitslen = 32 - self.masklen
        rbits = bin(random.getrandbits(rbitslen))[2:]
        return IPAddr((self.prefix + rbits.zfill(rbitslen)).tobytes())

    def __repr__(self):
        return "%s/%d" % (repr(self.pattern), self.masklen)

    def __contains__(self, ipaddr):
        if not isinstance(ipaddr, IPAddr):
            raise TypeError
        
        ipaddr_bits = bitarray()
        ipaddr_bits.frombytes(ipaddr.toRaw())

        return self.prefix == ipaddr_bits[:self.masklen]

class MTDController(EventMixin):
    """TODO:
    *) When we trigger a reassignment, maybe we can use 
       ofp_stats_request to find out a suspect and drop him/her out

    *) a test script (similar as submit.py) to automatic testing
    """
    def __init__(self, fixed, hosts, networks):
        super(MTDController, self).__init__()

        self.mapping = {}
        self.mapping_rev = {}
        self.fixed = fixed
        self.hosts = hosts
        self.prefixes = MTDIPPrefixes(networks)
        
        self.flush_assignments()

        self.listenTo(core.openflow)
        log.info("Enabling MTD Module...")

        Timer(STATS_PERIOD_SEC, self.start_stats_collection, recurring=True)
        Timer(ASSIGNMENT_DURATION_SEC, self.flush_assignments, recurring=True)
    
    def _next_ip_addr(self, used):
        ip_addr = self.prefixes.rand_ip_addr()
        while ip_addr in used:
            ip_addr = self.prefixed.rand_ip_addr()
        return ip_addr

    def flush_assignments(self):
        used_ipaddrs = set(self.mapping.keys())
        next_mapping = {}
        for host in self.hosts:
            new_ip_addr = self._next_ip_addr(used_ipaddrs)
            next_mapping[new_ip_addr] = [host, 0]
            used_ipaddrs.add(new_ip_addr)

        self.mapping = next_mapping

        print "Current mapping: ", self.mapping

    def flush_assignment(self, vip):
        used_ipaddrs = set(self.mapping.keys())
        host, _ = self.mapping[vip]
        new_ip_addr = self._next_ip_addr(used_ipaddrs)
        del self.mapping[vip]
        self.mapping[new_ip_addr] = [host, 0]

        print "Host %s switched from %s to %s" % (host, vip, new_ip_addr)

    def start_stats_collection(self):
        for conn in core.openflow.connections:
            conn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def _handle_FlowStatsReceived(self, event):
        def compute_avg_rate(stat):
            if stat.duration_sec == 0:
                return 0
            return (float(stat.packet_count) / stat.duration_sec)

        def drop(from_rule, duration=RULE_DURATION_SEC):
            if not instance(duration, tuple):
                duration = (duration, duration)
            msg = of.ofp_flow_mod()
            msg.match = from_rule.match
            msg.priority = 1
            msg.idle_timeout = duration[0]
            msg.hard_timeout = duration[1]
            event.connection.send(msg)

        flow_stats = []
        for f in event.stats:
            if not f.actions or not f.match.nw_dst in self.prefixes:
                continue

            flow_stats.append(f)

        rates = map(compute_avg_rate, flow_stats)
        flow_stats = zip(rates, flow_stats)

        print "Debug:", flow_stats

        # TODO: how to find out attackers?
        # compute standard derivation d and set threshold to avg + 3*d?
        # and a predefined threshold to avoid making erroneous judgement?
        
        # Notice: I use # of pkt to compute avg insead of bytes
        # I thought how many requests does a user ask is more accurate 
        # than how much traffic does a user send.
        # Maybe I am wrong....

        # Once we find attacker(s), use drop method above to insert a 
        # higher priority(1) entry to block them out

    def _handle_PacketIn(self, event):
        packet = event.parsed
        ip = packet.find('ipv4')

        def flood():
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        def drop(duration=(RULE_DURATION_SEC, RULE_DURATION_SEC)):
            if not isinstance(duration, tuple):
                duration = (duration, duration)
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet)
            msg.idle_timeout = duration[0]
            msg.hard_timeout = duration[1]
            msg.buffer_id = event.ofp.buffer_id
            event.connection.send(msg)

        def fwd(target, duration=(RULE_DURATION_SEC, RULE_DURATION_SEC)):
            if not isinstance(duration, tuple):
                duration = (duration, duration)
            # srcip -> dstip
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet)
            msg.idle_timeout = duration[0]
            msg.hard_timeout = duration[1]
            msg.actions.append(of.ofp_action_nw_addr.set_dst(target))
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)

            # target -> srcip
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(dl_type=0x800, nw_src=target, nw_dst=ip.srcip)
            msg.idle_timeout = duration[0]
            msg.hard_timeout = duration[1]
            msg.actions.append(of.ofp_action_nw_addr.set_src(ip.dstip))
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)

            # send this pkt
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_nw_addr.set_dst(target))
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        if ip is None or ip.dstip in self.fixed:
            return flood()
        
        if ip.dstip in self.mapping:
            target = self.mapping[ip.dstip]
            print "Making a connection between %s and %s(%s)" \
                    % (ip.srcip, ip.dstip, target[0])

            target[1] += 1
            if target[1] >= LOAD_BALANCE_NUM:
                self.flush_assignment(ip.dstip)
            
            fwd(target[0])
        else:
            drop()

def launch():
    fixed = [IPAddr('172.0.0.1'), IPAddr('172.0.0.11')]
    hosts = [IPAddr('100.0.0.7')]
    networks = ['140.0.0.0/16',
                '150.0.0.0/8',
                '160.0.0.0/8',
                '170.0.0.0/16']

    core.registerNew(MTDController, fixed, hosts, networks)

