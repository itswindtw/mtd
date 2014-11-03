#!/usr/bin/python
"""MTD in SDN
This file create a topology to test MTD controller

Ref: SDX mininet script
Author: Meng-Hsin Tung
"""

import os, sys, atexit
from mininext.topo import Topo
from mininext.services.quagga import QuaggaService
from mininext.net import MiniNExT as Mininext
from mininext.cli import CLI
import mininext.util
# Imports from Mininet
import mininet.util
mininet.util.isShellBuiltin = mininext.util.isShellBuiltin
sys.modules['mininet.util'] = mininet.util

from mininet.util import dumpNodeConnections
from mininet.node import RemoteController
from mininet.node import Node
from mininet.link import Link
from mininet.log import setLogLevel, info
from collections import namedtuple

QuaggaHost = namedtuple("QuaggaHost", "name ip mac port")
net = None

class QuaggaTopo(Topo):
    def __init__(self):
        super(QuaggaTopo, self).__init__()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        quagga_svc = QuaggaService(autoStop=False)
        quagga_base_config_path = os.path.join(script_dir, 'quaggacfgs')

        quagga_hosts = [
            QuaggaHost('a1', '172.0.0.1/16', '08:00:27:89:3b:9f', 1),
            QuaggaHost('b1', '172.0.0.11/16', '08:00:27:92:18:1f', 2)
        ]

        # a switch to connect hosts
        switch = self.addSwitch('s1')

        for host in quagga_hosts:
            quagga_svc_config = {
                'quaggaConfigPath': os.path.join(quagga_base_config_path, host.name)
            }
            quagga_container = self.addHost(
                name=host.name,
                ip=host.ip,
                mac=host.mac,
                privateLogDir=True,
                privateRunDir=True,
                inMountNamespace=True,
                inPIDNamespace=True
            )
            self.addNodeService(node=host.name, service=quagga_svc,
                                nodeConfig=quagga_svc_config)

            self.addLink(quagga_container, switch, port2=host.port)

def add_interfaces_for_mtd(net):
    print 'Configuring participating ASs...'
    for host in net.hosts:
        print 'Host: ', host.name 
        if host.name == 'a1':
            host.cmd('sudo ifconfig lo:1 100.0.0.1 netmask 255.255.255.0 up')
            host.cmd('sudo ifconfig lo:1 100.0.0.7 netmask 255.255.255.0 up')
        elif host.name == 'b1':
            host.cmd('sudo ifconfig lo:1 110.0.0.10 netmask 255.255.255.0 up')
            host.cmd('sudo ifconfig lo:2 110.0.0.20 netmask 255.255.255.0 up')
            host.cmd('sudo ifconfig lo:3 110.0.0.30 netmask 255.255.255.0 up')

def startNetwork():
    info('** Creating Quagga network topology\n')
    topo = QuaggaTopo()
    net = Mininext(topo=topo,
            controller=lambda name: RemoteController(name, ip='127.0.0.1'),
            listenPort=6633)
    
    info('** Starting the network\n')
    net.start()

    info('** ps aux dumps on all hosts\n')
    for host in net.hosts:
        host.cmdPrint('ps aux')

    info('** Adding Network Interfaces for MTD setup\n')
    add_interfaces_for_mtd(net)

    info('Running CLI\n')
    CLI(net)
    return net

def stopNetwork(net):
    if net:
        info("** Tearing down Quagga network\n")
        net.stop()

if __name__ == '__main__':
    setLogLevel('debug')

    net = startNetwork()
    atexit.register(stopNetwork, net)

