#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def myNetwork():
    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')

    info('*** Adding controller\n')
    c1 = net.addController(name='c1', controller=RemoteController, ip='127.0.0.1', port=6633)

    info('*** Add switches\n')
    switches = []
    for i in range(1, 11):
        switches.append(net.addSwitch(f's{i}', cls=OVSKernelSwitch))

    info('*** Add hosts\n')
    hosts = []
    for i in range(1, 82):
        hosts.append(net.addHost(f'h{i}', cls=Host, ip=f'10.0.0.{i}', defaultRoute=None))

    info('*** Add links\n')
    # Connect switches in your desired topology
    net.addLink(switches[0], switches[4])
    net.addLink(switches[0], switches[5])
    net.addLink(switches[0], switches[7])
    net.addLink(switches[0], switches[9])
    net.addLink(switches[1], switches[4])
    net.addLink(switches[1], switches[5])
    net.addLink(switches[1], switches[7])
    net.addLink(switches[1], switches[9])
    net.addLink(switches[2], switches[4])
    net.addLink(switches[2], switches[5])
    net.addLink(switches[2], switches[6])
    net.addLink(switches[3], switches[4])
    net.addLink(switches[3], switches[6])
    net.addLink(switches[3], switches[7])
    net.addLink(switches[4], switches[6])
    net.addLink(switches[5], switches[7])
    net.addLink(switches[6], switches[8])
    net.addLink(switches[6], switches[9])
    net.addLink(switches[7], switches[8])
    net.addLink(switches[7], switches[9])

    # Connect switches to hosts
    for i in range(1, 82):
        if i <= 8:
            net.addLink(switches[0], hosts[i-1])
        elif 9 <= i <= 16:
            net.addLink(switches[1], hosts[i-1])
        elif 17 <= i <= 24:
            net.addLink(switches[2], hosts[i-1])
        elif 25 <= i <= 32:
            net.addLink(switches[3], hosts[i-1])
        elif 33 <= i <= 40:
            net.addLink(switches[4], hosts[i-1])
        elif 41 <= i <= 48:
            net.addLink(switches[5], hosts[i-1])
        elif 49 <= i <= 56:
            net.addLink(switches[6], hosts[i-1])
        elif 57 <= i <= 64:
            net.addLink(switches[7], hosts[i-1])
        elif 65 <= i <= 72:
            net.addLink(switches[8], hosts[i-1])
        elif 73 <= i <= 81:
            net.addLink(switches[9], hosts[i-1])

    info('*** Starting network\n')
    net.build()

    info('*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info('*** Starting switches\n')
    for switch in switches:
        switch.start([c1])

    info('*** Post configure switches and hosts\n')
    CLI(net)

if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()

