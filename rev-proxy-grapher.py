#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
from __future__ import (absolute_import,
                        division,
                        print_function,
                        unicode_literals)

import sys
import yaml
import re
import logging
import socket

import pydotplus.graphviz as pd

from netaddr import IPNetwork, IPAddress, AddrFormatError

# Used for easy tracking
nodes = {}
clusters = {}
subnets = {}

logger = logging.getLogger(__name__)


def get_node_by_ip(ip):
    """
    :param ip: str
    :rtype: Node
    """
    if ip not in nodes:
        nodes[ip] = Node(ip)
    return nodes[ip]


def get_cluster_by_ip(ip):
    for title, cluster in clusters.items():
        if cluster.has_ip(ip):
            return cluster

    return None


def get_cluster_by_title(title):
    if title in clusters:
        return clusters[title]

    return None


def get_subnet_by_ip(ip):
    for cidr, subnet in subnets.items():
        if subnet.contains_ip(ip):
            return subnet

    return None


def mk_dot_name(name):
    return re.sub('[^a-zA-Z0-9_]+', '_', str(name))


def load_nodes_from_nmap_xml(nmapxml):
    import nmap

    fh = open(nmapxml, 'r')
    report = fh.read()
    fh.close()

    nm = nmap.PortScanner()
    nd = nm.analyse_nmap_xml_scan(report)

    for ip in nd['scan']:
        data = nd['scan'][ip]
        if data['status']['state'] == 'down':
            continue

        node = get_node_by_ip(ip)

        if len(data['hostnames'][0]['name']):
            node.hostname = data['hostnames'][0]['name']

        if 'tcp' in data:
            tcp = data['tcp']
            ports = sorted(tcp.keys())
            if ports:
                for port in ports:
                    if tcp[port]['state'] != 'open':
                        continue
                    prodver = None
                    if 'product' in tcp[port] and len(tcp[port]['product']):
                        prodver = tcp[port]['product']
                        if 'version' in tcp[port] and len(tcp[port]['version']):
                            prodver += '/' + tcp[port]['version']
                    node.add_port(port, prodver)


class Cluster:
    def __init__(self, title, rips, vips=None):
        self.title = title

        self.rips = rips

        if not vips:
            vips = []
            self.type = 'lb'
        else:
            self.type = 'ha'

        self.vips = vips

        # Used to track special LB-cluster node
        self.lb_node = None

        self.subgraph = pd.Subgraph('cluster_%s' % mk_dot_name(self.title))
        # use the color of the first vip or the first rip
        allips = self.vips + self.rips
        subnet = get_subnet_by_ip(allips[0])
        if subnet is None:
            color = 'gray'
        else:
            color = subnet.color
        self.subgraph.set('color', color)
        self.subgraph.set('style', 'dashed')
        self.subgraph.set('label', '%s cluster: %s' % (self.type.upper(), self.title))

    def has_ip(self, ip, viponly=False):
        ip = IPAddress(ip)
        for vip in self.vips:
            if ip == IPAddress(vip):
                return True

        if viponly:
            return False

        for rip in self.rips:
            if ip in IPNetwork(rip):
                return True

        return False

    def has_vip(self, ip):
        return self.has_ip(ip, viponly=True)

    def __repr__(self):
        return "Cluster(%s: rips=[%s], vips=[%s])" % (self.title, ','.join(self.rips),
                                                      ','.join(self.vips))


class Subnet:
    def __init__(self, title, cidr, color, trimdomain=''):
        self.title = title
        self.network = IPNetwork(cidr)
        self.color = color
        self.trimdomain = trimdomain

    def contains_ip(self, ip):
        ip = IPNetwork(ip)
        if ip in self.network:
            return True

    def __repr__(self):
        return "Subnet(%s(%s): %s)" % (self.title, self.color, str(self.network))


class Node:
    def __init__(self, ip):
        self.ip = IPAddress(ip)

        self.hostname = None
        self.nodename = 'node_%s' % mk_dot_name(self.ip)
        self.subnet = get_subnet_by_ip(ip)
        self.cluster = get_cluster_by_ip(ip)

        # Dictionary of portnum=>list of proxy tuples
        self.ports = {}
        # If there is cpe info in the nmap file, put it here
        self.prodvers = {}

        self.is_src_node = False
        self.is_on_graph = False

    def add_proxy(self, portnum, method, logic, dst_node, dst_port):
        self.is_src_node = True

        if portnum not in self.ports:
            self.add_port(portnum)

        myport = self.ports[portnum]
        dst_node.add_port(dst_port)
        proxy = (method, logic, dst_node, dst_port)
        if proxy not in myport:
            self.ports[portnum].append(proxy)

    def add_port(self, portnum, prodver=None):
        portnum = int(portnum)
        if portnum not in self.ports:
            self.ports[portnum] = []
        if prodver:
            self.prodvers[portnum] = prodver

    def draw(self, graph, resolve_dns=False):
        if self.is_on_graph:
            return

        if self.cluster and self.cluster.lb_node is not None:
            # We already drew the LB cluster node
            return

        gnode = pd.Node(self.nodename)
        gnode.set('shape', 'record')
        subnet = get_subnet_by_ip(self.ip)
        if not subnet:
            color = 'gray'
        else:
            color = subnet.color
        gnode.set('color', color)

        # make the ports label
        # we need to add <p_foo> endpoint parts for each port
        pary = []
        for portnum in sorted(self.ports.keys()):
            try:
                service = socket.getservbyport(portnum)
            except OSError:
                service = 'unknown'

            if portnum in self.prodvers and len(self.prodvers[portnum]):
                pary.append('<p_%s>%s/%s\n[%s]' % (portnum, portnum, service, self.prodvers[portnum]))
            else:
                pary.append('<p_%s>%s/%s' % (portnum, portnum, service))

        plabel = '%s' % '|'.join(pary)
        hlabel = str(self.ip)

        if not self.hostname and resolve_dns:
            try:
                hostname = socket.gethostbyaddr(str(self.ip))[0]
                logger.debug('%s -> %s' % (str(self.ip), hostname))
                self.hostname = hostname
            except socket.herror:
                pass

        hostname = self.hostname

        if self.hostname and self.subnet and len(self.subnet.trimdomain):
            hostname = re.sub(r'\.%s$' % self.subnet.trimdomain, '', self.hostname)

        if hostname:
            hlabel = r'%s\n%s' % (self.ip, hostname)

        if self.cluster and self.cluster.has_vip(self.ip):
            hlabel = '%s\n%s' % ('VIP', hlabel)

        if self.cluster and self.cluster.type == 'lb':
            # LB clusters replace all nodes with a single one
            # to avoid drawing a bajillion lines.
            # Did we already make a node for this?
            if not self.cluster.lb_node:
                hlabel = '|'.join(self.cluster.rips)
                label = '{{%s}|{cluster ips:|%s}}' % (plabel, hlabel)
                gnode.set('label', label)
                self.cluster.lb_node = self.nodename
        else:
            # on the src node, the ports are on the right
            if self.is_src_node:
                label = '{%s|{%s}}' % (hlabel, plabel)
                gnode.set('label', label)
                self.draw_proxies(graph, resolve_dns)
            else:
                label = '{{%s}|%s}' % (plabel, hlabel)
                gnode.set('label', label)

        # if we're in a cluster, we'll be adding ourselves to a subgraph instead

        if self.cluster is not None:
            self.cluster.subgraph.add_node(gnode)
        else:
            graph.add_node(gnode)

        self.is_on_graph = True

    def draw_proxies(self, graph, resolve_dns=False):
        method_nodes = {}
        drawn_edges = []
        for portnum, proxies in sorted(self.ports.items()):
            for proxy in proxies:
                (method, logic, dst_node, dst_port) = proxy
                dst_node.draw(graph, resolve_dns)

                mnode_name = 'method_%s' % mk_dot_name('%s_%s' % (str(self.ip), method))
                if mnode_name not in method_nodes:
                    # Make a new method node
                    mnode = pd.Node(mnode_name)
                    mnode.set('shape', 'record')
                    mnode.set('style', 'rounded')
                    mnode.set('color', 'gray')
                    # we use it to track things for us
                    mnode.logics = [logic]
                    graph.add_node(mnode)
                    method_nodes[mnode_name] = mnode
                else:
                    mnode = method_nodes[mnode_name]
                    if logic not in mnode.logics:
                        mnode.logics.append(logic)

                left_label = '<m_%s>%s' % (method, method)
                label_array = []
                for logic in mnode.logics:
                    label_array.append('<l_%s>%s' % (mk_dot_name(logic), logic))
                right_label = '|'.join(label_array)

                label = '{%s|{%s}}' % (left_label, right_label)
                mnode.set('label', label)

                # Draw edge from mother node to this method if not present already
                src_from = '%s:p_%s' % (self.nodename, portnum)
                src_to = '%s:m_%s' % (mnode_name, mk_dot_name(method))
                if (src_from, src_to) not in drawn_edges:
                    graph.add_edge(pd.Edge(src_from, src_to, dir='none'))
                    drawn_edges.append((src_from, src_to))

                # Draw edge from this logic to the destination node/port
                tgt_from = '%s:l_%s' % (mnode_name, mk_dot_name(logic))

                if dst_node.cluster and dst_node.cluster.lb_node:
                    tgt_to = '%s:p_%s' % (dst_node.cluster.lb_node, dst_port)
                else:
                    tgt_to = '%s:p_%s' % (dst_node.nodename, dst_port)

                if (tgt_from, tgt_to) not in drawn_edges:
                    graph.add_edge(pd.Edge(tgt_from, tgt_to, dir='none'))
                    drawn_edges.append((tgt_from, tgt_to))

    def __repr__(self):
        return "Node(%s/%s: [%s])" % (self.ip, self.hostname, ','.join(self.ports.keys()))


def get_dst_nodes_from_ip(int_ip):
    dst_nodes = []
    # is it a cluster?
    cluster = get_cluster_by_title(int_ip)
    if cluster is None:
        dst_nodes.append(get_node_by_ip(int_ip))
    else:
        for rip in cluster.rips:
            try:
                dst_nodes.append(get_node_by_ip(rip))
            except ValueError:
                # In case it's a subnet, we take the first IP available, because
                # it doesn't really matter for our needs
                ip = IPNetwork(rip)
                dst_nodes.append(get_node_by_ip(ip.ip))

    return dst_nodes


def load_proxies_from_yaml(proxies):
    for ext_ip, members in proxies.items():
        try:
            src_node = get_node_by_ip(ext_ip)
        except AddrFormatError:
            logger.critical('Not a valid IP: %s' % ext_ip)
            sys.exit(1)
        for ext_port, methods in members.items():
            for method, logics in methods.items():
                if type(logics) == str:
                    # Simple logic.
                    logics = {ext_port: logics}
                for logic, dest in logics.items():
                    try:
                        int_ip, int_port = dest.split(':')
                    except ValueError:
                        int_ip = dest
                        int_port = ext_port

                    for dst_node in get_dst_nodes_from_ip(int_ip):
                        src_node.add_proxy(int(ext_port), method, logic, dst_node, int(int_port))


def draw_graph(args):
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    if args.verbose:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.CRITICAL)

    logger.addHandler(ch)

    with open(args.topology, 'r') as topofh:
        topology = yaml.load(topofh)
        topofh.close()

    graph = pd.Dot(
        graph_type='digraph',
    )
    graph.set('rankdir', 'LR')
    graph.set('ranksep', args.ranksep)
    graph.set_node_defaults(
        fontname=args.font,
        fontsize=args.fontsize
    )

    if 'subnets' in topology:
        for subnet_title, params in topology['subnets'].items():
            if 'trimdomain' not in params:
                params['trimdomain'] = ''
            subnets[subnet_title] = Subnet(subnet_title, params['cidr'], params['color'],
                                           params['trimdomain'])

    if 'clusters' in topology:
        for cluster_title, cluster_ips in topology['clusters'].items():
            rips = []
            vips = []
            if 'ips' in cluster_ips:
                rips = cluster_ips['ips']
            if 'vips' in cluster_ips:
                vips = cluster_ips['vips']
            clusters[cluster_title] = Cluster(cluster_title, rips, vips)

    load_proxies_from_yaml(topology['proxies'])

    if len(args.nmap_xml):
        for nmap_xml in args.nmap_xml:
            load_nodes_from_nmap_xml(nmap_xml)

    limit_subnets = []
    if len(args.limit_ext):
        for sublimit in args.limit_ext:
            limit_subnets.append(IPNetwork(sublimit))

    for ip, node in nodes.items():
        if node.is_src_node:
            found = False
            for sublimit in limit_subnets:
                if node.ip in sublimit:
                    found = True
                    break
            if len(limit_subnets) and not found:
                continue
            node.draw(graph, args.resolve_dns)

    # Add clusters to the graph
    for title, cluster in clusters.items():
        cluster.subgraph.set('fontname', args.font)
        cluster.subgraph.set('fontsize', args.fontsize)
        graph.add_subgraph(cluster.subgraph)

    # Guess format from the extension
    chunks = args.out.split('.')
    outformat = chunks[-1]

    graph.write(args.out, format=outformat)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='Draw a nice graph of your external to internal proxies',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--topology', default='topology.yaml', required=True,
                        help='File describing the proxies and the topology of your networks')
    parser.add_argument('--resolve-dns', action='store_true', default=False,
                        help='Attempt to resolve DNS for all IPs')
    parser.add_argument('--nmap-xml', nargs='+', default=(),
                        help='Get additional node details from these nmap XML scan files')
    parser.add_argument('--limit-ext', nargs='+', default=(),
                        help='Only include these source IPs or networks')
    parser.add_argument('--font', default='droid sans,dejavu sans,helvetica',
                        help='Font to use in the graph')
    parser.add_argument('--fontsize', default='11',
                        help='Font size to use in the graph')
    parser.add_argument('--ranksep', default='1',
                        help='Node separation between columns')
    parser.add_argument('--out', default='graph.png',
                        help='Write graph into this file, guessing the output format by extension')
    parser.add_argument('--verbose', action='store_true', default=False,
                        help='Be more verbose')

    cmdargs = parser.parse_args()

    draw_graph(cmdargs)
