#!/usr/bin/env python

"""
Summarizes the wire cost of network traffic flows, selected by host and/or
ports.

Command line usage:

      $ ./summarize_pcap.py [-h] [-H host,host,host] [-p 1,2,3] pcap-file [pcap-files...]

Host can be a hostname or an IP. Ports must be comma-separated integers,
with no spaces between the commas. Default ports are 53,80,443 (I use this
for web traffic flows). Hosts can be IP addresses or hostnames, again
separated by commas and no spaces. As usual, -h is help.

This program is released under the terms of the GNU General Public License,
version 2. See the file COPYING.txt. Written by Chris Palmer
<chris@isecpartners.com> with help from Sebastian Ng."""

# $Id$


from Cheetah.Template import Template
from decimal import Decimal
from PcapReader import PcapReader
from socket import gethostbyname as resolve
import sys
from os.path import dirname, basename, join as path_join
from os import stat
import dpkt
from reassemble_tcp import ip_address
from summarize_http import summarize_http_connection
import time


def usage():
      print __doc__
      sys.exit(1)


def deltas(numbers):

      """Given a sequence of numbers, returns a list of their deltas."""

      return [ b - a for a, b in zip(numbers, numbers[1:]) ]


def average_delta(numbers):

      """Given a sequence of numbers, returns the average delta between
subsequent numbers."""

      return float(sum(deltas(numbers))) / float(len(numbers) - 1)


class PacketSynopsis:

      """A synopsis of a packet for use with PacketSummary. A PacketSynopsis
has the following attributes: timestamp, source_host, source_port,
destination_host, destination_port, frame_bytes, ip_bytes, transport_bytes,
application_bytes, and application_payload."""

      def __init__(self, **kwargs):
            for k, v in kwargs.items():
                  setattr(self, k, v)


def filter(pcap_file_name, hosts, ports):

      """Given the file name pcap_file_name, scans the named packet dump for
packets matching the given transport layer ports and/or hosts, and yields a
PacketSynopsis. hosts and ports are sequences. To match any port, provide an
empty sequence; similarly for hosts."""

      for p, m in PcapReader(pcap_file_name):
            try:
                  e = dpkt.ethernet.Ethernet(p)
                  i = e.data
                  t = i.data
                  src = ip_address(i.src)
                  dstntn = ip_address(i.dst)

                  if ports and (t.dport not in ports) and (t.sport not in ports):
                        continue
                  if hosts and (src not in hosts) and (dstntn not in hosts):
                        continue

                  # This bit of cheese with Decimal is an attempt to avoid
                  # floating-point rounding errors, to maintain the same
                  # timestamps as found when you look at the pcap in
                  # Wireshark. It appears to work so far.
                  yield PacketSynopsis(timestamp=Decimal("%d.%06d" % m[:2]),
                          source_host=src,
                          source_port=t.sport,
                          destination_host=dstntn,
                          destination_port=t.dport,
                          frame_bytes=len(p),
                          ip_bytes=len(e.data),
                          transport_bytes=len(i.data),
                          application_bytes=len(t.data),
                          application_payload=t.data )

            except Exception, e:
                  sys.stderr.write(str(type(e)) + ": " + e.message + "\n")


class PacketSummary:

      """A running summary of a sequence of packet synopses."""

      def __init__(self):
            self.frame_bytes = self.ip_bytes = self.transport_bytes = self.application_bytes = 0
            self.packets = 0
            self.unique_hosts = { }
            self.unique_ports = { }
            self.latencies = { }
            self.timestamps = [ ]
            self.connection_bytes = { }
            self.first = self.last = None
            self.connections = { }

      def add(self, synopsis):
            if not self.first:
                  self.first = synopsis

            # We use .first and .last to calculate the time elapsed. Don't
            # count long-delayed FINs and ACKs and such against the time
            # elapsed. This is a cheesetacular hack. Specifically, Humboldt
            # Fog.
            #
            if synopsis.application_bytes > 0:
                  self.last = synopsis

            self.frame_bytes += synopsis.frame_bytes
            self.ip_bytes += synopsis.ip_bytes
            self.transport_bytes += synopsis.transport_bytes
            self.application_bytes += synopsis.application_bytes
            self.packets += 1
            self.unique_hosts[synopsis.source_host] = self.unique_hosts[synopsis.destination_host] = True
            self.unique_ports[synopsis.source_port] = self.unique_ports[synopsis.destination_port] = True

            id = connection_id(synopsis.source_port, synopsis.destination_port)
            if self.connections.has_key(id):
                  self.connections[id].append(synopsis.application_payload)
            else:
                  self.connections[id] = [synopsis.application_payload]

            # Store timestamps for each connection, so we can figure
            # average latency later.
            self.timestamps.append(synopsis.timestamp)
            for p in synopsis.source_port, synopsis.destination_port:
                  if p in self.latencies:
                        self.latencies[p].append(synopsis.timestamp)
                  else:
                        self.latencies[p] = [synopsis.timestamp]

                  # Store application layer bytes per connection.
                  self.connection_bytes[p] = self.connection_bytes.get(p, 0) + synopsis.application_bytes


def connection_id(source_port, destination_port):

      """Returns a unique-ish identifier for a "connection"."""

      return ",".join(sorted( (str(source_port), str(destination_port)) ))


if __name__ == "__main__":
      from getopt import getopt, GetoptError

      if 1 == len(sys.argv):
            usage()

      optns = { "-p": "53,80,443", "-H": "" }
      try:
            (o, pcp_fls) = getopt(sys.argv[1:], "hH:p:")
      except GetoptError, e:
            usage()
      if not pcp_fls:
            usage()
      optns.update(dict(o))

      if "-h" in optns:
            usage()

      hsts = ()
      if optns["-H"]:
            hsts = [ resolve(h) for h in optns["-H"].split(",") ]
      prts = [ int(p) for p in optns["-p"].split(",") ]


      # Now parse the pcap files and render the summaries.
      #
      for pcp_fl in pcp_fls:
            pkt_smry = PacketSummary()
            i = 0
            snpses = []
            for snpss in filter(pcp_fl, hsts, prts):
                  snpss.relative_timestamp = 0
                  if pkt_smry.first:
                        snpss.relative_timestamp = snpss.timestamp - pkt_smry.first.timestamp
                  snpss.packet = i
                  pkt_smry.add(snpss)
                  snpses.append(snpss)
                  i += 1

            pkt_smry.unique_hosts = pkt_smry.unique_hosts.keys()
            pkt_smry.unique_hosts.sort()

            pkt_smry.unique_ports = pkt_smry.latencies.keys()
            pkt_smry.unique_ports.sort()

            tmplt_fl = path_join(dirname(sys.argv[0]), "summary.html")
            tmplt = Template(file(tmplt_fl, "rb").read())

            tmplt.pcap_date = time.asctime(time.localtime(stat(pcp_fl).st_mtime))
            tmplt.summary_date = time.asctime(time.localtime())

            tmplt.synopses = snpses
            tmplt.packet_summary = pkt_smry
            tmplt.pcap_file_name = pcp_fl

            tmplt.time_elapsed = pkt_smry.last.timestamp - pkt_smry.first.timestamp
            tmplt.link_overhead = (1 - float(pkt_smry.application_bytes) / pkt_smry.frame_bytes) * 100
            tmplt.network_overhead = (1 - float(pkt_smry.application_bytes) / pkt_smry.ip_bytes) * 100
            tmplt.unique_hosts_count = len(pkt_smry.unique_hosts)

            tmplt.unique_ports_count = len(pkt_smry.latencies)

            tmplt.connections_count = len(pkt_smry.unique_ports) - len([p for p in prts if p in pkt_smry.latencies])

            smrzd_cnctns = []
            for c in pkt_smry.connections:
                  s = "".join(pkt_smry.connections[c])
                  l = len(s)
                  s = summarize_http_connection(s)
                  if not s:
                        continue
                  smrzd_cnctns.append( { "id": c, "summary": s, "length": l } )
            tmplt.summarized_connections = smrzd_cnctns

            avrgs = []
            for k in sorted(pkt_smry.latencies):
                  if 1 == len(pkt_smry.latencies[k]):
                        continue
                  a = average_delta(pkt_smry.latencies[k])
                  avrgs.append( { "port": k, "average": a, "bytes": pkt_smry.connection_bytes[k] } )

            tmplt.average_latencies = avrgs
            tmplt.latency_average = sum([a["average"] for a in avrgs]) / len(avrgs)

            fl = pcp_fl.replace(".pcap", ".html")
            file(fl, "w").write(str(tmplt))
            print fl

## END

