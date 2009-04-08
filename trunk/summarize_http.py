#!/usr/bin/env python

# $Id$

import re
from reassemble_tcp import ethernet_frames, ip_datagrams, tcp_streams

REQUEST_MATCHER = re.compile(r"^(GET|PUT|POST|HEAD|DELETE|PROPFIND|TRACE|OPTIONS|CONNECT)\s+.*$",
                             re.IGNORECASE|re.MULTILINE)
RESPONSE_MATCHER = re.compile(r"^HTTP/\d\.?\d? [1-5]\d{2}.+$",
                              re.IGNORECASE|re.MULTILINE)

REQUEST_RESPONSE_MATCHER = re.compile(r"((GET|PUT|POST|HEAD|DELETE|PROPFIND|TRACE|OPTIONS|CONNECT)\s+.*)|(HTTP/\d\.?\d? [1-5]\d{2}.+)$",
                                      re.IGNORECASE|re.MULTILINE)


def summarize_http_connection(stream):
      return [ m.group() for m in REQUEST_RESPONSE_MATCHER.finditer(stream) ]


if __name__ == "__main__":

      import sys
      from PcapReader import PcapReader

      if 2 != len(sys.argv):
            print "Usage: summarize_http pcap-file"
            sys.exit(1)

      frms = ethernet_frames( [ p for p, m in PcapReader(sys.argv[1]) ] )
      dt_grms = ip_datagrams(frms)
      strms = tcp_streams(dt_grms)
      for s in [ t for t in strms ]:
            if (80 not in s) and (443 not in s) and (53 not in s):
                  continue

            #print s
            #for m in REQUEST_MATCHER.finditer(strms[s]):
            #      print m.group()
            #for m in RESPONSE_MATCHER.finditer(strms[s]):
            #      print m.group()
            #for m in REQUEST_RESPONSE_MATCHER.finditer(strms[s]):
            #      print m.group()

            print summarize_http_connection(strms[s])

