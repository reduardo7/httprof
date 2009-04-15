#!/usr/bin/env python

# $Id$

import re
from reassemble_tcp import ethernet_frames, ip_datagrams, tcp_streams

REQUEST_MATCHER = re.compile(r"^(GET|PUT|POST|HEAD|DELETE|PROPFIND|TRACE|OPTIONS|CONNECT)\s+.*$",
                             re.IGNORECASE|re.MULTILINE)
RESPONSE_MATCHER = re.compile(r"^HTTP/\d?\.?\d? [1-5]\d{2}.+$",
                              re.IGNORECASE|re.MULTILINE)

REQUEST_RESPONSE_MATCHER = re.compile(r"((GET|PUT|POST|HEAD|DELETE|PROPFIND|TRACE|OPTIONS|CONNECT)\s+.*HTTP/\d?\.?\d?)|(HTTP/\d?\.?\d? [1-5]\d{2}.+)$",
                                      re.IGNORECASE|re.MULTILINE)


def summarize_http_connection(stream):

      """stream: A stream of bytes. Returns an array of regular expression
match objects from REQUEST_RESPONSE_MATCHER for each request or response
found in stream."""

      return [ m for m in REQUEST_RESPONSE_MATCHER.finditer(stream) ]


def get_response_segments(stream, matches):

      """stream: A stream of bytes. matches: A sequence of regular
expression match objects, such as returned by summarize_http_connection.
Returns: a sequence of tuples describing the boundaries of the HTTP
responses in stream."""

      sgmnts = [ ]
      for i in xrange(len(matches) - 1):
            s = matches[i].start()
            e = matches[i + 1].start()
            if RESPONSE_MATCHER.match(stream[s:e]):
                  sgmnts.append( (s, e) )

      return sgmnts


def get_response_body(stream, start, end):

      """stream: A stream of bytes. start: The start of a response, NOT the
start of the response body. end: The end of the response. start and end
could come from get_response_segments, for example. Returns: The response
body. If the response was compressed, the decompressed body is returned. The
returned response body may be an empty string."""

      from gzip import GzipFile
      from StringIO import StringIO

      try:
            dlmtr = start + stream[start:end].index("\r\n\r\n")
      except ValueError, e:
            return ""

      hdrs = { }
      for h in stream[start:dlmtr].split("\r\n"):
            try:
                  k, v = h.split(":", 1)
            except ValueError, e:
                  hdrs[h] = None
                  continue
            hdrs[k.strip().lower()] = v.strip()

      bdy = stream[dlmtr+4:end]
      if "gzip" in hdrs.get("content-encoding", "").lower():
            return GzipFile(fileobj=StringIO(bdy)).read()
      return bdy


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

            print [ m.group() for m in summarize_http_connection(strms[s]) ]

