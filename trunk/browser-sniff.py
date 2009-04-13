#!/usr/bin/env python

"""This program starts a browser and takes a packet capture of its
conversations with servers. It stops capturing and kills the browser after a
given timeout.

Note that this program will use tshark or tcpdump to capture network packets
(not in promiscuous mode), but you must have at least one of the two.

Usage:

      $ browser-sniff.py [-h] [-d device] [-f filter] [-n count] [-t seconds] output-directory browser-command [browser-options...]

-h    this help message
-d    network device to sniff on (default: le0)
-f    pcap filters (default: none)
-n    number of trials to run (default: 1)
-t    seconds before timeout (default: 30)

output-directory will be filled with count pcap files. browser-command is the
browser command line you want to run, including possibly a Firefox profile and
definitely a URL. Examples:

      firefox -P some.profile https://www.eff.org/
      "c:\\program files\\mozilla firefox\\firefox.exe" -P some.profile https://www.isecpartners.com/
      "c:\\program files\\internet explorer\\iexplore.exe" http://www.noncombatant.org/

If you don't know what device to use for the -d option, run

      $ ./browser-sniff.py -h

which prints out a list of available devices at the end. Here is a complete
usage example on Linux/Unix:

      $ ./browser-sniff.py -h
      [help elided...]
      You have the following devices available for sniffing:
      1.le0
      2.lo0

Since lo0 is the loopback interface, that leaves le0 as the real network
interface. Therefore:

      $ ./browser-sniff.py -d le0 eff.org firefox http://www.eff.org/
      tcpdump: listening on le0, link-type EN10MB (Ethernet), capture size 65535 bytes
      100 packets captured
      100 packets received by filter
      0 packets dropped by kernel
      Completed test in eff.org/00000.pcap

This program is released under the terms of the GNU General Public License,
version 2. See the file COPYING.txt. Written by Chris Palmer
<chris@isecpartners.com> with help from Sebastian Ng.

$Id$
"""

import os
import subprocess
import sys
from time import time, sleep

if "win32" == sys.platform:
      import win32process


TCPDUMP = "tcpdump"
TSHARK = "tshark"
USING_TSHARK = False
if "win32" == sys.platform:
      TSHARK = '"%s"' % os.path.join(os.environ["ProgramFiles"], "wireshark", "tshark.exe")


def usage():
      sys.stderr.write(__doc__)
      sys.stderr.write("\nYou have the following devices available for sniffing:\n")

      p = os.popen(TSHARK + " -D").read()
      if not p:
            sys.stderr.write("Trying tcpdump instead..." + "\n")
            p = os.popen(TCPDUMP + " -D").read()
      sys.stderr.write(p + "\n")
      sys.exit(1)


def get_program_name_and_arguments(command_line):
      cmnd = command_line.lower()
      try:
            i = cmnd.index(".exe") + 4
      except ValueError, e:
            sys.stderr.write("Sorry, Windows command lines must begin with a program name that ends with '.exe.'\n")
            sys.exit(1)

      cmnd = command_line[:i].strip('"')
      b = os.path.basename(cmnd)
      return cmnd, b + " " + command_line[i+1:]
 

def launch(browser, device, pcap_filter, timeout, output):

      """Launches browser and sniffs device (with pcap_filter, if any) for
packets, until timeout has passed. Stores a pcap file in a file named
output."""

      if pcap_filter:
            pcap_filter = "-f " + pcap_filter
      else:
            pcap_filter = ""
      tshrk = "%s -i %s -a duration:%d -p -w %s %s" % (TSHARK, device, timeout, output, pcap_filter)
      tcpdmp = "%s -i %s -s 65535 -p -w %s %s" % (TCPDUMP, device, output, pcap_filter)

      rtrn = None
      if "win32" == sys.platform:
            cmnd, rgmnts = get_program_name_and_arguments(browser)
            print "cmnd:", cmnd
            print "rgmnts:", rgmnts
            subprocess.Popen("cmd.exe /c start cmd.exe /c " + tshrk, creationflags=0x8)
            # Give tshark a chance to start up.
            sleep(3)
            s = win32process.STARTUPINFO()
            p, t, pid, tid = win32process.CreateProcess(cmnd, rgmnts, None, None, 0, 0, None, "\\" , s)
            
      else:
            tshrk += " &"
            tcpdmp += " &"

            global USING_TSHARK
            for p in os.environ["PATH"].split(":"):
                  if os.access(p + "/tshark", os.X_OK):
                        USING_TSHARK = True
                        break

            if USING_TSHARK:
                  os.system(tshrk)
            else:
                  sys.stderr.write("Could not execute tshark. Trying tcpdump...\n")
                  os.system(tcpdmp)

            os.system(browser)


if __name__ == "__main__":

      from getopt import getopt, GetoptError

      try:
            optns, rgmnts = getopt(sys.argv[1:], "d:f:hn:t:")
      except GetoptError:
            usage()

      if len(rgmnts) < 2:
            usage()

      optns = dict(optns)
      drctry_nm = rgmnts[0]
      if "win32" == sys.platform:
            rgmnts[1] = '"%s"' % rgmnts[1]
      brwsr = " ".join(rgmnts[1:]).strip()
      if "win32" != sys.platform:
            brwsr += " &"

      try:
            os.mkdir(drctry_nm)
      except OSError, e:
            sys.stderr.write(str(e) + "\n")

      for i in xrange(int(optns.get("-n", 1))):
            fl_nm = os.path.join(drctry_nm, "%05d" % i) + ".pcap"
            launch(brwsr, optns.get("-d", "le0"), optns.get("-f", ""), int(optns.get("-t", 30)), fl_nm)

            sleep(int(optns.get("-t", 30)) + 6)

            b = os.path.split(rgmnts[1])[-1]
            if "win32" == sys.platform:
                  os.system("taskkill /f /t /im %s" % b)
            else:
                  os.system("kill $(ps -o pid,command | grep '%s' | grep -v grep | grep -v sniff | awk '{print $1}')" % b)
                  if not USING_TSHARK:
                        os.system("kill $(ps -o pid,command | grep tcpdump | grep -v grep | awk '{print $1}')")

            print "Completed test in", fl_nm

