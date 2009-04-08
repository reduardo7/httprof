SUMMARIZE_PCAP
==============

By Chris Palmer <chris@isecpartners.com> and Sebastian Ng.

These programs measure the network-level performance characteristics of
network traffic. We use it to guesstimate part of the performance impact of
different HTTP configuration parameters such as TLS/SSL, compression,
keepalive, and pipelining.


Files in This Distribution
==========================

README.txt:
      This README file.
COPYING.txt:
      The gentle license for this software.
browser-sniff.py:
      Launches a browser, connects to a web site, and captures packet data.
summarize_pcap.py:
      Computes some statistics about the data flows in a packet capture.
PcapReader.py:
      Reads libpcap files.
summarize_http.py:
      Helper module for getting a summary of HTTP conversations.
reassemble_tcp.py:
      Some TCP/IP helper functions.


Setup and Dependencies
======================

Programming Language
--------------------

Since the programs are written in the Python programming language, you'll
need a Python interpreter. On Mac OS X, it's part of the standard system.
For Windows, the best way to get it is to download it from the official web
site:

      http://www.python.org/

On FreeBSD, install the lang/python port.

Libraries and Other Dependencies
--------------------------------

You will need the dpkt Python module, available for all platforms at:

      http://code.google.com/p/dpkt/

On FreeBSD, install the net/py-dpkt port.

browser-sniff.py uses the tshark program, which comes with Wireshark.
Wireshark is available for all platforms and is available at:

      http://www.wireshark.org/

On FreeBSD, install the net/wireshark port. If browser-sniff.py can't find
tshark, it will try to use tcpdump, which is available in the base install
of Mac OS X.

summarize_pcap.py also depends on the Cheetah templating library. On
FreeBSD, install the devel/py-cheetah port. For Windows, you can download
Cheetah at:

      http://www.cheetahtemplate.org/download.html

For best results, you will want to have at least one HTTP client. :)

It is also possible to use browser-sniff.py to capture pcaps, and then use
summarize_pcap.py on another machine to analyze them.

Special Privileges for Packet Sniffing
--------------------------------------

Depending on your operating system and its configuration, you will need some
special privilege in order to sniff packets. (To analyze previously recorded
packet dumps with summarize_pcap.py does not require special privilege.)

On Windows, you have to run browser-sniff.py as a user that is in an
Administrator group.

On Unix systems, you can run browser-sniff.py as root, and everything will
work fine. However, with a little extra work, you can avoiding having to do
that. The rest of this section describes how.

On FreeBSD, you can add a devfs rule to give an otherwise low-privilege user
permission to read /dev/bpf*. In /etc/devfs.rules, add a rule like this:

      [localrules=10]
      add path 'bpf*' mode 0640 group wheel

and then reboot. Users in the wheel group but who are not root can now sniff
packets. You could create a new group for this purpose if you don't want to
overload the meaning of wheel. But, do not give the packet sniffing group,
wheel or otherwise, more than just read permission on bpf*. It's not
necessary.

On Mac OS X, I don't know if devfs rules work, but in any case you can chown
and chmod bpf* files as normal:

      $ sudo chmod 640 /dev/bpf*

There are a few billion vaguely distinct operating systems based on the many
versions of the Linux kernel, some of which may or may not support the
"capabilities" mechanism (see capabilities(7) if your Linux-based system
supports manual pages, or http://linux.die.net/man/7/capabilities
otherwise). The capability CAP_NET_RAW may provide the same functionality as
does chmoding BSD's bpf*. Otherwise, you'll have to be root. You may have
sudo, and it may be configured as insanely as it is on OS X, which is
helpful but naughty. sudo usage help is available here:

      http://xkcd.com/149/

If you're not using BSD, Windows, OS X, or Linux, please send me an email
and let me know (a) how you got these programs working, and (b) how you
survive day to day on the intertubes. Score 200 bonus points for Plan 9,
5000 points for FreeDOS, and -42 points for Amiga OS.


Usage
=====

The basic use model is that you use browser-sniff.py to capture packet
traces of your browsing sessions, and then you use summarize_pcap.py to
generate a summary of the resulting pcap files.

Read the help for browser-sniff.py and summarize_pcap.py. Hopefully it is
complete enough to get you started. To get the help, use the -h command line
option:

      $ browser-sniff.py -h
      $ summarize_pcap.py -h

