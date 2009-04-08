# Borrowed from libnewsh by Tim Newsham.

# Id: $

from struct import unpack

class BadFileException(Exception):
    pass

class PcapReader :
 
    """Given the name of a libpcap data file (.pcap), parses the packet
data. Instances of PcapReader are generators; they yield the next (packet,
packet_metadata) tuple on each iteration."""

    def __init__(self, pcap_file_name) :
        self.fd = open(pcap_file_name, "rb")
        buf = self.fd.read(6 * 4)
        if 6 * 4 != len(buf):
            raise BadFileException("EOF")

        mag1 = unpack("<I", buf[:4])[0]
        mag2 = unpack(">I", buf[:4])[0]
        MAG = 0xa1b2c3d4L
        if mag1 == MAG :
            self.end = "<"
        elif mag2 == MAG :
            self.end = ">"
        else :
            raise BadFileException("bad magic %x" % mag1)

        self.vermin, self.vermaj, self.tz, self.sigfigs, \
            self.snaplen, self.linktype = unpack(self.end + "HHiIII", buf[4:])

    def next(self) :
        """Yields (packet, (seconds, microseconds, capture_length,
actual_length)) tuples."""

        buf = self.fd.read(4 * 4)
        if 4 * 4 != len(buf):
            return None, (0, 0, 0, 0)
        sec,usec,caplen,actlen = unpack(self.end + "IIII", buf)
        pack = self.fd.read(caplen)
        #if len(pack) != caplen :
        #    #raise "short read!"
        #    return None, (sec,usec,caplen,actlen)
        return pack, (sec,usec,caplen,actlen)

    def __iter__(self) :
        while 1 :
            pack,meta = self.next()
            if pack is None :
                break
            yield pack,meta

