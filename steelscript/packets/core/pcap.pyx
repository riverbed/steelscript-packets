# cython: profile=False

# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

import sys
import time
import struct
from struct import pack
from cpython.array cimport array
from libc.stdint cimport int32_t, int64_t, uint16_t, uint32_t, uint64_t

from steelscript.packets.core.inetpkt cimport Ethernet

# Defined Static Vars
SHB_MIN_SIZE = 24
SECTION_LEN_UNDEFINED = -1
SEEK_FROM_CUR_POS = 1
OPT_CODE_TSRES = 9
OPT_CODE_TSLEN = 1
INVALID_IFACE = 255

cdef class PcapHeader:
    """
    Implments the file header for a legacy PCAP (libpcap). Details from
    https://wiki.wireshark.org/Development/LibpcapFileFormat
    This type is equivalent to pcap_hdr_s in libpcap code.
    """
    def __init__(self, *args, **kwargs):
        """
        Creates a PCAP File Header.
        :param args: Optional one element list containing bytes of a pcap
               file.
        :param data: Optional keyword argument containing bytes of a pcap
               file.
        :param magic: used to detect the file format itself and the byte
               ordering.
        :param major_version: the major version number of this file format
              (current major version is 2)
        :param minor_version: the minor version number of this file format
              (current minor version is 4)
        :param tz_offset: the correction time in seconds between GMT (UTC)
               and the local timezone of the following packet header
               timestamps.
        :param ts_accuracy: unused parameter. Was intended to determine
               the accuracy of timestamps. Set to 0 by wireshark and tshark.
        :param snap_len: Length of each packet to capture in bytes. Set to
               65535 by tcpdump when -s0 is used. Can be larger in some tools.
        :param net_layer: link-layer header type. 1 is the value for Ethernet.
               For other supported values see:
               http://www.tcpdump.org/linktypes.html
        """
        self.use_buffer = 0
        self._buffer = b''
        if (args and len(args) == 1 and isinstance(args[0], (str, bytes))):
            self._buffer = args[0]
            self.use_buffer = 1
        elif (kwargs and kwargs.has_key('data') and
                  isinstance(kwargs['data'], bytes)):
            self._buffer = kwargs['data']
            self.use_buffer = 1

        if self.use_buffer:
            self.magic = struct.unpack('I', self._buffer[:4])[0]
            if self.magic == MAGIC.ident:
                self.order = '<'
                self.nano = 0
            elif self.magic == MAGIC.ident_nano:
                self.order = '<'
                self.nano = 1
            elif self.magic == MAGIC.swapped:
                self.order = '>'
                self.nano = 0
            elif self.magic == MAGIC.swapped_nano:
                self.order = '>'
                self.nano = 1
            else:
                raise ValueError('PCAP header magic number is invalid. Was '
                                 '{0} vs once of {1}.'
                                 ''.format(self.magic,
                                           ','.join([MAGIC.ident,
                                                     MAGIC.ident_nano,
                                                     MAGIC.swapped,
                                                     MAGIC.swapped_nano])))
            (self.major_version,
             self.minor_version,
             self.tz_offset,
             self.ts_accuracy,
             self.snap_len,
             self.net_layer) = struct.unpack('{0}HHiIII'.format(self.order),
                                             self._buffer[4:])
        else:
            self.magic = kwargs.get('magic', MAGIC.ident)
            if self.magic == MAGIC.ident:
                self.order = '<'
                self.nano = 0
            elif self.magic == MAGIC.ident_nano:
                self.order = '<'
                self.nano = 1
            elif self.magic == MAGIC.swapped:
                self.order = '>'
                self.nano = 0
            elif self.magic == MAGIC.swapped_nano:
                self.order = '>'
                self.nano = 1
            else:
                raise ValueError('PCAP header magic number is invalid. Was '
                                 '{0} vs once of {1}.'
                                 ''.format(self.magic,
                                           ','.join([MAGIC.ident,
                                                     MAGIC.ident_nano,
                                                     MAGIC.swapped,
                                                     MAGIC.swapped_nano])))
            self.major_version = kwargs.get('major_version', 2)
            self.minor_version = kwargs.get('minor_version', 4)
            self.tz_offset = kwargs.get('tz_offset', 0)
            self.ts_accuracy = kwargs.get('ts_accuracy', 0)
            self.snap_len = kwargs.get('snap_len', 1500)
            self.net_layer = kwargs.get('net_layer', 1)

    property order:
        def __get__(self):
            return self._order
        def __set__(self, bytes val):
            if val in ['<', '>']:
                self._order = val
            else:
                raise ValueError("order must '>' or '<'")

    property tz_offset:
        def __get__(self):
            return self._tz_offset
        def __set__(self, int val):
            if -0x80000000 <= val <= 0x7fffffff:
                self._tz_offset = val
            else:
                raise ValueError("Valid tz_offset number values are "
                                 "{0}-{1}".format(-0x80000000, 0x7fffffff))

    def __str__(self):
        return bytes(pack('{0}IHHIIII'.format(self.order),
                          self.magic,
                          self.major_version,
                          self.minor_version,
                          self.tz_offset,
                          self.ts_accuracy,
                          self.snap_len,
                          self.net_layer))


cdef class PktHeader:
    """
    Implments the Record (Packet) Header for a legacy PCAP (libpcap).
    Details from https://wiki.wireshark.org/Development/LibpcapFileFormat
    This type is equivalent to pcaprec_hdr_s in libpcap code.
    """
    def __init__(self, *args, **kwargs):
        """
        Creates a PCAP record header.
        :param args: Optional one element list containing bytes of a pcap
               record header.
        :param data: Optional keyword argument containing bytes of a pcap
               record header.
        :param ts_sec: packet timestamp seconds
        :param ts_usec: packet timestamp useconds
        :param incl_len: number of bytes of packet data actually captured and
               saved.
        :param orig_len: length of the packet as it appeared on the network.
        """
        self.order = kwargs.get('order', b'<')
        self.use_buffer = 0
        self._buffer = b''
        if (args and len(args) == 1 and isinstance(args[0], (str, bytes))):
            self._buffer = args[0]
            self.use_buffer = 1
        elif (kwargs and kwargs.has_key('data') and
                  isinstance(kwargs['data'], bytes)):
            self._buffer = kwargs['data']
            self.use_buffer = 1

        if self.use_buffer:
            (self.ts_sec,
             self.ts_usec,
             self.incl_len,
             self.orig_len) = struct.unpack('{0}IIII'.format(self.order),
                                            self._buffer)
        else:
            self.ts_sec = kwargs.get('ts_sec', 0)
            self.ts_usec = kwargs.get('ts_usec', 0)
            self.incl_len = kwargs.get('incl_len', 0)
            self.orig_len = kwargs.get('orig_len', 0)

    def __str__(self):
        return bytes(pack('{0}IIII'.format(self.order),
                          self.ts_sec,
                          self.ts_usec,
                          self.incl_len,
                          self.orig_len))

    property order:
        def __get__(self):
            return self._order
        def __set__(self, bytes val):
            if val in ['<', '>']:
                self._order = val
            else:
                raise ValueError("order must '>' or '<'")

    cpdef double get_timestamp(self, uint16_t file_header_nano):
        cdef double rval
        if file_header_nano:
            rval = self.ts_sec + (self.ts_usec / 1000000000.0)
        else:
            rval = self.ts_sec + (self.ts_usec / 1000000.0)
        return rval


cdef class Decode:

    def close(self):
        self.fh.close()


cdef class PCAPDecode(Decode):
    """
    Decoder class for libpcap format pcap files.
    """

    def __cinit__(self):
        self.PCAP_HDR_LEN = 24
        self.PKT_HDR_LEN = 16

    def __init__(self, file_handle, pk_format=pktypes.array_data):
        """
        Create a PCAPDecode instance
        :param file_handle: file handle instance of the pcap file.
        :param pk_format: return data format. array.array of bytes (2) or
               bytes string (1). Default is array.array of bytes.
        """
        self.fh = file_handle
        self.pk_format = pk_format
        self.header =  PcapHeader(self.fh.read(self.PCAP_HDR_LEN))

    def __iter__(self):
        return self

    # no next function defined on purpose. Its a cython thing
    # See: http://cython.readthedocs.io/en/latest/src/userguide/special_methods.html#the-next-method
    def __next__(self):
        """
        Implements the iterator behavior of this class according to Cython
        rules.
        :return: Each packet of the file as bytes or array.array of
                 bytes depending on the pk_format.
        """
        cdef:
            bytes data
            PktHeader hdr
        while 1:
            data = self.fh.read(self.PKT_HDR_LEN)
            if not len(data):
                raise StopIteration()
            else:
                hdr = PktHeader(data, order=self.header.order)
                if self.pk_format == pktypes.array_data:
                    return (hdr.get_timestamp(self.header.nano),
                            array('B', self.fh.read(hdr.incl_len)),
                            self.header.net_layer)
                else:
                    return (hdr.get_timestamp(self.header.nano),
                            self.fh.read(hdr.incl_len),
                            self.header.net_layer)

    cpdef int tz_offset(self):
        """
        Get the timezone offset from the pcap header object.
        :return: self.header.tz_offset
        """
        return self.header.tz_offset

    cpdef list pkts(self):
        """
        Generates a list object containing all the packets in a pcap file.
        Should only be used for very small pcap files.
        :return: list of byte strings or array.array of bytes depending on the
                 value of pk_format.
        """
        return list(self)


cdef class SectionHeaderBlock:

    def __init__(self, *args, **kwargs):
        """
        Builds instance of PCAPNG Section Header Block. This PCAPNG Section
        Header Block implementation does not support Options. They are skipped.
        :param args: Optional one element list containing file handle of PCAPNG
               file.
        :param file_handle: Optional file handle of PCAPNG file.
        :param block_len: total size of this block, in bytes.
        :param order: '<' for little endian, '>' for big endian.
        :param magic: Should be 0x1a2b3c4d for little endian or 0x4d3c2b1a for
               big endian systems.
        :param major: Major PCAPNG version number. This code supports 1
        :param minor: Minor PCAPNG version number. This code supports 0
        :param section_len: 64-bit value specifying the length in bytes of
               the following section, excluding the Section Header Block
               itself. Used to allow tools to skip sections. -1 means the
               section length is undefined.
        """
        # Setting this because these 4 bytes were this value if
        # any of the pcap code is creating this type.
        self.block_type = NGMAGIC.sec_hdr
        self.use_buffer = 0
        if (args and len(args) == 1 and isinstance(args[0], object)):
            self.fh = args[0]
            self.use_buffer = 1
        elif (kwargs and kwargs.has_key('file_handle') and
              isinstance(kwargs['file_handle'], object)):
            self.fh = kwargs['file_handle']
            self.use_buffer = 1

        if self.use_buffer:
            b_len_data = self.fh.read(4)
            self.magic = struct.unpack('I', self.fh.read(4))[0]
            if self.magic == NGMAGIC.little:
                self.order = b'<'
            else:
                self.order = b'>'
            (self.major,
             self.minor,
             self.section_len) = struct.unpack('{0}HHq'.format(self.order),
                                               self.fh.read(12))
            self.block_len = struct.unpack('{0}I'.format(self.order),
                                           b_len_data)[0]
            self.fh.seek(self.block_len - 24, SEEK_FROM_CUR_POS)
        else:
            self.block_len = kwargs.get('block_len', SHB_MIN_SIZE)
            self.order = kwargs.get('byte_order', b'<')
            self.magic = kwargs.get('magic', NGMAGIC.little)
            self.major = kwargs.get('major', 1)
            self.minor = kwargs.get('minor', 0)
            self.section_len = kwargs.get('section_len', SECTION_LEN_UNDEFINED)

    property order:
        """
        Property limiting the values for order to < or >.
        """
        def __get__(self):
            return self._order
        def __set__(self, bytes val):
            if val in ['<', '>']:
                self._order = val
            else:
                raise ValueError("order must '>' or '<'")

cdef tuple parse_epb(object fh,
                     bytes order,
                     list ifaces,
                     unsigned char ptype):
    """
    Parser function for PCAPNG Enhanced Packet Block
    :param fh: PCAPNG file handle object
    :param order: Detected order < or >
    :param ifaces: List of interfaces parsed from the Interface Description 
           Block
    :param ptype: Type of packet data to return. bytes string or array.array. 
    :return: Tuple containing the packets capture timestamp, the packet data,
             and the link type. Link types are standardized in Appendix C
             of the PCAP-DumpFileFormat documents hosted on winpcap.org.
             A value of 1 specifies 802.3 Ethernet.
    """
    cdef:
        uint32_t block_len, iface_id, ts_low
        uint32_t cap_len, pkt_len
        unsigned long long ts, ts_high
        double ret_ts, tsdiv
        uint16_t linktype_index, tsres_index
        tuple rtuple

    (block_len,
     iface_id,
     ts_high,
     ts_low,
     cap_len,
     pkt_len) = struct.unpack('{order}IIIIII'.format(order=order),
                              fh.read(6 * 4))

    linktype_index = 0
    tsres_index = 1
    ts = ts_low | (ts_high<<32)
    if len(ifaces) > iface_id:
        # true if we have decoded a Interface Description Block for this
        # interface.
        if ifaces[iface_id][tsres_index] <= 127:
            tsdiv = 10**ifaces[iface_id][tsres_index]
        elif 128 <= ifaces[iface_id] <= 254:
            tsdiv = 2**(ifaces[iface_id][tsres_index] & 0b01111111)
        else:
            # Should really never happen but just for safety.
            return (-1, -1, -1)
        # calculate the return timestamp.
        ret_ts = ts / tsdiv
        if ptype == pktypes.array_data:
            rtuple =  (ret_ts,
                       array('B', fh.read(cap_len)),
                       ifaces[iface_id][linktype_index])
        elif ptype == pktypes.bytes_data:
            rtuple =  (ret_ts,
                       fh.read(cap_len),
                       ifaces[iface_id][linktype_index])
        else:
            raise ValueError("Invalid pktype. Must be array.array of bytes "
                             "({0}) or bytestring ({1})".format(
                pktypes.array_data,
                pktypes.bytes_data
            ))
        # seek past the rest of the packet
        fh.seek((block_len - (28 + cap_len)), SEEK_FROM_CUR_POS)
        return rtuple
    else:
        # We don't have this interface so return all null values.
        return (-1, -1, -1)



cdef tuple parse_iface_descr(object fh, bytes order):
    """
    Parse an Interface Description Block to determine the timestamp resolution
    and link type.
    :param fh: File handler object to read
    :param order: Byte order determined from the Section Header Block
    :return: tuple of link type and timestamp resolution.
    """
    cdef:
        unsigned char tsres
        uint32_t block_len
        uint16_t link, opt_code, opt_len, opt_bytes_remain

    # from PCAP-DumpFileFormat.html on winpcap.org if the if_tsresol option
    # is not present, a resolution of 10^-6 is assumed (i.e. timestamps have
    # the same resolution of the standard 'libpcap' timestamps).
    tsres = 6
    (block_len, link) = struct.unpack('{order}IH'.format(order=order),
                                      fh.read(6))
    # Seek 6 bytes to bypass reserved and SnapLen
    fh.seek(6, SEEK_FROM_CUR_POS)
    # rule out a block with no options
    if block_len <= 20:
        # We are 16 bytes into the block now. Seek past the rest and return
        fh.seek(block_len - 16, SEEK_FROM_CUR_POS)
        return (link, tsres)
    else:
        opt_bytes_remain = 1
        while opt_bytes_remain:
            (opt_code, opt_len) = \
                struct.unpack('{order}HH'.format(order=order),
                                                 fh.read(4))
            if opt_code == OPT_CODE_TSRES and opt_len == OPT_CODE_TSLEN:
                # order does not matter for a byte
                tsres = struct.unpack('B', fh.read(OPT_CODE_TSLEN))[0]
                # seek past padding
                fh.seek(3, SEEK_FROM_CUR_POS)
            elif opt_code == 0 and opt_len == 0:
                opt_bytes_remain = 0
            else:
                # seek past code we don't care about
                # all values are 32 bit aligned
                if opt_len%4:
                    fh.seek(opt_len + (4 - (opt_len%4)), SEEK_FROM_CUR_POS)
                else:
                    fh.seek(opt_len, SEEK_FROM_CUR_POS)
    # seek past the block total len and return
    fh.seek(4, SEEK_FROM_CUR_POS)
    return (link, tsres)


cdef class PCAPNGDecode(Decode):
    """
    PCAPNG format decoder
    """

    def __init__(self, file_handle, pk_format=pktypes.array_data):
        """
        Builds a PCAPNG decoder
        :param file_handle: file handle instance of the pcap file.
        :param pk_format: return data format. array.array of bytes (2) or
               bytes string (1). Default is array.array of bytes.
        """
        self.fh = file_handle
        self.pk_format = pk_format
        self.order = b'@'
        self.int_unpack = b'{en}I'.format(en=self.order)
        self.iface_descrs = list()
        self.pkt_count = 0
        self.sec_hdr = SectionHeaderBlock()

    def __iter__(self):
        return self

    # no next function defined on purpose. Its a cython thing
    # See: http://cython.readthedocs.io/en/latest/src/userguide/special_methods.html#the-next-method
    def __next__(self):
        """
        Implements the iterator behavior of this class according to Cython
        rules.
        :return: Each packet of the file as bytes or array.array of
                 bytes depending on the pk_format.
        """
        cdef:
            uint32_t bt, readpast
            bytes data
            tuple parsed_pkt

        while 1:
            data = self.fh.read(4)
            if not data:
                raise StopIteration()
            else:
                bt = struct.unpack(self.int_unpack, data)[0]
                if bt == NGMAGIC.epb:
                    parsed_pkt = parse_epb(self.fh,
                                           self.order,
                                           self.iface_descrs,
                                           self.pk_format)
                    if parsed_pkt[0] != -1:
                        self.pkt_count += 1
                        return parsed_pkt
                elif bt == NGMAGIC.sec_hdr:
                    # likely once per file
                    self.sec_hdr = SectionHeaderBlock(self.fh)
                    self.order = self.sec_hdr.order
                    self.iface_descrs = list()
                    self.int_unpack = b'{en}I'.format(en=self.order)
                elif bt == NGMAGIC.iface_descr:
                    # once per file
                    self.iface_descrs.append(parse_iface_descr(self.fh,
                                                               self.order))
                else:
                    readpast = struct.unpack(self.int_unpack,
                                             self.fh.read(4))[0]
                    self.fh.seek(readpast-8, SEEK_FROM_CUR_POS)

    cpdef list pkts(self):
        """
        Generates a list object containing all the packets in a pcap file.
        Should only be used for very small pcap files.
        :return: list of byte strings or array.array of bytes depending on the
                 value of pk_format.
        """
        return list(self)


cdef class PCAPReader:

    def __init__(self, file_handle, pk_format=pktypes.array_data):
        """Create a PCAPReader instance. PCAPReader is a pcap and pcapng
        reader object. From the file data it will determine what type of
        PCAP file is being read and initialize a decoder instance to handle
        that format.

        Notes about use:

        Each call to next() will return a tuple of 3 elements
        if data is still present in the file. The three elements are the
        timestamp of the packet, the packet data, and the Network Layer of the
        packet. Network Layer 1 is Ethernet.

        PCAPReader is implemented as an iterator. So packets can be proceeded
        by calling 'for timestamp, pkt, net_layer in pcap_reader:'

        Args:
            :file_handle (object): file handle object of the pcap file. Open
                for read.
            :pk_format (1 or 2): This determines what type of data is returned
                for every call to next(). Default (2) is to return the packet
                data as an array.array of bytes. If 1 is specified then the
                packet data will be returned as a bytes string.
        """
        cdef uint32_t firstbytes
        firstbytes = struct.unpack('I', file_handle.read(4))[0]
        # print binascii.hexlify(self.fh.read(4))
        file_handle.seek(0)
        if firstbytes == NGMAGIC.sec_hdr:
            self.decoder = PCAPNGDecode(file_handle, pk_format=pk_format)
        elif firstbytes in (MAGIC.ident, MAGIC.ident_nano,
                            MAGIC.swapped, MAGIC.swapped_nano):
            self.decoder = PCAPDecode(file_handle, pk_format=pk_format)
        else:
            raise ValueError("Invalid PCAP file.")

    def __iter__(self):
        return self.decoder

    def __next__(self):
        return self.decoder.__next__()

    def close(self):
        """Close the underlying file object. Better done by using a PCAPReader
        in a context manager.
        """
        self.decoder.close()

    cpdef list pkts(self):
        """
        Generates a list object containing all the packets in a pcap file.
        Should only be used for very small pcap files.

        Returns: 
            :list: containing byte strings or array.array of bytes depending on 
                the value of pk_format.
        """
        return self.decoder.pkts()


cdef class PCAPWriter:
    """
    Object for writing PCAP (libpcap format) files.
    """
    def __init__(self, file_handle, snap_len=1500, net_layer=1):
        """Creates a pcap writer. Requires a file opened for write.

        Args:
            :file_handle (object): File handle opened for write.
            :snap_len (uint16_t): Length of each packet to capture in bytes.
                Set to 65535 by tcpdump when -s0 is used.
            :net_layer(uint16_t): link-layer header type. 1 is the value for
                Ethernet.For other supported values see:
                    http://www.tcpdump.org/linktypes.html
        """
        self._magic = MAGIC.ident
        if sys.byteorder == 'big':
            self._magic = MAGIC.swapped
        self._f = file_handle
        self._header = PcapHeader(magic=self._magic, snap_len=snap_len,
                                  net_layer=net_layer)
        self._f.write(str(self._header))

    cpdef writepkt(self, bytes pkt, double ts):
        """Write the bytes of a single packet to an open pcap file.

        Args:
            :pkt (bytes): Packet data in network order byte string
            :ts (double): Timestamp to mark this packet header with. If the 
                value 0.00 is used then writepkt() will fill in the current 
                time.
        """
        cdef:
            double time_stmp
            long pktlen, writelen
            PktHeader pkt_header

        if ts == 0.00:
            time_stmp = time.time()
        else:
            time_stmp = ts
        pktlen = writelen = len(pkt)

        # Don't write any more than the headers snap len. That could mess with
        # tools that don't expect it.
        if pktlen > self._header.snap_len:
            writelen = self._header.snap_len
        pkt_header = PktHeader(ts_sec=int(time_stmp),
                                ts_usec=int(round(time_stmp % 1, 6) * 10 ** 6),
                                incl_len=writelen, orig_len=pktlen,
                                order = self._header.order)
        self._f.write(str(pkt_header))
        self._f.write(pkt[:writelen])

    def close(self):
        """Close the underlying file object.
        """
        self._f.close()


cpdef dict pcap_info(object f):
    """Helper function used by steelscript.wireshark and steelscript.appfwk
    PCAP manager to obtain information about pcap files.

    Args:
        :f (object): File handler open for read.

    Returns: 
        :dict: Keys are first_timestamp, last_timestamp, total_packets, 
            and total_bytes and will contain those metrics from the PCAP file
            opened as f.
    """
    cdef:
        PCAPReader rdr
        uint16_t linktype
        uint32_t pkts
        uint64_t byte_count
        double first_ts, last_ts
        bytes pkt
        dict rval

    rdr = PCAPReader(f, pk_format=pktypes.bytes_data)
    first_ts, pkt , linktype = rdr.next()
    pkts = 1
    byte_count = len(pkt)
    for last_ts, pkt, linktype in rdr:
        pkts += 1
        byte_count += len(pkt)
    rval = {'first_timestamp': first_ts,
            'last_timestamp': last_ts,
            'total_packets': pkts,
            'total_bytes': byte_count}
    return rval
