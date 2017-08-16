# cython: profile=False

# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from struct import pack
from cpython.array cimport array
import struct
import time
import sys
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
        :param args:
        :param kwargs:
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

    def __cinit__(self):
        self.PCAP_HDR_LEN = 24
        self.PKT_HDR_LEN = 16

    def __init__(self, file_handle, pk_format=pktypes.array_data):
        self.fh = file_handle
        self.pk_format = pk_format
        self.header =  PcapHeader(self.fh.read(self.PCAP_HDR_LEN))

    def __iter__(self):
        return self

    # no next function defined on purpose. Its a cython thing
    # See: http://cython.readthedocs.io/en/latest/src/userguide/special_methods.html#the-next-method
    def __next__(self):
        cdef:
            bytes data
            PktHeader hdr
        while 1:
            data = self.fh.read(self.PKT_HDR_LEN)
            if not len(data):
                raise StopIteration()
            else:
                hdr = PktHeader(data, order=self.header.order)
                if self.pk_format == 2:
                    return (hdr.get_timestamp(self.header.nano),
                            array('B', self.fh.read(hdr.incl_len)),
                            self.header.net_layer)
                else:
                    return (hdr.get_timestamp(self.header.nano),
                            self.fh.read(hdr.incl_len),
                            self.header.net_layer)

    cpdef int tz_offset(self):
        return self.header.tz_offset

    cpdef list pkts(self):
        return list(self)


cdef class SectionHeaderBlock:

    def __init__(self, *args, **kwargs):
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
        if ifaces[iface_id][tsres_index] <= 127:
            tsdiv = 10**ifaces[iface_id][tsres_index]
        elif 128 <= ifaces[iface_id] <= 254:
            tsdiv = 2**ifaces[iface_id][tsres_index]
        else:
            return (-1, -1, -1)
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
        return (-1, -1, -1)



cdef tuple parse_iface_descr(object fh, bytes order):
    cdef:
        unsigned char tsres
        uint32_t block_len
        uint16_t link, opt_code, opt_len, opt_bytes_remain

    # default if no tsresol is present
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

    def __init__(self, file_handle, pk_format=pktypes.array_data):
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
        return list(self)


cdef class PCAPReader:

    def __init__(self, file_handle, pk_format=pktypes.array_data):
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
        self.decoder.close()


cdef class PCAPWriter:

    def __init__(self, file_handle, snap_len=1500, net_layer=1):
        self._magic = MAGIC.ident
        if sys.byteorder == 'big':
            self._magic = MAGIC.swapped
        self._f = file_handle
        self._header = PcapHeader(magic=self._magic, snap_len=snap_len,
                                  net_layer=net_layer)
        self._f.write(str(self._header))

    cpdef writepkt(self, bytes pkt, double ts):
        if ts == 0.00:
            _ts = time.time()
        else:
            _ts = ts
        _n = len(pkt)
        _p_header_c = PktHeader(ts_sec=int(_ts),
                                ts_usec=int(round(_ts % 1, 6) * 10 ** 6),
                                incl_len=_n, orig_len=_n,
                                order = self._header.order)
        self._f.write(str(_p_header_c))
        self._f.write(pkt)

    def close(self):
        self._f.close()


cpdef dict pcap_info(object f):
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
