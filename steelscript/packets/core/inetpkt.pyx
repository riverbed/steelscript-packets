# cython: profile=False

# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.


from struct import pack
from cpython.array cimport array
import binascii
import socket
import struct
import re

from libc.stdint cimport int64_t, uint64_t, \
    int32_t, uint32_t, uint16_t, intptr_t
import ctypes as c
_get_dict = c.pythonapi._PyObject_GetDictPtr
_get_dict.restype = c.POINTER(c.py_object)
_get_dict.argtypes = [c.py_object]

offset_re = re.compile(r'^(udp|tcp)\.payload\.offset\[(\d*):(\d*)\]$')
PTR_VAL = 0
NOT_FOUND = -1

cdef uint16_t checksum(bytes pkt):
    """
    16-bit one's complement of the one's complement sum or an arry of bytes
    padded if necessary to make it an even number of bytes.
    :param pkt: a byte string representing the packet data to be checksummed.
    :return: 16 bit checksum value.
    """
    cdef uint32_t s
    cdef uint16_t _s
    cdef array pdata
    if len(pkt) % 2 == 1:
        pkt += b"\0"
    pdata = array('H', pkt)
    s = sum(pdata)
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    _s = ~s
    return (((_s>>8)&0xff)|_s<<8) & 0xffff


cdef unsigned char is_ipv4(bytes ip):
    """
    Test if a set of bytes is a valid IPv4 address.
    :param ip: 
    :return: 1/0 depending on if the bytes are a IPv4 address.
    """
    try:
        socket.inet_aton(ip)
        return 1
    except socket.error:
        return 0

cdef void set_short_nibble(uint16_t* short_word,
                           unsigned char nibble,
                           unsigned char which):
    """
    Set the value of a 4 bit nibble in a 16 bit short.
    :param short_word: Pointer to the short to set.
    :param nibble: 4 bit value to set.
    :param which: 1-4 from low to high nibble.
    :return: void
    """
    cdef:
        uint16_t shift
    shift = 4 * which
    short_word[PTR_VAL] = \
        (short_word[PTR_VAL] & ~(0xf << shift)) | (nibble << shift)

cdef void set_char_nibble(unsigned char* char_word,
                          unsigned char nibble,
                          unsigned char which):
    """
    Set the value of a 4 bit nibble in a 8 bit char.
    :param short_word: Pointer to the char to set.
    :param nibble: 4 bit value to set.
    :param which: 1-2 from low to high nibble.
    :return: void
    """
    cdef:
        unsigned char shift
    shift = 4 * which
    char_word[PTR_VAL] =  \
        (char_word[PTR_VAL] & ~(0xf << shift)) | (nibble << shift)


cdef uint16_t get_short_nibble(uint16_t short_word, unsigned char which):
    """
    Get 4 bit value from a 16 bit short.
    :param short_word: unsigned short value to get a nibble from.
    :param which: 1-4 from low to high nibble.
    :return: unsigned short containing value of nibble.
    """
    return (short_word >> (4 * which)) & 0xF

cdef unsigned char get_char_nibble(unsigned char char_word,
                                   unsigned char which):
    """
    Get 4 bit value from a 8 bit char.
    :param short_word: unsigned char value to get a nibble from.
    :param which: 1-2 from low to high nibble.
    :return: unsigned char containing value of nibble.
    """
    return (char_word >> (4 * which)) & 0xF

cdef void set_bit(uint16_t* flags, unsigned char offset):
    """
    Set a single bit in a unsigned short
    :param flags: pointer to 16bit flags value
    :param offset: bit offset from low to high (0-15)
    :return: void
    """
    cdef:
        uint16_t mask
    if offset <= 15:
        mask = 1 << offset
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] | mask
    else:
        raise ValueError("inetpkt.set_bit() offset ({0}) value to large "
                         "for short type".format(offset))

cdef void set_word_bit(uint32_t* flags, unsigned char offset):
    """
    Set a single bit in a unsigned int
    :param flags: pointer to 32bit flags value
    :param offset: bit offset from low to high (0-31)
    :return: void
    """
    cdef:
        uint16_t mask
    if offset <= 31:
        mask = 1 << offset
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] | mask
    else:
        raise ValueError("inetpkt.set_bit() offset ({0}) value to large "
                         "for int type".format(offset))

cdef void set_cbit(unsigned char* flags, unsigned char offset):
    """
    Set a single bit in a unsigned char
    :param flags: pointer to 8bit flags value
    :param offset: bit offset from low to high (0-7)
    :return: void
    """
    cdef:
        unsigned char mask
    if offset <= 7:
        mask = 1 << offset
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] | mask
    else:
        raise ValueError("inetpkt.set_cbit() offset ({0}) value to large "
                         "for unsigned char type".format(offset))


cdef void unset_bit(uint16_t* flags, unsigned char offset):
    """
    Unset a single bit in a unsigned short
    :param flags: pointer to 16bit flags value
    :param offset: bit offset from low to high (0-15)
    :return: void
    """
    cdef:
        uint16_t mask
    if offset <= 15:
        mask = ~(1 << offset)
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] & mask
    else:
        raise ValueError("inetpkt.unset_bit() offset ({0}) value to large "
                         "for short type".format(offset))

cdef void unset_word_bit(uint32_t* flags, unsigned char offset):
    """
    Unset a single bit in a unsigned int
    :param flags: pointer to 32bit flags value
    :param offset: bit offset from low to high (0-31)
    :return: void
    """
    cdef:
        uint16_t mask
    if offset <= 31:
        mask = ~(1 << offset)
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] & mask
    else:
        raise ValueError("inetpkt.unset_bit() offset ({0}) value to large "
                         "for int type".format(offset))

cdef void unset_cbit(unsigned char* flags, unsigned char offset):
    """
    Unset a single bit in a unsigned char
    :param flags: pointer to 8bit flags value
    :param offset: bit offset from low to high (0-7)
    :return: void
    """
    cdef:
        unsigned char mask
    if offset <= 15:
        mask = ~(1 << offset)
        if not flags[PTR_VAL] & mask:
            flags[PTR_VAL] = flags[PTR_VAL] & mask
    else:
        raise ValueError("inetpkt.unset_cbit() offset ({0}) value to large "
                         "for unsigned char type".format(offset))


cdef class PKT:
    """
    Base class for all Steelscript Packets packet objects.
    """

    def __init__(self, *args, **kwargs):
        """

        :param args: pass through to sub classes.
        :param kwargs: pass through to sub classes excepting 'l7_ports'.
        :param l7_ports: A dictionary of <port>: <class>. Used by sub
               classes like TCP and UDP to determine what class to
               use in decoding their payload.
        """
        self.pkt_name = b'PKT'
        self.pq_type, self.query_fields = PKT.query_info()
        if 'l7_ports' in kwargs and isinstance(kwargs['l7_ports'], dict):
            self.l7_ports = kwargs['l7_ports']
        else:
            self.l7_ports = {}

    @classmethod
    def query_info(cls):
        """
        Used by pcap_query to determine what query fields this packet type
        supports and what its PKT type ID is.
        The PKT type ID is usually the layer 4 port number for layer 7
        PKT types.
        :return: tuple of PKT type and a tuple of the supported field names.
        """
        return (PQTYPES.t_pkt,
                ())

    @classmethod
    def default_ports(cls):
        """
        Used by pcap_query to automatically decode layer 7 protocols.
        :return: list of layer 4 ports for 'this' protocol.
        """
        return []

    # TODO figure out what query_field_map was and if I can get rid of it.
    cpdef object get_field_val(self, bytes field):
        return getattr(self, self.query_field_map.get(field, b''), None)

    cpdef PKT get_layer(self, bytes name, int instance=1, int found=0):
        """
        Used to get sub 'layers' of a PKT class based on the name of the
        desired layer.
        :param name: Class ID of the desired layer ('IP', 'UDP', ...)
        :param instance: The Nth instance of the class you want. Useful for
               PKT types that can exist multiple times in a single packet.
               Examples include MPLS or Ethernet.
        :param found: Used in recursive calls to get_layer when instance is
               > 1
        :return: The PKT instance OR an empty NullPkt instance if not found.
        """
        cdef:
            int fnd

        fnd = found
        if hasattr(self, 'payload') and isinstance(self.payload, PKT):
            if self.payload.pkt_name == name:
                fnd += 1
            if fnd == instance:
                return self.payload
            else:
                return self.payload.get_layer(name,
                                              instance=instance,
                                              found=fnd)
        else:
            return NullPkt()

    cpdef PKT get_layer_by_type(self,
                                uint16_t pq_type,
                                int instance=1,
                                int found=0):
        """
        Used to get sub 'layers' of a PKT class based on the PKT type ID 
        of the desired layer.
        :param pq_type: Class name of the desired layer (PQTYPES.t_ip, 
               PQTYPES.t_udp, ...)
        :param instance: The Nth instance of the class you want. Useful for
               PKT types that can exist multiple times in a single packet.
               Examples include MPLS or Ethernet.
        :param found: Used in recursive calls to get_layer when instance is
               > 1
        :return: The PKT instance OR an empty NullPkt instance if not found.
        """
        cdef:
            int fnd

        fnd = found
        if hasattr(self, 'payload') and isinstance(self.payload, PKT):
            if self.payload.pq_type == pq_type:
                fnd += 1
            if fnd == instance:
                return self.payload
            else:
                return self.payload.get_layer_by_type(pq_type,
                                                      instance=instance,
                                                      found=fnd)
        else:
            return NullPkt()

    cpdef bytes pkt2net(self, dict kwargs):
        """
        Used to export a PKT based packet class in network order for writing
        to a socket or into a pcap file.
        :param kwargs: list of arguments defined by PKT sub classes.
        :return: network order byte string representation of the PKT instance.
        """
        return b''

    cpdef tuple from_buffer(self, tuple args, dict kwargs):
        """
        Used to determine if the instance is being initialized from data or
        from keyword arguments. If args[0] is an array, bytes, or a string OR
        if a 'data' keyword argument is then the PKT instance is initialized
        from an array of Unsigned chars.
        :param args: array of initialization arguments 
        :param kwargs: dictionary of keyword arguments
        :return: tuple of 1/0 specifying if the instance is or is not 
                 initializing from data, and the data as an array of unsigned
                 chars.
        """
        if len(args) == 1 and isinstance(args[0], array):
            return 1, args[0]
        elif len(args) == 1 and isinstance(args[0], (bytes, str)):
            return 1, array('B', args[0])
        elif 'data' in kwargs and isinstance(kwargs['data'], array):
            return 1, kwargs['data']
        elif 'data' in kwargs and isinstance(kwargs['data'], (bytes, str)):
            return 1, array('B', kwargs['data'])
        return 0, array('B')


cdef class ARP(PKT):
    """
    Implements RFC 826 Address Resolution Protocol. See schematic to
    follow:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Hardware Type        |         Protocol Type         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Hardware Len  |   Proto Len  |           Operation           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Sender Hardware Addr (Hardware Len Bytes)           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Sender Protocol Addr (Proto Len Bytes)             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Target Hardware Addr (Hardware Len Bytes)           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Target Protocol Addr (Proto Len Bytes)             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    def __init__(self, *args, **kwargs):
        """
        Initialize an ARP object.
        :param args: Optional one element list containing network order
               bytes of an ARP packet
        :param data: Optional keyword argument containing network order
               bytes of an ARP packet
        :param hardware_type: Network Protocol Type. For example: Ethernet
               is hardware_type 1.
        :param proto_type: Network protocol for this ARP request. For example
               this field would be set to 0x800 if this is a IPv4 ARP. Valid
               values for this field are shared with the IEEE 802.3
               EtherType specification used by Ethernet.
        :param hardware_len: Length in bytes (octets) for the hardware type
               specified in hardware_type above.
        :param proto_len: Length in octets for the proto_type specified above.
               IPv4 has a lenght of 4 for example.
        :param operation: 1 for request and 0 for response.
        :param sender_hw_addr: string representation of the senders hardware
               address. For example with hardware_type 1 this would be:
               'xx:xx:xx:xx:xx:xx'
        :param sender_proto_addr: string representation of the senders
               hardware address. For example with proto_type 0x800 this would
               be 'xxx.xxx.xxx.xxx'
        :param target_hw_addr: string representation of the targets hardware
               address.
        :param target_proto_addr: string representation of the targets
               hardware address.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'ARP'
        self.pq_type, self.query_fields = ARP.query_info()

        cdef:
            unsigned char use_buffer
            unsigned int s_proto_start, t_hw_start, t_proto_start
            bytes h_u, p_u
        use_buffer, self._buffer = self.from_buffer(args, kwargs)
        if use_buffer:
            (self.hardware_type, self.proto_type, self.hardware_len,
             self.proto_len, self.operation) = \
                struct.unpack('!HHBBH', self._buffer[:8])
            if(self.hardware_type == ARP_CONST.hwt_ether and
                       self.proto_type == ETHERTYPES.ipv4 and
                       self.proto_len == ARP_CONST.ipv4_len):
                self.sender_hw_addr = bytes(':'.join('%02x'%i for i in
                                struct.unpack("!6B",self._buffer[8:14])))
                self.sender_proto_addr = socket.inet_ntoa(self._buffer[14:18])
                self.target_hw_addr = bytes(':'.join('%02x'%i for i in
                                struct.unpack("!6B",self._buffer[18:24])))
                self.target_proto_addr = socket.inet_ntoa(self._buffer[24:28])
            else:
                s_proto_start = 8 + self.hardware_len
                t_hw_start = s_proto_start + self.proto_len
                t_proto_start = t_hw_start + self.hardware_len
                t_proto_end = t_proto_start + self.proto_len
                h_u = "!{0}B".format(self.hardware_len)
                p_u = "!{0}B".format(self.proto_len)
                self.sender_hw_addr = \
                    bytes(''.join('%02x'%i for i in struct.unpack(h_u,
                        self._buffer[8:s_proto_start])))
                self.sender_proto_addr = \
                    bytes(''.join('%02x'%i for i in struct.unpack(p_u,
                        self._buffer[s_proto_start:t_hw_start])))
                self.taget_hw_addr = \
                    bytes(''.join('%02x'%i for i in struct.unpack(h_u,
                        self._buffer[t_hw_start:t_proto_start])))
                self.taget_proto_addr = \
                    bytes(''.join('%02x'%i for i in struct.unpack(p_u,
                        self._buffer[t_proto_start:t_proto_end])))
        else:
            self.hardware_type = kwargs.get('hardware_type',
                                            ARP_CONST.hwt_ether)
            self.proto_type = kwargs.get('proto_type', ETHERTYPES.ipv4)
            self.hardware_len = kwargs.get('hardware_len',
                                           ARP_CONST.eth_mac_len)
            self.proto_len = kwargs.get('proto_len', ARP_CONST.ipv4_len)
            self.operation = kwargs.get('operation', 1)
            self.sender_hw_addr = kwargs.get('sender_hw_addr',
                                             b'00:00:00:00:00:00')
            self.sender_proto_addr = kwargs.get('sender_proto_addr',
                                                b'0.0.0.0')
            self.target_hw_addr = kwargs.get('target_hw_addr',
                                            b'00:00:00:00:00:00')
            self.target_proto_addr = kwargs.get('target_proto_addr',
                                                b'0.0.0.0')

    @classmethod
    def query_info(cls):
        """
        Provides pcap_query with the query fields ARP supports and ARP's
        PKT type ID.
        :return: tuple of PQTYPES.t_arp and a tuple of the supported
        field names.
        """
        return (PQTYPES.t_arp,
                (b'arp.hw.type', b'arp.proto.type', b'arp.hw.size',
                 b'arp.proto.size', b'arp.src.hw_mac', b'arp.src.proto_ipv4',
                 b'arp.dst.hw_mac', b'arp.dst.proto_ipv4'))

    cpdef object get_field_val(self, bytes field):
        """
        Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.
        :param field: name of the desired field in Wireshark format. For 
               example: arp.proto.type or tcp.flags.urg
        :return: Returns the value of the field as a python object.
        """
        if field == b'arp.hw.type':
            return self.hardware_type
        elif field == b'arp.proto.type':
            return self.proto_type
        elif field == b'arp.hw.size':
            return self.hardware_len
        elif field == b'arp.proto.size':
            return self.proto_len
        elif field == b'arp.src.hw_mac':
            return self.sender_hw_addr
        elif field == b'arp.src.proto_ipv4':
            return self.sender_proto_addr
        elif field == b'arp.dst.hw_mac':
            return self.target_hw_addr
        elif field == b'arp.dst.proto_ipv4':
            return self.target_proto_addr
        else:
            return None

    property operation:
        """
        Get and Set the ARP operation value. Enforces values 1-9
        """
        def __get__(self):
            """
            Get ARP.operation
            """
            return self._operation
        def __set__(self, unsigned char val):
            """
            Set ARP.operation
            :param val: unsigned char value to set operation to.
            :return: None
            """
            if 1 <= val <= 9:
                self._operation = val
            else:
                raise ValueError("Valid operation codes are 1 - 9. Common "
                                 "values are 1 for request and 2 for reply.")

    cpdef bytes pkt2net(self, dict kwargs):
        """
        Used to export a ARP packet class instance in network order for 
        writing to a socket or into a pcap file. At present this function
        only works Ethernet/IPv4 ARP packets OR if buffer was set. If this is 
        not a self.hardware_type == ARP_CONST.hwt_ether, 
        self.proto_type == ETHERTYPES.ipv4 packet BUT buffer is set then the 
        packet in will simply be repeated from the buffer. Any changes are 
        lost
        :param kwargs: list of arguments defined by PKT sub classes. ARP does
               not have any such options.
        :return: network order byte string representation of the PKT instance.
        """
        cdef:
            bytes sndr, trgt, pair
        sndr = trgt = b''

        if(self.hardware_type == ARP_CONST.hwt_ether and
               self.proto_type == ETHERTYPES.ipv4 and
               self.proto_len == ARP_CONST.ipv4_len):
            for pair in self.sender_hw_addr.split(':'):
                sndr += binascii.unhexlify(pair)
            for pair in self.target_hw_addr.split(':'):
                trgt += binascii.unhexlify(pair)
            return b'{0}{1}{2}{3}{4}'.format(
                struct.pack('!HHBBH', self.hardware_type,
                                      self.proto_type,
                                      self.hardware_len,
                                      self.proto_len,
                                      self.operation),
                sndr,
                socket.inet_aton(self.sender_proto_addr),
                trgt,
                socket.inet_aton(self.target_proto_addr)
            )
        elif self._buffer != b'':
            return self._buffer
        else:
            return b''


cdef class NullPkt(PKT):
    """
    NullPkt is a catch all packet type that can be used to simply store
    packet bytes without any decode.
    """
    def __init__(self, *args, **kwargs):
        """
        Initialize an NullPkt object.
        :param args: Optional one element list containing network order
               bytes of an ARP packet
        :param data: Optional keyword argument containing network order
               bytes of an ARP packet
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'NullPkt'
        self.pq_type, self.query_fields = NullPkt.query_info()

        cdef:
            unsigned char use_buffer
        use_buffer, self._buffer = self.from_buffer(args, kwargs)
        if use_buffer:
            self.payload = self._buffer.tostring()
        else:
            self.payload = b''

    @classmethod
    def query_info(cls):
        """
        pseudo pcap_query support for query_info.
        :return: returns tuple of PQTYPES.t_nullpkt and an empty field list
        """
        return (PQTYPES.t_nullpkt,
                ())

    cpdef object get_field_val(self, bytes field):
        """
        pseudo pcap_query support for get_field_val.
        """
        return None

    cpdef bytes pkt2net(self, dict kwargs):
        """
        Used to export a NullPkt object for writing to a socket or into 
        a pcap file. Data is exactly as it came in.
        :param kwargs: Ignored
        :return: string
        """
        return b'{0}'.format(self.payload)


cdef class Ip4Ph:
    """
    Class to encapsulate an IPv4 pseudo header. Used in pkt2net functions
    for TCP and UDP. Part of checksum calculation. Automatically passed in
    to pkt2net by IP if its payload is TCP or UDP
    """
    def __cinit__(self, **kwargs):
        """
        C level init function for Ip4Ph.
        :param src: IPv4 src address for parent IP Object
        :param dst: IPv4 dst address for parent IP Object
        :param reserved: unused 8 bits in pseudo header. Should be 0
        :param proto: Proto of parent IP object.
        :param payload_len: Total length of IP payload in octets.
        :return: Ip4Ph object
        """
        self.src = kwargs.get('src', b'0.0.0.0')
        self.dst = kwargs.get('dst', b'0.0.0.0')
        self.reserved = kwargs.get('reserved', 0)
        self.proto = kwargs.get('proto', 0)
        self.payload_len = kwargs.get('payload_len', 0)


cdef class NetflowSimple(PKT):
    """
    A Netflow decoder used by Riverbed's QA group to replay
    captured netflow data. This packet type only decodes enough of a
    Netflow version 1-9 packet to allow the timestamps to be altered.
    Useful to make previously captured flows appear to a Netflow analyzer
    to have happened 'now'. Be aware that the field unix_nano_seconds in
    this packet type is not accurately defined if the version is 9.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize a NetflowSimple object.
        :param args: Optional one element list containing network order
               bytes of an ARP packet
        :param data: Optional keyword argument containing network order
               bytes of an ARP packet
        :param version: Netflow version (1-9)
        :param count: Count of records if version is 1-8 or count of flow
               sets if version is 9
        :param sys_uptime: Current time in milliseconds since the export
               device started at the moment the netflow packet was sent.
        :param unix_secs: Seconds since the start of the epoch
        :param unix_nano_seconds: nanoseconds remaining from unix_secs. This
               field will not be correct IF the version is 9
        :param payload: The rest of the netflow packet as bytes.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'NetflowSimple'
        self.pq_type, self.query_fields = NetflowSimple.query_info()
        cdef:
            unsigned char use_buffer
        use_buffer, self._buffer = self.from_buffer(args, kwargs)

        if use_buffer:
            (self.version,
             self.count,
             self.sys_uptime,
             self.unix_secs,
             self.unix_nano_seconds) = \
                struct.unpack('!HHIII', self._buffer[:16])

            if len(self._buffer[16:]):
                self.payload = self._buffer[16:]
            else:
                self.payload = b''
        else:
            self.version = kwargs.get('version', 0)
            self.count = kwargs.get('count', 0)
            self.sys_uptime = kwargs.get('sys_uptime', 0)
            self.unix_secs = kwargs.get('unix_secs', 0)
            self.unix_nano_seconds = kwargs.get('unix_nano_seconds', 0)
            self.payload = kwargs.get('payload', b'')

    @classmethod
    def query_info(cls):
        """
        Provides pcap_query with the query fields NetflowSimple supports
        and NetflowSimple's PKT type ID.
        :return: tuple of PQTYPES.t_netflow_simple and a tuple
        of the supported field names.
        """
        return (PQTYPES.t_netflow_simple,
                (b'netflow.version', b'netflow.count', b'netflow.sys_uptime',
                 b'netflow.unix_secs', b'netflow.unix_nano_seconds'))

    @classmethod
    def default_ports(cls):
        """
        Used by pcap_query to automatically decode layer 7 protocols.
        :return: list of layer 4 ports for NetflowSimple.
        """
        return [2005, 2055]

    cpdef object get_field_val(self, bytes field):
        """
        Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.
        :param field: Name of the desired field in Wireshark format. For
               example: arp.proto.type or tcp.flags.urg 
        :return: The value.
        """
        if field == b'netflow.version':
            return self.version
        elif field == b'netflow.count':
            return self.count
        elif field == b'netflow.sys_uptime':
            return self.sys_uptime
        elif field == b'netflow.unix_secs':
            return self.unix_secs
        elif field == b'netflow.unix_nano_seconds':
            return self.unix_nano_seconds
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """
        Used to export a NetflowSimple packet class instance in network order 
        for writing to a socket or into a pcap file. 
        :param kwargs: list of arguments defined by PKT sub classes. 
               NetflowSimple does not have any such options.
        :return: network order byte string representation of this 
                 NetflowSimple instance.
        """
        return b'{0}{1}'.format(pack("!HHIII", self.version,
                                               self.count,
                                               self.sys_uptime,
                                               self.unix_secs,
                                               self.unix_nano_seconds),
                                self.payload)


cdef class UDP(PKT):
    """
    Implements RFC 768 User Datagram Protocol
     0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |     Source      |   Destination   |
    |      Port       |      Port       |
    +--------+--------+--------+--------+
    |                 |                 |
    |     Length      |    Checksum     |
    +--------+--------+--------+--------+
    |
    |          data octets ...
    +---------------- ...
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize a UDP object.
        :param args: Optional one element list containing network order
               bytes of an UDP packet
        :param data: Optional keyword argument containing network order
               bytes of an UDP packet
        :param sport: Layer 4 source port of this packet
        :param dport: Layer 4 destination port of this packet
        :param ulen: UDP Length - Total length of the UDP header plus data
               in bytes
        :param checksum: The checksum value for this packet. Optional with
               IPv4 and must be 0 if not used.
        :param payload: The payload of this packet. Payload can be a PKT
               sub class or a byte string.
        :param l7_ports: A dictionary where the keys are layer 4 port numbers
               and the values are PKT subclass packet classes. Used by
               app_layer to determine what class should be used to decode
               the payload string or byte array.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'UDP'
        self.pq_type, self.query_fields = UDP.query_info()
        cdef:
            unsigned char use_buffer
        use_buffer, self._buffer = self.from_buffer(args, kwargs)
        if use_buffer:
            self.sport, self.dport, self.ulen, self.checksum = \
                struct.unpack('!HHHH', self._buffer[:8])
            self.app_layer(self._buffer[8:])
        else:
            self.sport = kwargs.get('sport', 0)
            self.dport = kwargs.get('dport', 0)
            self.ulen = kwargs.get('ulen', 0)
            self.checksum = kwargs.get('checksum', 0)
            if kwargs.has_key('payload'):
                if isinstance(kwargs['payload'], PKT):
                   self.payload = kwargs['payload']
                elif isinstance(kwargs['payload'], (bytes, str)):
                    self.app_layer(kwargs['payload'])
                else:
                    self.payload = PKT()
            else:
                self.payload = PKT()

    @classmethod
    def query_info(cls):
        """
        Provides pcap_query with the query fields UDP supports and UDP's
        PKT type ID.
        :return: tuple of PQTYPES.t_udp and a tuple of the supported
        field names.
        """
        return (PQTYPES.t_udp,
                (b'udp.srcport', b'udp.dstport', b'udp.length',
                 b'udp.checksum', b'udp.payload',b'udp.payload.offset[x:y]'))

    cpdef object get_field_val(self, bytes field):
        """
        Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch. Also handles 
        udp.payload.offset[x:y] field. 
        :param field: name of the desired field in Wireshark format. For 
               example: arp.proto.type or tcp.flags.urg
        :return: Returns the value of the field as a python object.
        """
        cdef list offsets
        cdef f = field[:18]
        if f == b'udp.srcport':
            return self.sport
        elif f == b'udp.dstport':
            return self.dport
        elif f == b'udp.length':
            return self.ulen
        elif f == b'udp.checksum':
            return self.checksum
        elif f == b'udp.payload':
            return self.payload.pkt2net({})
        elif f == b'udp.payload.offset':
            offsets = (field[19:field.index(']')].split(':'))
            if len(offsets) == 2:
                return self.payload.pkt2net({})[
                       int(offsets[0]):int(offsets[1])
                       ]
            return None
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """
        Used to export a UDP packet class instance in network order 
        for writing to a socket or into a pcap file. 
        :param kwargs: list of arguments defined by PKT sub classes. UDP
               supports the following keyword arguments:
        :param update: Determines if this UDP instance and any sub layers
               should update size counters. For UDP this means updating the
               ulen variable.
        :param csum: Determines if this UDP instance should re-calculate 
               its checksum.
        :param ipv4_pheader: IPv4 psuedo header used in checksum calculation.
        :return: network order byte string representation of this 
                 UDP instance.
        """
        cdef:
            unsigned char _update, _csum
            Ip4Ph _ipv4_pheader
            bytes _pload_bytes, ip_ph

        _update = kwargs.get('update', 0)
        _csum = kwargs.get('csum', 0)
        _ipv4_pheader = kwargs.get('ipv4_pheader', Ip4Ph())

        _pload_bytes = self.payload.pkt2net(kwargs)

        if _update:
            self.ulen = 8 + len(_pload_bytes)
        if _csum and isinstance(_ipv4_pheader, Ip4Ph):
            ip_ph = b'{0}{1}{2}'.format(_ipv4_pheader.src,
                                        _ipv4_pheader.dst,
                                        pack('!HHHHH', _ipv4_pheader.proto,
                                                       self.ulen,
                                                       self.sport,
                                                       self.dport,
                                                       self.ulen))
            self.checksum = checksum(b'{0}\000\000{1}'.format(ip_ph,
                                                              _pload_bytes))

        return b'{0}{1}'.format(pack('!HHHH', self.sport,
                                              self.dport,
                                              self.ulen,
                                              self.checksum),
                                _pload_bytes)

    cdef app_layer(self, array plbuffer):
        """
        Attempts to create an instance of the correct layer 7 protocol
        if the layer 4 ports match. Otherwise returns NullPkt or PKT
        instance.
        :param plbuffer: array of bytes that make up the Layer 7 payload.
        :return: void
        """
        cdef type pkt_cls
        if len(plbuffer):
            if self.dport in self.l7_ports:
                if issubclass(self.l7_ports[self.dport], PKT):
                    pkt_cls = self.l7_ports[self.dport]
                else:
                    pkt_cls = globals()[self.l7_ports[self.dport]]
            elif self.sport in self.l7_ports:
                if issubclass(self.l7_ports[self.sport], PKT):
                    pkt_cls = self.l7_ports[self.sport]
                else:
                    pkt_cls = globals()[self.l7_ports[self.sport]]
            elif 0 in self.l7_ports and len(self.l7_ports) == 1:
                if issubclass(self.l7_ports[self.sport], PKT):
                    pkt_cls = self.l7_ports[0]
                else:
                    pkt_cls = globals()[self.l7_ports[0]]
            else:
                pkt_cls = NullPkt
            self.payload = pkt_cls(plbuffer)
        else:
            self.payload = PKT()


cdef class TCP(PKT):
    """
     0                  1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |     |N|C|E|U|A|P|R|S|F|                               |
    | Offset| Res |S|W|C|R|C|S|S|Y|I|            Window             |
    |       |     | |R|E|G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    def __init__(self, *args, **kwargs):
        """
        Initialize a TCP object.
        :param args: Optional one element list containing network order
               bytes of an TCP packet
        :param data: Optional keyword argument containing network order
               bytes of an TCP packet
        :param sport: Layer 4 source port of this packet
        :param dport: Layer 4 destination port of this packet
        :param sequence: TCP sequence number.
        :param acknowledgment: Acknowledgment number.
        :param data_offset: Size of the TCP header in 32-bit 'words'. Min is
               5.
        :param flag_ns: ECN-nonce concealment protection (RFC 3540).
        :param flag_cwr: Congestion Window Reduced flag (RFC 3168).
        :param flag_ece: ECN-Echo flag (RFC 3168).
        :param flag_urg: flag that the Urgent pointer field is significant.
        :param flag_ack: flag that Acknowledgment field is significant.
        :param flag_psh: flag requesting buffered data be pushed to the
               receiving application.
        :param flag_rst: Reset the connection
        :param flag_syn: Synchronize sequence numbers. Starts TCP handshake.
        :param flag_fin: Flag as the last package from src of this packet.
        :param window: Size of the receive window (default in bytes).
        :param checksum: The 16-bit checksum field.
        :param urg_ptr: Offset from the sequence number indicating the
               last urgent data byte. Use urg flag if set.
        :param options: Array of bytes to use as the TCP options. The user
               must update data_offset and make these bytes align to 32bit
               words. This is not fully implemented in this PKT class.
        :param payload: The payload of this packet. Payload can be a PKT
               sub class or a byte string.
        :param l7_ports: A dictionary where the keys are layer 4 port numbers
               and the values are PKT subclass packet classes. Used by
               app_layer to determine what class should be used to decode
               the payload string or byte array.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'TCP'
        self.pq_type, self.query_fields = TCP.query_info()
        cdef:
            unsigned char use_buffer
        use_buffer, self._buffer = self.from_buffer(args, kwargs)
        self.ws_len = 0
        self._pad = b''

        if use_buffer:
            self.ws_len = len(self._buffer)
            (self.sport, self.dport, self.sequence, self.acknowledgment,
            self._off_flags, self.window, self.checksum, self.urg_ptr) = \
                struct.unpack('!HHIIHHHH', self._buffer[:20])
            if self.data_offset > 5:
                self._options = \
                    bytes(self._buffer[20:(self.data_offset * 4)].tostring())
            else:
                self._options = b''

            self.app_layer(self._buffer[(self.data_offset * 4):])

        else:
            self.sport = kwargs.get('sport', 0)
            self.dport = kwargs.get('dport', 0)
            self.sequence = kwargs.get('sequence', 0)
            self.acknowledgment = kwargs.get('acknowledgment', 0)
            self.data_offset = kwargs.get('data_offset', 5)
            self.flag_ns = kwargs.get('flag_ns', 0)
            self.flag_cwr = kwargs.get('flag_cwr', 0)
            self.flag_ece = kwargs.get('flag_ece', 0)
            self.flag_urg = kwargs.get('flag_urg', 0)
            self.flag_ack = kwargs.get('flag_ack', 0)
            self.flag_psh = kwargs.get('flag_psh', 0)
            self.flag_rst = kwargs.get('flag_rst', 0)
            self.flag_syn = kwargs.get('flag_syn', 0)
            self.flag_fin = kwargs.get('flag_fin', 0)
            self.window = kwargs.get('window', 0)
            self.checksum = kwargs.get('checksum', 0)
            self.urg_ptr = kwargs.get('urg_ptr', 0)
            self.options = kwargs.get('options', b'')
            if kwargs.has_key('payload'):
                if isinstance(kwargs['payload'], PKT):
                   self.payload = kwargs['payload']
                elif isinstance(kwargs['payload'], (bytes)):
                    self.app_layer(kwargs['payload'])
                elif isinstance(kwargs['payload'], (str)):
                    self.app_layer(bytes(kwargs['payload']))
                else:
                    self.payload = PKT()
            else:
                self.payload = PKT()

    @classmethod
    def query_info(cls):
        """
        Provides pcap_query with the query fields UDP supports and TCP's
        PKT type ID.
        :return: tuple of PQTYPES.t_tcp and a tuple of the supported
        field names.
        """
        return (PQTYPES.t_tcp,
                (b'tcp.srcport', b'tcp.dstport', b'tcp.seq', b'tcp.ack',
                 b'tcp.hdr_len', b'tcp.len', b'tcp.flags', b'tcp.flags.urg',
                 b'tcp.flags.ack', b'tcp.flags.push', b'tcp.flags.reset',
                 b'tcp.flags.syn', b'tcp.flags.fin', b'tcp.window_size_value',
                 b'tcp.checksum', b'tcp.urgent_pointer', b'tcp.payload',
                 b'tcp.payload.offset[x:y]'))

    cpdef object get_field_val(self, bytes field):
        """
        Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch. Also handles 
        tcp.payload.offset[x:y] field. 
        :param field: name of the desired field in Wireshark format. For 
               example: arp.proto.type or tcp.flags.urg
        :return: Returns the value of the field as a python object.
        """
        cdef list offsets
        cdef f = field[:18]
        if f == b'tcp.srcport':
            return self.sport
        elif f == b'tcp.dstport':
            return self.dport
        elif f == b'tcp.seq':
            return self.sequence
        elif f == b'tcp.ack':
            return self.acknowledgment
        elif f == b'tcp.hdr_len':
            return self.data_offset
        elif f == b'tcp.len':
            return self.ws_len
        elif f == b'tcp.flags':
            return self.flags
        elif f == b'tcp.flags.urg':
            return self.flag_urg
        elif f == b'tcp.flags.ack':
            return self.flag_ack
        elif f == b'tcp.flags.push':
            return self.flag_psh
        elif f == b'tcp.flags.reset':
            return self.flag_rst
        elif f == b'tcp.flags.syn':
            return self.flag_syn
        elif f == b'tcp.flags.fin':
            return self.flag_fin
        elif f == b'tcp.window_size_va':
            return self.window
        elif f == b'tcp.checksum':
            return self.checksum
        elif f == b'tcp.urgent_pointer':
            return self.urg_ptr
        elif f == b'tcp.payload':
            return self.payload.pkt2net({})
        elif f == b'tcp.payload.offset':
            offsets = (field[19:field.index(']')].split(':'))
            if len(offsets) == 2:
                return self.payload.pkt2net({})[
                       int(offsets[0]):int(offsets[1])
                       ]
            return None
        else:
            return None

    property data_offset:
        # 4 bits
        def __get__(self):
            return get_short_nibble(self._off_flags, 3)
        def __set__(self, unsigned char val):
            if 5 <= val <= 15:
                set_short_nibble(&self._off_flags, val, 3)
            else:
                raise ValueError("data_offset valid values are 5-15")

    property flags:
        # support for wireshark flags field. fin - urg
        def __get__(self):
            return self._off_flags & 0b111111


    property flag_ns:
        def __get__(self):
            return (self._off_flags >> 8) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 8)
            elif val == 0:
                unset_bit(&self._off_flags, 8)
            else:
                raise ValueError("TCP NS bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_cwr:
        def __get__(self):
            return (self._off_flags >> 7) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 7)
            elif val == 0:
                unset_bit(&self._off_flags, 7)
            else:
                raise ValueError("TCP CRW bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_ece:
        def __get__(self):
            return (self._off_flags >> 6) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 6)
            elif val == 0:
                unset_bit(&self._off_flags, 6)
            else:
                raise ValueError("TCP ECE bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_urg:
        def __get__(self):
            return (self._off_flags >> 5) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 5)
            elif val == 0:
                unset_bit(&self._off_flags, 5)
            else:
                raise ValueError("TCP URG bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_ack:
        def __get__(self):
            return (self._off_flags >> 4) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 4)
            elif val == 0:
                unset_bit(&self._off_flags, 4)
            else:
                raise ValueError("TCP ACK bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_psh:
        def __get__(self):
            return (self._off_flags >> 3) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 3)
            elif val == 0:
                unset_bit(&self._off_flags, 3)
            else:
                raise ValueError("TCP PSH bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_rst:
        def __get__(self):
            return (self._off_flags >> 2) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 2)
            elif val == 0:
                unset_bit(&self._off_flags, 2)
            else:
                raise ValueError("TCP RST bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_syn:
        def __get__(self):
            return (self._off_flags >> 1) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 1)
            elif val == 0:
                unset_bit(&self._off_flags, 1)
            else:
                raise ValueError("TCP SYN bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_fin:
        def __get__(self):
            return self._off_flags  & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._off_flags, 0)
            elif val == 0:
                unset_bit(&self._off_flags, 0)
            else:
                raise ValueError("TCP FIN bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property options:
        def __get__(self):
            return self._options
        def __set__(self, bytes val):
            pad_mod = len(val) % 4
            self.data_offset = 5 + len(val) / 4
            if pad_mod:
                self._pad = b'\x00' * (4 - len(val) % 4)
                self.data_offset += 1
            self._options = val

    cpdef bytes pkt2net(self, dict kwargs):
        """
        Used to export a TCP packet class instance in network order 
        for writing to a socket or into a pcap file. 
        :param kwargs: list of arguments defined by PKT sub classes. TCP
               supports the following keyword arguments:
        :param csum: Determines if this TCP instance should re-calculate 
               its checksum.
        :param ipv4_pheader: IPv4 psuedo header used in checksum calculation.
        :return: network order byte string representation of this 
                 TCP instance.
        """
        cdef:
            uint16_t _csum, tcp_len
            unsigned char _update
            Ip4Ph _ipv4_pheader
            bytes _pload_bytes, ip_ph, sport_window

        _csum = kwargs.get('csum', 0)
        _ipv4_pheader = kwargs.get('ipv4_pheader', Ip4Ph())

        _pload_bytes = self.payload.pkt2net(kwargs)

        sport_window = pack('!HHIIHH', self.sport,
                                       self.dport,
                                       self.sequence,
                                       self.acknowledgment,
                                       self._off_flags,
                                       self.window)

        if _csum and isinstance(_ipv4_pheader, Ip4Ph):
            tcp_len = (self.data_offset * 4) + len(_pload_bytes)
            # Note _ipv4_pheader.proto is packed as a short on purpose.
            ip_ph = b'{0}{1}{2}{3}'.format(
                _ipv4_pheader.src,
                _ipv4_pheader.dst,
                pack('!HH', _ipv4_pheader.proto, tcp_len),
                sport_window)
            self.checksum = checksum(b'{0}\000\000{1}{2}{3}{4}'.format(
                ip_ph,
                pack('!H', self.urg_ptr),
                self._options,
                self._pad,
                _pload_bytes))

        return b'{0}{1}{2}{3}{4}'.format(sport_window,
                                         pack('!HH', self.checksum,
                                                     self.urg_ptr),
                                         self._options,
                                         self._pad,
                                         _pload_bytes)

    cdef app_layer(self, array plbuffer):
        """
        Attempts to create an instance of the correct layer 7 protocol
        if the layer 4 ports match. Otherwise returns NullPkt or PKT
        instance.
        :param plbuffer: array of bytes that make up the Layer 7 payload.
        :return: void
        """
        cdef type pkt_cls
        if len(plbuffer):
            if self.dport in self.l7_ports:
                if issubclass(self.l7_ports[self.dport], PKT):
                    pkt_cls = self.l7_ports[self.dport]
                else:
                    pkt_cls = globals()[self.l7_ports[self.dport]]
            elif self.sport in self.l7_ports:
                if issubclass(self.l7_ports[self.sport], PKT):
                    pkt_cls = self.l7_ports[self.sport]
                else:
                    pkt_cls = globals()[self.l7_ports[self.sport]]
            elif 0 in self.l7_ports and len(self.l7_ports) == 1:
                if issubclass(self.l7_ports[self.sport], PKT):
                    pkt_cls = self.l7_ports[0]
                else:
                    pkt_cls = globals()[self.l7_ports[0]]
            else:
                pkt_cls = NullPkt
            self.payload = pkt_cls(plbuffer)
        else:
            self.payload = PKT()


cdef class IP(PKT):
    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize a IP object.
        :param args: Optional one element list containing network order
               bytes of an IP packet
        :param data: Optional keyword argument containing network order
               bytes of an IP packet
        :param version: IP version of this packet. Only 4 is supported.
        :param iphl: Internet Protocol Header Length in 32-bit 'words'.
               Min is 5.
        :param tos: IP type of service. Now primarily used to store DSCP
               values and ECN values. ECN is the low 2 bits.
        :param total_len: The total lenght of the IP packet including the
               header and data.
        :param ident: Primarily used for uniquely identifying the group
               of fragments of a single IP datagram. Used with frag_offset and
               flag_m.
        :param flag_x: Flag bit zero implemented as x bit. See RFC 3514 for
               appropriate use ;-)
        :param flag_d: Don't fragment flag.
        :param flag_m: More fragments flag
        :param frag_offset: This IP packet fragment offset from the
               beginning of the original unfragmented IP datagram measured
               in units of eight-byte blocks.
        :param ttl: The time to live for the IP datagram. Decremented by
               routers as a method to prevent endless circular routes.
        :param checksum: The 16-bit checksum field.
        :param src: IPv4 src address in dot notation (1.1.1.1)
        :param dst: IPv4 dst address in dot notation (1.1.1.2)
        :param payload: The payload of this packet. Payload can be a PKT
               sub class or a byte string.
        :param l7_ports: A dictionary where the keys are layer 4 port numbers
               and the values are PKT subclass packet classes. Used by
               app_layer to determine what class should be used to decode
               the payload string or byte array.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'IP'
        self.pq_type, self.query_fields = IP.query_info()
        cdef:
            unsigned char use_buffer
        self.ipv4_pheader = Ip4Ph()
        use_buffer, self._buffer = self.from_buffer(args, kwargs)

        if use_buffer:
            self._version_iphl = self._buffer[0]
            self.tos = self._buffer[1]
            (self.total_len, self.ident, self._flags_offset) = \
                struct.unpack('!HHH', self._buffer[2:8])
            self.ttl = self._buffer[8]
            self.proto = self._buffer[9]
            self.checksum = struct.unpack('!H', self._buffer[10:12])[0]
            self.src_nochk = self._buffer[12:16]
            self.dst_nochk = self._buffer[16:20]
            if len(self._buffer[(self.iphl * 4):]):
                if self.proto == PROTO.udp:
                    self.payload = UDP(self._buffer[(self.iphl * 4):],
                                       l7_ports = self.l7_ports)
                elif self.proto == PROTO.tcp:
                    self.payload = TCP(self._buffer[(self.iphl * 4):],
                                       l7_ports = self.l7_ports)
                else:
                    self.payload = NullPkt(self._buffer[(self.iphl * 4):],
                                           l7_ports = self.l7_ports)
            else:
                self.payload = PKT()
        else:
            self.version = kwargs.get('version', 4)
            self.iphl = kwargs.get('iphl', 5)
            self.tos = kwargs.get('tos', 0)
            self.total_len = kwargs.get('total_len', 0)
            self.ident = kwargs.get('ident', 0)
            self.flag_x = kwargs.get('flag_x', 0)
            self.flag_d = kwargs.get('flag_d', 0)
            self.flag_m = kwargs.get('flag_m', 0)
            self.frag_offset = kwargs.get('frag_offset', 0)
            self.ttl = kwargs.get('ttl', 64)
            self.proto = kwargs.get('proto', 0)
            self.checksum = kwargs.get('checksum', 0)
            self.src = kwargs.get('src', b'0.0.0.0')
            self.dst = kwargs.get('dst', b'0.0.0.0')
            if (kwargs.has_key('payload') and
                    isinstance(kwargs['payload'], PKT)):
                self.payload = kwargs['payload']
            elif (kwargs.has_key('payload') and
                      isinstance(kwargs['payload'], (str, bytes))):
                if self.proto == PROTO.udp:
                    self.payload = UDP(kwargs['payload'],
                                       l7_ports = self.l7_ports)
                elif self.proto == PROTO.tcp:
                    self.payload = TCP(kwargs['payload'],
                                       l7_ports = self.l7_ports)
                else:
                    self.payload = NullPkt(kwargs['payload'],
                                           l7_ports = self.l7_ports)
            else:
                self.payload = PKT()

    @classmethod
    def query_info(cls):
        """
        Used by pcap_query to determine what query fields this packet type
        supports and what its PKT type ID is.
        The PKT type ID is usually the layer 4 port number for layer 7
        PKT types.
        :return: tuple of PQTYPES.t_ip and a tuple of the supported field
                 names.
        """
        return (PQTYPES.t_ip,
                (b'ip.version', b'ip.hdr_len', b'ip.tos', b'ip.len', b'ip.id',
                 b'ip.flags', b'ip.flags.df', b'ip.flags.mf',
                 b'ip.frag_offset', b'ip.ttl', b'ip.proto', b'ip.src',
                 b'ip.dst', b'ip.checksum'))

    cpdef object get_field_val(self, bytes field):
        """
        Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.
        :param field: name of the desired field in Wireshark format. For 
               example: arp.proto.type or tcp.flags.urg
        :return: Returns the value of the field as a python object.
        """
        if field == b'ip.version':
            return self.version
        elif field == b'ip.hdr_len':
            return self.iphl
        elif field == b'ip.tos':
            return self.tos
        elif field == b'ip.len':
            return self.total_len
        elif field == b'ip.id':
            return self.ident
        elif field == b'ip.flags':
            return self.flags
        elif field == b'ip.flags.df':
            return self.flag_d
        elif field == b'ip.flags.mf':
            return self.flag_m
        elif field == b'ip.frag_offset':
            return self.frag_offset
        elif field == b'ip.ttl':
            return self.ttl
        elif field == b'ip.proto':
            return self.proto
        elif field == b'ip.src':
            return self.src
        elif field == b'ip.dst':
            return self.dst
        elif field == b'ip.checksum':
            return self.checksum
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """
        Used to export a TCP packet class instance in network order 
        for writing to a socket or into a pcap file. 
        :param kwargs: list of arguments defined by PKT sub classes. TCP
               supports the following keyword arguments:
        :param csum: Determines if this IP instance should re-calculate 
               its checksum.
        :param update: Determines if this IP instance and any sub layers
               should update size counters. For IP this means updating the
               total_len variable.
        :param ipv4_pheader: IPv4 psuedo header used in checksum calculation.
        :return: network order byte string representation of this 
                 IP instance.
        """
        cdef:
            unsigned char _csum, _update
            bytes _pload_bytes, ip_ph

        _csum = 0
        _update = 0
        _pload_bytes = b''
        ip_ph = b''

        _csum = kwargs.get('csum', 0)
        _update = kwargs.get('update', 0)
        if isinstance(self.payload, (TCP, UDP)):
            kwargs['ipv4_pheader'] = self.ipv4_pheader
        if isinstance(self.payload, PKT):
            _pload_bytes = self.payload.pkt2net(kwargs)
        else:
            _pload_bytes = b''

        if _update:
            self.total_len = self.iphl * 4 + len(_pload_bytes)

        ip_ph = pack('!BBHHHBB', self._version_iphl,
                                 self.tos,
                                 self.total_len,
                                 self.ident,
                                 self._flags_offset,
                                 self.ttl,
                                 self._proto)

        if _csum:
            self.checksum = checksum(b'{0}\000\000{1}{2}'
                                     b''.format(ip_ph,
                                                self.ipv4_pheader.src,
                                                self.ipv4_pheader.dst)
                                     )

        return bytes("{0}{1}{2}{3}{4}".format(ip_ph,
                                              pack('!H', self.checksum),
                                              self.ipv4_pheader.src,
                                              self.ipv4_pheader.dst,
                                              _pload_bytes))

    property version:
        """ The IP version defined by this packet. """
        def __get__(self):
            """ Return the IP Version. """
            return get_char_nibble(self._version_iphl, 1)
        def __set__(self, unsigned char val):
            """ Set the IP Version. """
            if val in [4,6]:
                set_char_nibble(&self._version_iphl, val, 1)
            else:
                raise ValueError("Only IP versions 4 and 6 supported")

    property iphl:
        """ Number of 32 bit words in the header. Max is 15 (60 bytes). """
        def __get__(self):
            """ Return the number of 32 bit words in the header. """
            return get_char_nibble(self._version_iphl, 0)

        def __set__(self, unsigned char val):
            """ Set the IP header length in 32 bit words. """
            if val <= 0xf:
                set_char_nibble(&self._version_iphl, val, 0)
            else:
                raise ValueError("IP iphl valid values are 0-15")

    property flags:
        # support for wireshark ip.flags field.
        def __get__ (self):
            # return the last 3 bits of _flags_offset
            return get_short_nibble(self._flags_offset, 3) >> 1

    property flag_x:
        """ Set or get the so called evil bit. See RFC 3514. Implemented
        here for fun. """
        def __get__(self):
            return (self._flags_offset >> 15) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._flags_offset, 15)
            elif val == 0:
                unset_bit(&self._flags_offset, 15)
            else:
                raise ValueError("IP Evil bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_d:
        def __get__(self):
            return (self._flags_offset >> 14) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._flags_offset, 14)
            elif val == 0:
                unset_bit(&self._flags_offset, 14)
            else:
                raise ValueError("IP do not fragment bit must be 0 or 1 "
                                 "got: {0}".format(val))

    property flag_m:
        def __get__(self):
            return (self._flags_offset >> 13) & 1
        def __set__(self, unsigned char val):
            if val == 1:
                set_bit(&self._flags_offset, 13)
            elif val == 0:
                unset_bit(&self._flags_offset, 13)
            else:
                raise ValueError("IP more fragments must be 0 or 1 "
                                 "got: {0}".format(val))

    property frag_offset:
        """ Get and set the frag_offset of the datagram. """
        def __get__(self):
            """ Return the frag_offset. """
            return self._flags_offset & 0x1fff
        def __set__(self, uint16_t val):
            """ Set the datagram frag_offset value. """
            if val <= 0x1fff:
                self._flags_offset = (self._flags_offset & ~(0x1fff)) | val
            else:
                raise ValueError("IP frag offset valid values are 0-8191")

    property proto:
        """ Get and set the proto. """
        def __get__(self):
            """ Return the proto. """
            return self._proto
        def __set__(self, unsigned char val):
            """ Set the datagram proto value. """
            self._proto = val
            self.ipv4_pheader.proto = val

    property src_nochk:
        def __set__(self, array val):
            self.ipv4_pheader.src = val.tostring()
            self._src = val

    property src:
        def __get__(self):
            return socket.inet_ntoa(self._src)
        def __set__(self, bytes val):
            cdef bytes t
            if is_ipv4(val):
                t = socket.inet_aton(val)
                self._src = array('B', t)
                self.ipv4_pheader.src = t
            else:
                raise ValueError("src must be a dot notation "
                                 "IPv4 string. (1.1.1.1)")
    property dst_nochk:
        def __set__(self, array val):
            self.ipv4_pheader.dst = val.tostring()
            self._dst = val

    property dst:
        def __get__(self):
            return socket.inet_ntoa(self._dst)
        def __set__(self, bytes val):
            cdef bytes t
            if is_ipv4(val):
                t = socket.inet_aton(val)
                self._dst = array('B', t)
                self.ipv4_pheader.dst = t
            else:
                raise ValueError("dst must be a dot notation "
                                 "IPv4 string. (1.1.1.1)")


cdef class MPLS(PKT):
    """ 
    Very limited implementation of MPLS (RFC 3031). Supports only IPv4 and
    Ethernet payloads. And only detects the difference by looking at the
    first nibble of the payload bytes.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize a MPLS object.
        :param args: Optional one element list containing network order
               bytes of an MPLS packet
        :param data: Optional keyword argument containing network order
               bytes of an MPLS packet
        :param label: 20 bit MPLS label value.
        :param tc: Traffic Class (QoS and ECN).
        :param s: Bottom of label stack bit.
        :param ttl: Time to live for this label.
        :param payload: The payload of this packet. Payload can be a PKT
               sub class or a byte string.
        :param l7_ports: A dictionary where the keys are layer 4 port numbers
               and the values are PKT subclass packet classes. Used by
               app_layer to determine what class should be used to decode
               the payload string or byte array.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'MPLS'
        self.pq_type, self.query_fields = MPLS.query_info()
        cdef:
            unsigned char use_buffer
        use_buffer, self._buffer = self.from_buffer(args, kwargs)

        if use_buffer:
            self._data = struct.unpack('!I', self._buffer[:4])[0]
            if self.s and self._buffer[4:]:
                if self._buffer[4] >> 4 == 4:
                    # NEED TO DO BETTER MPLS FIX
                    self.payload = IP(self._buffer[4:],
                                      l7_ports = self.l7_ports)
                else:
                    self.payload = Ethernet(self._buffer[4:],
                                            l7_ports = self.l7_ports)
            elif self._buffer[4:]:
                self.payload = MPLS(self._buffer[4:],
                                    l7_ports = self.l7_ports)
            else:
                self.payload = NullPkt()
        else:
            self._data = 0
            self.label = kwargs.get('label', 0)
            self.tc = kwargs.get('tc', 0)
            self.s = kwargs.get('s', 1)
            self.ttl = kwargs.get('ttl', 0)
            if (kwargs.has_key('payload') and
                    isinstance(kwargs['payload'], PKT)):
                self.payload = kwargs['payload']
            elif (kwargs.has_key('payload') and
                      isinstance(kwargs['payload'], (str, bytes, array))):
                if self.s:
                    if isinstance(kwargs['payload'], (str, bytes)):
                        kwargs['payload'] = array('B', kwargs['payload'])
                    if kwargs['payload'][0] >> 4 == 4:
                        self.payload = IP(kwargs['payload'],
                                          l7_ports = self.l7_ports)
                    else:
                        self.payload = Ethernet(kwargs['payload'],
                                                l7_ports = self.l7_ports)
                else:
                    self.payload = MPLS(kwargs['payload'],
                                        l7_ports = self.l7_ports)
            else:
                self.payload = NullPkt(b'')

    @classmethod
    def query_info(cls):
        """
        Provides pcap_query with the query fields UDP supports and UDP's
        PKT type ID.
        :return: tuple of PQTYPES.t_mpls and a tuple of the supported
        field names.
        """
        return (PQTYPES.t_mpls,
                (b'mpls.bottom.label', b'mpls.bottom.tc',
                 b'mpls.bottom.stack_bit', b'mpls.bottom.ttl',
                 b'mpls.top.label', b'mpls.top.tc',
                 b'mpls.top.stack_bit', b'mpls.top.ttl'))

    cpdef get_field_val(self, bytes field):
        """
        Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.
        :param field: name of the desired field in Wireshark format. For 
               example: arp.proto.type or tcp.flags.urg
        :return: Returns the value of the field as a python object.
        """
        if field.find('.bottom.') >= 0 and self.s:
            if field == b'mpls.bottom.label':
                return self.label
            elif field == b'mpls.bottom.tc':
                return self.tc
            elif field == b'mpls.bottom.stack_bit':
                return self.s
            elif field == b'mpls.bottom.ttl':
                return self.ttl
            else:
                return None
        elif field.find('.top.') >= 0 and not self.s:
            if field == b'mpls.top.label':
                return self.label
            elif field == b'mpls.top.tc':
                return self.tc
            elif field == b'mpls.top.stack_bit':
                return self.s
            elif field == b'mpls.top.ttl':
                return self.ttl
            else:
                return None
        else:
            return self.payload.get_field_val(field)

    property label:
        """ The label value. """
        def __get__(self):
            """ Return the label value. """
            return self._data >> 12
        def __set__(self, uint32_t val):
            """ Set the label value. """
            if val <= 0xfffff:
                self._data = (self._data & ~(0xfffff << 12)) | (val << 12)
            else:
                raise ValueError("label valid values are 0-1048575")

    property tc:
        """ The Traffic Class. """
        def __get__(self):
            """ Return the traffic class value. """
            return (self._data >> 12) & 0b111
        def __set__(self, unsigned char val):
            """ Set the traffic class value. """
            if val <= 0b111:
                self._data = (self._data & ~(0b111 << 9)) | (val << 9)
            else:
                raise ValueError("MPLS TC valid values are 0-7")

    property s:
        """ Set or get the stack bit. """
        def __get__(self):
            """ Return the stack bit. """
            return (self._data >> 8) & 1
        def __set__(self, unsigned char val):
            """ Set the stack bit. """
            if val == 1:
                set_word_bit(&self._data, 8)
            elif val == 0:
                unset_word_bit(&self._data, 8)
            else:
                raise ValueError("Bottom of stack bit must be 0 or 1")

    property ttl:
        """ Set or get ttl value. """
        def __get__(self):
            """ Return the TTL. """
            return self._data & 0xff
        def __set__(self, unsigned char val):
            """ Set the TTL. """
            self._data = (self._data & ~0xff) | val


    cpdef bytes pkt2net(self, dict kwargs):
        """
        Used to export a MPLS packet class instance in network order 
        for writing to a socket or into a pcap file. 
        :param kwargs: list of arguments defined by PKT sub classes. Passed
               along by MPLS to payload classes. MPLS has no options
               that it directly supports.
        :return: network order byte string representation of this 
                 IP instance.
        """
        cdef:
            bytes _pload_bytes

        _pload_bytes = b''

        if isinstance(self.payload, PKT):
            _pload_bytes = self.payload.pkt2net(kwargs)
        else:
            _pload_bytes = b''

        return bytes("{0}{1}".format(pack('!I', self._data),
                                     _pload_bytes))


cdef class Ethernet(PKT):
    """
    Implements Ethernet II frame without CRC.
    """
    def __init__(self, *args, **kwargs):\

        """
        Initialize a Ethernet II object.
        :param args: Optional one element list containing network order
               bytes of an Ethernet packet
        :param data: Optional keyword argument containing network order
               bytes of an Ethernet packet
        :param src_mac: Layer 2 source address in colon notation. For example
               the layer 2 broadcast MAC would be 'ff:ff:ff:ff:ff:ff'
        :param dst_mac: Layer 2 destination address in colon notation.
        :param type: EtherType of the payload. Common values are 0x0800 for
               IPv4 and 0x0806 for ARP.
        :param payload: The payload of this packet. Payload can be a PKT
               sub class or a byte string.
        :param l7_ports: A dictionary where the keys are layer 4 port numbers
               and the values are PKT subclass packet classes. Used by
               app_layer to determine what class should be used to decode
               the payload string or byte array.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'Ethernet'
        self.pq_type, self.query_fields = Ethernet.query_info()
        cdef unsigned char use_buffer
        use_buffer, self._buffer = self.from_buffer(args, kwargs)

        if use_buffer:
            self._dst_mac = self._buffer[:6]
            self._src_mac = self._buffer[6:12]
            self.type = struct.unpack('!H', self._buffer[12:14])[0]
            if self.type == ETHERTYPES.ipv4:
                self.payload = IP(self._buffer[14:],
                                  l7_ports = self.l7_ports)
            elif self.type == ETHERTYPES.arp:
                self.payload = ARP(self._buffer[14:])
            elif self.type in (ETHERTYPES.mpls_unicast,
                               ETHERTYPES.mpls_multicast):
                self.payload = MPLS(self._buffer[14:])
            else:
                self.payload = NullPkt(self._buffer[14:])
        else:
            self.src_mac = kwargs.get('src_mac', b'00:00:00:00:00:00')
            self.dst_mac = kwargs.get('dst_mac', b'00:00:00:00:00:00')
            self.type = kwargs.get('type', ETHERTYPES.ipv4)
            self.payload = kwargs.get('payload', PKT())

    @classmethod
    def query_info(cls):
        """
        Provides pcap_query with the query fields UDP supports and UDP's
        PKT type ID.
        :return: tuple of PQTYPES.t_eth and a tuple of the supported
        field names.
        """
        return (PQTYPES.t_eth,
                (b'eth.type', b'eth.src', 'eth.dst'))

    cpdef object get_field_val(self, bytes field):
        """
        Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.
        :param field: name of the desired field in Wireshark format. For 
               example: arp.proto.type or tcp.flags.urg
        :return: Returns the value of the field as a python object.
        """
        if field == b'eth.type':
            return self.type
        elif field == b'eth.src':
            return self.src_mac
        elif field == b'eth.dst':
            return self.dst_mac
        else:
            return None

    property src_mac:
        def __get__(self):
            return ':'.join(format(x, '02x') for x in self._src_mac)
        def __set__(self, bytes val):
            self._src_mac = array('B',
                                  (int(x, 16) for x in val.split(':')))

    property dst_mac:
        def __get__(self):
            return ':'.join(format(x, '02x') for x in self._dst_mac)
        def __set__(self, bytes val):
            self._dst_mac = array('B',
                                  (int(x, 16) for x in val.split(':')))

    cpdef bytes pkt2net(self, dict kwargs):
        """
        Used to export a Ethernet packet class instance in network order 
        for writing to a socket or into a pcap file. 
        :param kwargs: list of arguments defined by PKT sub classes. Passed
               along by Ethernet to payload classes. Ethernet has no options
               that it directly supports.
        :return: network order byte string representation of this 
                 IP instance.
        """
        cdef:
            bytes _pload_bytes
        _pload_bytes = b''

        if isinstance(self.payload, PKT):
            _pload_bytes = self.payload.pkt2net(kwargs)
        return b'{0}{1}{2}{3}'.format(self._dst_mac.tostring(),
                                      self._src_mac.tostring(),
                                      pack('!H', self.type),
                                      _pload_bytes)

