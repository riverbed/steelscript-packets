# cython: profile=False

# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from struct import pack, unpack
from cpython.array cimport array
import binascii
import socket
import re

from libc.stdint cimport uint32_t, uint16_t

offset_re = re.compile(r'^(udp|tcp)\.payload\.offset\[(\d*):(\d*)\]$')

IPV4_LEN = 4
IPV4_VER = 4
IPV4_MIN_HDR_LEN = 5
IPV6_LEN = 8
IPV6_VER = 6
MAC_LEN = 6
ARP_TYPE_ETH = 1
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2
ARP_OP_RARP_REQUEST = 3
ARP_OP_RARP_REPLY = 4
ARP_OP_DYN_RARP_REQUEST = 5
ARP_OP_DYN_RARP_REPLY = 6
ARP_OP_DYN_RARP_ERR = 7
ARP_OP_INV_REQUEST = 8
ARP_OP_INV_REPLY = 9
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_ARP = 0x0806
ETH_TYPE_RARP = 0x8035
ETH_TYPE_8021Q = 0x8100
ETH_TYPE_IPV6 = 0x86dd
ETH_TYPE_MPLS_UCAST = 0x8847
ETH_TYPE_MPLS_MCAST = 0x8848
ICMP_TYPE_ECHO_REPLY = 0
ICMP_TYPE_DU = 3
ICMP_TYPE_SRC_QUENCH = 4
ICMP_TYPE_REDIR = 5
ICMP_TYPE_ECHO = 8
ICMP_TYPE_TIME_EX = 11
ICMP_TYPE_PER_PROB = 12
ICMP_TYPE_TS = 13
ICMP_TYPE_TS_REPLY = 14
ICMP_TYPE_INFO = 15
ICMP_TYPE_INFO_REPLY = 16
ICMP_DU_CODE_NET_UNREACH = 0
ICMP_DU_CODE_HOST_UNREACH = 1
ICMP_DU_CODE_PROTO_UNREACH = 2
ICMP_DU_CODE_PORT_UNREACH = 3
ICMP_DU_CODE_FRAG_NEEDED = 4
ICMP_DU_CODE_SRC_RT_FAIL = 5
ICMP_DU_CODE_DEST_NET_UNKNOWN = 6
ICMP_DU_CODE_DEST_HOST_UNKNOWN = 7
ICMP_DU_CODE_SRC_HOST_ISOLATED = 8
ICMP_DU_CODE_NET_ADMIN_PROHIBIT = 9
ICMP_DU_CODE_HOST_ADMIN_PROHIBIT = 10
ICMP_DU_CODE_NET_TOS_UNREACH = 11
ICMP_DU_CODE_HOST_TOS_UNREACH = 12
ICMP_DU_CODE_COMMS_ADMIN_PROHIBIT = 13
ICMP_DU_CODE_HOST_PRECEDENCE = 14
ICMP_DU_CODE_PRECEDENCE_CUTOFF = 15
ICMP_REDIR_CODE_NET = 0
ICMP_REDIR_CODE_HOST = 1
ICMP_REDIR_CODE_NET_TOS = 2
ICMP_REDIR_CODE_HOST_TOS = 3
ICMP_TIME_EX_CODE_TTL_EXCEEDED = 0
ICMP_TIME_EX_CODE_FRAG_EXCEEDED = 1
ICMP_PER_PROB_CODE_POINTER = 0
ICMP_PER_PROB_CODE_OPTION_MISSING = 1
ICMP_PER_PROB_CODE_LENGTH = 2
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PQ_PKT = 0
PQ_ETH = 1
PQ_FRAME = 2
PQ_ICMP = 3
PQ_IP = 0x0800
PQ_TCP = 6
PQ_UDP = 17
PQ_ARP = 0x0806
PQ_MPLS = 0x8847
PQ_NETFLOW_SIMPLE = 2005
PQ_NULLPKT = 0xffff
PTR_VAL = 0
NOT_FOUND = -1

cdef class IP_CONST:
    def __cinit__(self):
        self.IPV4_LEN = IPV4_LEN
        self.IPV4_VER = IPV4_VER
        self.IPV4_MIN_HDR_LEN = IPV4_MIN_HDR_LEN
        self.IPV6_LEN = IPV6_LEN
        self.IPV6_VER = IPV6_VER
        self.MAC_LEN = MAC_LEN
        self.ARP_TYPE_ETH = ARP_TYPE_ETH
        self.ARP_OP_REQUEST = ARP_OP_REQUEST
        self.ARP_OP_REPLY = ARP_OP_REPLY
        self.ARP_OP_RARP_REQUEST = ARP_OP_RARP_REQUEST
        self.ARP_OP_RARP_REPLY = ARP_OP_RARP_REPLY
        self.ARP_OP_DYN_RARP_REQUEST = ARP_OP_DYN_RARP_REQUEST
        self.ARP_OP_DYN_RARP_REPLY = ARP_OP_DYN_RARP_REPLY
        self.ARP_OP_DYN_RARP_ERR = ARP_OP_DYN_RARP_ERR
        self.ARP_OP_INV_REQUEST = ARP_OP_INV_REQUEST
        self.ARP_OP_INV_REPLY = ARP_OP_INV_REPLY
        self.ETH_TYPE_IPV4 = ETH_TYPE_IPV4
        self.ETH_TYPE_ARP = ETH_TYPE_ARP
        self.ETH_TYPE_RARP = ETH_TYPE_RARP
        self.ETH_TYPE_8021Q = ETH_TYPE_8021Q
        self.ETH_TYPE_IPV6 = ETH_TYPE_IPV6
        self.ETH_TYPE_MPLS_UCAST = ETH_TYPE_MPLS_UCAST
        self.ETH_TYPE_MPLS_MCAST = ETH_TYPE_MPLS_MCAST
        self.ICMP_TYPE_ECHO_REPLY = ICMP_TYPE_ECHO_REPLY
        self.ICMP_TYPE_DU = ICMP_TYPE_DU
        self.ICMP_TYPE_SRC_QUENCH = ICMP_TYPE_SRC_QUENCH
        self.ICMP_TYPE_REDIR = ICMP_TYPE_SRC_QUENCH
        self.ICMP_TYPE_ECHO = ICMP_TYPE_ECHO
        self.ICMP_TYPE_TIME_EX = ICMP_TYPE_TIME_EX
        self.ICMP_TYPE_PER_PROB = ICMP_TYPE_PER_PROB
        self.ICMP_TYPE_TS = ICMP_TYPE_TS
        self.ICMP_TYPE_TS_REPLY = ICMP_TYPE_TS_REPLY
        self.ICMP_TYPE_INFO = ICMP_TYPE_INFO
        self.ICMP_TYPE_INFO_REPLY = ICMP_TYPE_INFO_REPLY
        self.ICMP_DU_CODE_NET_UNREACH = ICMP_DU_CODE_NET_UNREACH
        self.ICMP_DU_CODE_HOST_UNREACH = ICMP_DU_CODE_HOST_UNREACH
        self.ICMP_DU_CODE_PROTO_UNREACH = ICMP_DU_CODE_PROTO_UNREACH
        self.ICMP_DU_CODE_PORT_UNREACH = ICMP_DU_CODE_PORT_UNREACH
        self.ICMP_DU_CODE_FRAG_NEEDED = ICMP_DU_CODE_FRAG_NEEDED
        self.ICMP_DU_CODE_SRC_RT_FAIL = ICMP_DU_CODE_SRC_RT_FAIL
        self.ICMP_DU_CODE_DEST_NET_UNKNOWN = ICMP_DU_CODE_DEST_NET_UNKNOWN
        self.ICMP_DU_CODE_DEST_HOST_UNKNOWN = \
            ICMP_DU_CODE_DEST_HOST_UNKNOWN
        self.ICMP_DU_CODE_SRC_HOST_ISOLATED = \
            ICMP_DU_CODE_SRC_HOST_ISOLATED
        self.ICMP_DU_CODE_NET_ADMIN_PROHIBIT = \
            ICMP_DU_CODE_NET_ADMIN_PROHIBIT
        self.ICMP_DU_CODE_HOST_ADMIN_PROHIBIT = \
            ICMP_DU_CODE_HOST_ADMIN_PROHIBIT
        self.ICMP_DU_CODE_NET_TOS_UNREACH = ICMP_DU_CODE_NET_TOS_UNREACH
        self.ICMP_DU_CODE_HOST_TOS_UNREACH = ICMP_DU_CODE_HOST_TOS_UNREACH
        self.ICMP_DU_CODE_COMMS_ADMIN_PROHIBIT = \
            ICMP_DU_CODE_COMMS_ADMIN_PROHIBIT
        self.ICMP_DU_CODE_HOST_PRECEDENCE = ICMP_DU_CODE_HOST_PRECEDENCE
        self.ICMP_DU_CODE_PRECEDENCE_CUTOFF = \
            ICMP_DU_CODE_PRECEDENCE_CUTOFF
        self.ICMP_REDIR_CODE_NET = ICMP_REDIR_CODE_NET
        self.ICMP_REDIR_CODE_HOST = ICMP_REDIR_CODE_HOST
        self.ICMP_REDIR_CODE_NET_TOS = ICMP_REDIR_CODE_NET_TOS
        self.ICMP_REDIR_CODE_HOST_TOS = ICMP_REDIR_CODE_HOST_TOS
        self.ICMP_TIME_EX_CODE_TTL_EXCEEDED = \
            ICMP_TIME_EX_CODE_TTL_EXCEEDED
        self.ICMP_TIME_EX_CODE_FRAG_EXCEEDED = \
            ICMP_TIME_EX_CODE_FRAG_EXCEEDED
        self.ICMP_PER_PROB_CODE_POINTER = ICMP_PER_PROB_CODE_POINTER
        self.ICMP_PER_PROB_CODE_OPTION_MISSING = \
            ICMP_PER_PROB_CODE_OPTION_MISSING
        self.ICMP_PER_PROB_CODE_LENGTH = ICMP_PER_PROB_CODE_LENGTH
        self.PROTO_ICMP = PROTO_ICMP
        self.PROTO_TCP = PROTO_TCP
        self.PROTO_UDP = PROTO_UDP
        self.PQ_PKT = PQ_PKT
        self.PQ_ETH = PQ_ETH
        self.PQ_FRAME = PQ_FRAME
        self.PQ_ICMP = PQ_ICMP
        self.PQ_IP = PQ_IP
        self.PQ_TCP = PQ_TCP
        self.PQ_UDP = PQ_UDP
        self.PQ_ARP = PQ_ARP
        self.PQ_MPLS = PQ_MPLS
        self.PQ_NETFLOW_SIMPLE = PQ_NETFLOW_SIMPLE
        self.PQ_NULLPKT = PQ_NULLPKT


cdef uint16_t checksum(bytes pkt):
    """16-bit one's complement of the one's complement sum bytes string. The
    bytes are padded if necessary to make align it to 16 bits.

    Args:
        :pkt (bytes): a byte string representing the packet data to be 
            checksummed.

    Returns: 
        uint16_t: 16 bit checksum value.
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
                           unsigned char offset):
    """
    Set the value of a 4 bit nibble in a 16 bit short.
    :param short_word: Pointer to the short to set.
    :param nibble: 4 bit value to set.
    :param offset: 0-15 the offset of the nibble in bits
    :return: void
    """
    short_word[PTR_VAL] = \
        (short_word[PTR_VAL] & ~(0xf << offset)) | (nibble << offset)


cdef void set_char_nibble(unsigned char* char_word,
                          unsigned char nibble,
                          unsigned char offset):
    """
    Set the value of a 4 bit nibble in a 8 bit char.
    :param short_word: Pointer to the char to set.
    :param nibble: 4 bit value to set.
    :param offset: 0-7 the offset of the nibble in bits
    :return: void
    """
    char_word[PTR_VAL] =  \
        (char_word[PTR_VAL] & ~(0xf << offset)) | (nibble << offset)


cdef uint16_t get_short_nibble(uint16_t short_word, unsigned char offset):
    """
    Get 4 bit value from a 16 bit short.
    :param short_word: unsigned short value to get a nibble from.
    :param offset: 0-15 the offset of the nibble in bits
    :return: unsigned short containing value of nibble.
    """
    return (short_word >> offset) & 0xF


cdef unsigned char get_char_nibble(unsigned char char_word,
                                   unsigned char offset):
    """
    Get 4 bit value from a 8 bit char.
    :param char_word: unsigned char value to get a nibble from.
    :param offset: 0-7 the offset of the nibble in bits
    :return: unsigned char containing value of nibble.
    """
    return (char_word >> offset) & 0xF


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
    def __init__(self, *args, **kwargs):
        """Initialize a PKT object

        Args:
            :args (list): pass through to sub classes.
            :kwargs (dict): pass through to sub classes excepting 'l7_ports'.
            :l7_ports (dict): A dictionary of <port>: <class>. Used by
                sub classes like TCP and UDP to determine what class to use in
                decoding their payload.

        """
        self.pkt_name = b'PKT'
        self.pq_type, self.query_fields = PKT.query_info()
        if 'l7_ports' in kwargs and isinstance(kwargs['l7_ports'], dict):
            self.l7_ports = kwargs['l7_ports']
        else:
            self.l7_ports = {}

    @classmethod
    def query_info(cls):
        """ Used by pcap_query to determine what query fields this packet type
        supports and what its PKT type ID is. The PKT type ID is usually the
        layer 4 port number for layer 7 PKT types.

        Returns:
            :tuple: Consisting of PKT type and a tuple of the supported field
                names.
        """
        return (PQ_PKT,
                ())

    @classmethod
    def default_ports(cls):
        """Used by pcap_query to automatically decode layer 7 protocols.

        Returns:
            :list: list of layer 4 ports for 'this' protocol.
        """
        return []

    cpdef object get_field_val(self, bytes field):
        return None

    cpdef PKT get_layer(self, bytes name, int instance=1, int found=0):
        """Used to get sub 'layers' of a PKT class based on the name of the
        desired layer.

        Args:
            :name (bytes): Class name of the desired layer ('IP', 'UDP', ...)
            :instance (int): The Nth instance of the class you want. 
                Useful for PKT types that can exist multiple times in a single 
                packet. Examples include MPLS or Ethernet.
            :found (int): Used in recursive calls to get_layer when instance 
                is > 1

        Returns:
            PKT: The PKT instance OR an empty NullPkt instance if not found.

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
        """Used to get sub 'layers' of a PKT class based on the PKT type ID 
        of the desired layer.

        Args:
            :pq_type (uint16_t): Class type ID of the desired layer. For 
                example PQTYPES.t_ip, PQTYPES.t_udp, ...
            :instance (int): The Nth instance of the class you want. Useful for
                   PKT types that can exist multiple times in a single packet.
                   Examples include MPLS or Ethernet.
            :found (int): Used in recursive calls to get_layer when instance 
                is > 1
        Returns: 
            :PKT: The PKT instance OR an empty NullPkt instance if not found.

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
        """Used to export a PKT based packet class in network order for writing
        to a socket or into a pcap file.

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes.
        Returns: 
            :bytes: network order byte string representation of the PKT 
                instance.
        """

        return b''

    cpdef tuple from_buffer(self, tuple args, dict kwargs):
        """Used to determine if the instance is being initialized from data or
        from keyword arguments. If args[0] is an array, bytes, or a string OR
        if a 'data' keyword argument is then the PKT instance is initialized
        from an array of Unsigned chars.

        Args:
            :args (list): array of initialization arguments 
            :kwargs (dict): dictionary of keyword arguments

        Returns: 
            :tuple: First element contains 1 or 0 specifying if the instance
                is or is not initializing from data. The second element of the
                tuple contains the data as an array of unsigned chars if data
                is present. Otherwise an empty array.
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

    def __init__(self, *args, **kwargs):
        """Initialize an ARP object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an ARP packet
            :data (bytes or array.arry): Optional keyword argument containing
                network order bytes of an ARP packet
            :hardware_type (uint16_t): Network Protocol Type. For example:
                Ethernet is hardware_type 1.
            :proto_type (uint16_t): Network protocol for this ARP request. For
                example this field would be set to 0x800 if this is a IPv4 ARP.
                Valid values for this field are shared with the IEEE 802.3
                EtherType specification used by Ethernet.
            :hardware_len (unsigned char): Length in bytes (octets) for the
                hardware type specified in hardware_type above.
            :proto_len (unsigned char): Length in octets for the proto_type
                specified above. IPv4 has a length of 4 for example.
            :operation (unsigned char): 1 for request and 2 for response.
            :sender_hw_addr (bytes): bytes representation of the senders
                hardware address. For example with hardware_type 1 this would
                be: 'xx:xx:xx:xx:xx:xx'
            :sender_proto_addr (bytes): bytes representation of the senders
                hardware address. For example with proto_type 0x800 this would
                be 'xxx.xxx.xxx.xxx'
            :target_hw_addr (bytes): bytes representation of the targets
                hardware address.
            :target_proto_addr (bytes): bytes representation of the targets
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
                unpack('!HHBBH', self._buffer[:8])
            if(self.hardware_type == ARP_TYPE_ETH and
                       self.proto_type == ETH_TYPE_IPV4 and
                       self.proto_len == IPV4_LEN):
                self.sender_hw_addr = bytes(':'.join('%02x'%i for i in
                                unpack("!6B",self._buffer[8:14])))
                self.sender_proto_addr = socket.inet_ntoa(self._buffer[14:18])
                self.target_hw_addr = bytes(':'.join('%02x'%i for i in
                                unpack("!6B",self._buffer[18:24])))
                self.target_proto_addr = socket.inet_ntoa(self._buffer[24:28])
            else:
                s_proto_start = 8 + self.hardware_len
                t_hw_start = s_proto_start + self.proto_len
                t_proto_start = t_hw_start + self.hardware_len
                t_proto_end = t_proto_start + self.proto_len
                h_u = "!{0}B".format(self.hardware_len)
                p_u = "!{0}B".format(self.proto_len)
                self.sender_hw_addr = \
                    bytes(''.join('%02x'%i for i in unpack(h_u,
                        self._buffer[8:s_proto_start])))
                self.sender_proto_addr = \
                    bytes(''.join('%02x'%i for i in unpack(p_u,
                        self._buffer[s_proto_start:t_hw_start])))
                self.taget_hw_addr = \
                    bytes(''.join('%02x'%i for i in unpack(h_u,
                        self._buffer[t_hw_start:t_proto_start])))
                self.taget_proto_addr = \
                    bytes(''.join('%02x'%i for i in unpack(p_u,
                        self._buffer[t_proto_start:t_proto_end])))
        else:
            self.hardware_type = kwargs.get('hardware_type',
                                            ARP_TYPE_ETH)
            self.proto_type = kwargs.get('proto_type', ETH_TYPE_IPV4)
            self.hardware_len = kwargs.get('hardware_len',MAC_LEN)
            self.proto_len = kwargs.get('proto_len', IPV4_LEN)
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
        """classmethod - provides pcap_query with the query fields ARP
        supports and ARP's PKT type ID.

        Returns:
            :tuple: 2 elements: PQTYPES.t_arp and a tuple of the supported
                field names.
        """
        return (ETH_TYPE_ARP,
                (b'arp.hw.type', b'arp.proto.type', b'arp.hw.size',
                 b'arp.proto.size', b'arp.opcode', 'arp.src.hw_mac',
                 b'arp.src.proto_ipv4', b'arp.dst.hw_mac',
                 b'arp.dst.proto_ipv4'))

    cpdef object get_field_val(self, bytes field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
        """
        if field == b'arp.hw.type':
            return self.hardware_type
        elif field == b'arp.proto.type':
            return self.proto_type
        elif field == b'arp.hw.size':
            return self.hardware_len
        elif field == b'arp.proto.size':
            return self.proto_len
        elif field == b'arp.opcode':
            return self.operation
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

            Returns:
                :uint16_t: current operation value.
            """
            return self._operation
        def __set__(self, uint16_t val):
            """
            Set ARP.operation

            Args:
            :val (uint16_t): unsigned char value to set operation to. Supported
                values are 1 - 9.

            """
            if 1 <= val <= 9:
                self._operation = val
            else:
                raise ValueError("Valid operation codes are 1 - 9. Common "
                                 "values are 1 for request and 2 for reply.")

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a ARP packet class instance in network order for 
        writing to a socket or into a pcap file. At present this function
        only works Ethernet/IPv4 ARP packets OR if buffer was set. If this is 
        not a self.hardware_type == ARP_CONST.hwt_ether, 
        self.proto_type == ETHERTYPES.ipv4 packet BUT buffer is set then the 
        packet in will simply be repeated from the buffer. Any changes are 
        lost.

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. ARP
                does not support any key work arguments and does not have a 
                payload so any args passed will be ignored.
        Returns: 
            :bytes: network order byte string representation of the ARP 
                instance.
        """
        cdef:
            bytes sndr, trgt, pair
        sndr = trgt = b''

        if(self.hardware_type == ARP_TYPE_ETH and
               self.proto_type == ETH_TYPE_IPV4 and
               self.proto_len == IPV4_LEN):
            for pair in self.sender_hw_addr.split(':'):
                sndr += binascii.unhexlify(pair)
            for pair in self.target_hw_addr.split(':'):
                trgt += binascii.unhexlify(pair)
            return b'{0}{1}{2}{3}{4}'.format(
                pack('!HHBBH', self.hardware_type,
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
        """ Initialize an NullPkt object.

        Args:
        :args (list): Optional one element list containing network order bytes
            of an ARP packet
        :data (bytes): Optional keyword argument containing network order bytes
            of an ARP packet
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
        """pseudo pcap_query support for query_info.

        Returns:
            :tuple: PQTYPES.t_nullpkt and an empty field list
        """
        return (PQ_NULLPKT,
                ())

    def __repr__(self):
        return "{0}: {1}".format(self.pkt_name, self.payload)

    cpdef object get_field_val(self, bytes field):
        """
        pseudo pcap_query support for get_field_val.
        """
        return None

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a NullPkt object for writing to a socket or into 
        a pcap file. Data is exactly as it came in.

        Args:
            :kwargs (dict): Ignored

        Returns:
            :bytes: The NullPkt data exactly as it came into __init__
        """
        return b'{0}'.format(self.payload)


cdef class Ip4Ph:
    """
    Class to encapsulate an IPv4 pseudo header. Used in pkt2net functions
    for TCP and UDP. Part of checksum calculation. Automatically passed in
    to pkt2net by IP if its payload is TCP or UDP
    """

    def __init__(self, **kwargs):
        """Initialize a new Ip4Ph object. Actual initialization is done by the
        classes Cython __cinit__ function. __init__ exists to support
        documentation generation.

        Args:
            :src (bytes): IPv4 src address for parent IP Object
            :dst (bytes ): IPv4 dst address for parent IP Object
            :reserved (unsigned char): unused 8 bits in pseudo header. Should
                be 0
            :proto (unsigned char): Proto of parent IP object.
            :payload_len (uint16_t): Total length of IP payload in octets.

        """

    def __cinit__(self, **kwargs):
        """The real C level init function for Ip4Ph. __init__ above is only
        for documentation.
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
        """Initialize a NetflowSimple object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an ARP packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an ARP packet
            :version (uint16_t): Netflow version (1-9)
            :count (uint16_t): Count of records if version is 1-8 or count of
                flow sets if version is 9
            :sys_uptime (uint32_t): Current time in milliseconds since the
                export device started at the moment the netflow packet was
                sent.
            :unix_secs (uint32_t): Seconds since the start of the epoch
            :unix_nano_seconds (uint32_t): nanoseconds remaining from
                unix_secs. This field will not be correct IF the version is 9
            :payload (bytes): The rest of the netflow packet as bytes.
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
                unpack('!HHIII', self._buffer[:16])

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
        """classmethod - provides pcap_query with the query fields
        NetflowSimple supports and NetflowSimple's PKT type ID.

        Returns:
            :tuple: PQTYPES.t_netflow_simple and a tuple of the supported
            field names.
        """
        return (PQ_NETFLOW_SIMPLE,
                (b'netflow.version', b'netflow.count', b'netflow.sys_uptime',
                 b'netflow.unix_secs', b'netflow.unix_nano_seconds'))

    @classmethod
    def default_ports(cls):
        """
        Used by pcap_query to automatically decode layer 7 protocols.
        The default Layer 4 ports for netflow are 2005 and 2055.

        Returns:
            :list: layer 4 ports for NetflowSimple.
        """
        return [2005, 2055]

    cpdef object get_field_val(self, bytes field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
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
        """Used to export a NetflowSimple packet class instance in network 
        order for writing to a socket or into a pcap file.

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                NetflowSimple does not support any key work arguments and 
                does not have a PKT class payload so any args passed will 
                be ignored.
        Returns: 
            :bytes: network order byte string representation of the 
                NetflowSimple instance.
        """
        return b'{0}{1}'.format(pack("!HHIII", self.version,
                                               self.count,
                                               self.sys_uptime,
                                               self.unix_secs,
                                               self.unix_nano_seconds),
                                self.payload)


cdef class UDP(PKT):
    def __init__(self, *args, **kwargs):
        """Initialize a UDP object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an UDP packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an UDP packet
            :sport (uint16_t): Layer 4 source port of this packet
            :dport (uint16_t): Layer 4 destination port of this packet
            :ulen (uint16_t): UDP Length - Total length of the UDP header plus
                data in bytes
            :checksum (uint16_t): The checksum value for this packet. Optional
                with IPv4 and must be 0 if not used.
            :payload (PKT or bytes): The payload of this packet.
            :l7_ports: A dictionary where the keys are layer 4 port numbers
                   and the values are PKT subclass packet classes. Used by
                   UDP.app_layer() to determine what class should be used to
                   decode the payload string or byte array.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'UDP'
        self.pq_type, self.query_fields = UDP.query_info()
        cdef:
            unsigned char use_buffer
        use_buffer, self._buffer = self.from_buffer(args, kwargs)
        if use_buffer:
            self.sport, self.dport, self.ulen, self.checksum = \
                unpack('!HHHH', self._buffer[:8])
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
                    self.app_layer(array('B', kwargs['payload']))
                else:
                    self.payload = NullPkt()
            else:
                self.payload = NullPkt()

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields UDP supports and UDP's
        PKT type ID.

        Returns:
            :tuple: PQTYPES.t_udp and a tuple of the supported field names.
        """
        return (PQ_UDP,
                (b'udp.srcport', b'udp.dstport', b'udp.length',
                 b'udp.checksum', b'udp.payload',b'udp.payload.offset[x:y]'))

    cpdef object get_field_val(self, bytes field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch. Also handles 
        udp.payload.offset[x:y] field.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns: 
            :object: value of the field.
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
        """Used to export a UDP packet class instance in network order  for 
        writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by UDP to payload classes. UDP supports the 
                following keyword arguments:
            :csum (0 or 1): Determines if this UDP instance should re-calculate 
                its checksum.
            :update (0 or 1): Determines if this UDP instance and any sub 
                layers should update size counters. For UDP this means updating
                the ulen variable.
            :ipv4_pheader (Ip4Ph): IPv4 pseudo header used in checksum 
                calculation.

        Returns: 
            :bytes: network order byte string representation of this UDP 
                instance.
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
        """Attempts to create an instance of the correct layer 7 protocol
        if the layer 4 ports match. Otherwise returns NullPkt.
        instance.

        Args:
            :plbuffer (array.array of bytes): The Layer 7 payload.
        """
        cdef type pkt_cls
        pkt_cls = NullPkt
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
        self.payload = pkt_cls(plbuffer)


cdef class TCP(PKT):
    def __init__(self, *args, **kwargs):
        """Initialize a TCP object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an TCP packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an TCP packet
            :sport (uint16_t): Layer 4 source port of this packet
            :dport (uint16_t): Layer 4 destination port of this packet
            :sequence (uint32_t): TCP sequence number.
            :acknowledgment (uint32_t): Acknowledgment number.
            :data_offset (uint16_t): Size of the TCP header in 32-bit 'words'.
                Min is 5.
            :flag_ns (0 or 1): ECN-nonce concealment protection (RFC 3540).
            :flag_cwr (0 or 1): Congestion Window Reduced flag (RFC 3168).
            :flag_ece (0 or 1): ECN-Echo flag (RFC 3168).
            :flag_urg (0 or 1): flag that the Urgent pointer field is
                significant.
            :flag_ack (0 or 1): flag that Acknowledgment field is significant.
            :flag_psh (0 or 1): flag requesting buffered data be pushed to the
                receiving application.
            :flag_rst (0 or 1): Reset the connection
            :flag_syn (0 or 1): Synchronize sequence numbers. Starts TCP
                handshake.
            :flag_fin (0 or 1): Flag as the last package from src of this
                packet.
            :window (uint16_t): Size of the receive window (default in bytes).
            :checksum (uint16_t): The 16-bit checksum field.
            :urg_ptr (uint16_t): Offset from the sequence number indicating the
                last urgent data byte. Use urg flag if set.
            :options (bytes): Array of bytes to use as the TCP options. The
                user must update data_offset and make these bytes align to
                32bit words. This is not fully implemented in this PKT class.
            :payload (PKT or bytes): The payload of this packet.
            :l7_ports (dict): A dictionary where the keys are layer 4 port
                numbers and the values are PKT subclass packet classes. Used by
                TCP.app_layer() to determine what class should be used to
                decode the payload string or byte array.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'TCP'
        self.pq_type, self.query_fields = TCP.query_info()
        cdef:
            unsigned char use_buffer
        use_buffer, self._buffer = self.from_buffer(args, kwargs)
        self.ws_len = len(self._buffer)
        self._pad = b''

        if use_buffer and self.ws_len >= 20:
            (self.sport, self.dport, self.sequence, self.acknowledgment,
            self._off_flags, self.window, self.checksum, self.urg_ptr) = \
                unpack('!HHIIHHHH', self._buffer[:20])
            if self.data_offset > 5:
                self._options = \
                    bytes(self._buffer[20:(self.data_offset * 4)].tostring())
            else:
                self._options = b''

            self.app_layer(self._buffer[(self.data_offset * 4):])
        else:
            if use_buffer and self.ws_len == 8:
                # From ICMP
                (self.sport, self.dport, self.sequence) = \
                    unpack('!HHI', self._buffer[:8])
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
                elif isinstance(kwargs['payload'], (bytes, str)):
                    self.app_layer(array('B', kwargs['payload']))
                else:
                    self.payload = NullPkt()
            else:
                self.payload = NullPkt()

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields UDP supports and TCP's
        PKT type ID.

        Returns:
            :tuple: PQTYPES.t_tcp and a tuple of the supported field names.
        """
        return (PQ_TCP,
                (b'tcp.srcport', b'tcp.dstport', b'tcp.seq', b'tcp.ack',
                 b'tcp.hdr_len', b'tcp.len', b'tcp.flags', b'tcp.flags.urg',
                 b'tcp.flags.ack', b'tcp.flags.push', b'tcp.flags.reset',
                 b'tcp.flags.syn', b'tcp.flags.fin', b'tcp.window_size_value',
                 b'tcp.checksum', b'tcp.urgent_pointer', b'tcp.payload',
                 b'tcp.payload.offset[x:y]'))

    cpdef object get_field_val(self, bytes field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch. Also handles 
        tcp.payload.offset[x:y] field. 

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg
        Returns: 
            :object: value of the field.
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
            return get_short_nibble(self._off_flags, 12)
        def __set__(self, unsigned char val):
            if 5 <= val <= 15:
                set_short_nibble(&self._off_flags, val, 12)
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
        """Used to export a TCP packet class instance in network order 
        for writing to a socket or into a pcap file.

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. TCP
                supports the following keyword arguments:
            :csum (0 or 1): Determines if this TCP instance should re-calculate 
                its checksum.
            :ipv4_pheader (Ip4Ps): IPv4 psuedo header used in checksum 
                calculation.

        Returns: 
            :bytes: network order byte string representation of this 
                TCP instance.
        """
        cdef:
            uint16_t tcp_len
            bint _csum
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
        pkt_cls = NullPkt
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
        self.payload = pkt_cls(plbuffer)


cdef class ICMP(PKT):
    """ RFC 792 ICMP with some additions. For example next hop MTU supported
    for destination unreachable. Not all record types supported.
    """
    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'ICMP'
        self.pq_type, self.query_fields = ICMP.query_info()
        cdef:
            unsigned char use_buffer
        use_buffer, self._buffer = self.from_buffer(args, kwargs)
        if use_buffer:
            self.identifier = 0
            self.sequence = 0
            self.mtu = 0
            self.pointer = 0
            self.orig_ts = 0
            self.rec_ts = 0
            self.trans_ts = 0
            self.hdr_pkt = NullPkt()
            self.data = array('B')
            self.echo_data = b''
            self._address = array('B', (0,0,0,0))
            self.type, self.code, self.checksum = \
                unpack('!BBH', self._buffer[:4])
            if (self.type in (ICMP_TYPE_ECHO_REPLY,
                              ICMP_TYPE_ECHO,
                              ICMP_TYPE_INFO,
                              ICMP_TYPE_INFO_REPLY)):
                # Echo packet format
                (self.identifier, self.sequence) = unpack('!HH',
                                                          self._buffer[4:8])
                if self._buffer[8:]:
                    self.echo_data = self._buffer[8:].tostring()
                else:
                    self.echo_data = b''
            elif self.type == ICMP_TYPE_DU:
                # Destination Unreachable format
                self.mtu = unpack('!H', self._buffer[6:8])[0]
                self.hdr_pkt = IP(self._buffer[8:])
            elif (self.type in (ICMP_TYPE_SRC_QUENCH,
                                ICMP_TYPE_TIME_EX)):
                # Source quench format
                self.hdr_pkt = IP(self._buffer[8:])
            elif self.type == ICMP_TYPE_REDIR:
                # redirect format
                self._address = self._buffer[4:8]
                self.hdr_pkt = IP(self._buffer[8:])
            elif self.type == ICMP_TYPE_PER_PROB:
                # Parameter Problem format
                self.pointer = self._buffer[4]
                self.hdr_pkt = IP(self._buffer[8:])
            elif (self.type in (ICMP_TYPE_TS,
                                ICMP_TYPE_TS_REPLY)):
                (self.identifier, self.sequence, self.orig_ts,
                 self.rec_ts, self.trans_ts) = unpack('!HHIII',
                                                      self._buffer)
            else:
                # unknown
                self.have_data = 1
        else:
            self.type = kwargs.get('type', 0)
            self.code = kwargs.get('code', 0)
            self.checksum = kwargs.get('checksum', 0)
            self.identifier = kwargs.get('identifier', 0)
            self.sequence = kwargs.get('sequence', 0)
            self.mtu = kwargs.get('mtu', 0)
            self.pointer = kwargs.get('pointer', 0)
            self.orig_ts = kwargs.get('orig_ts', 0)
            self.rec_ts = kwargs.get('rec_ts', 0)
            self.trans_ts = kwargs.get('trans_ts', 0)
            self.hdr_pkt = kwargs.get('hdr_pkt', NullPkt())
            self.data = kwargs.get('data', array('B'))
            self.echo_data = kwargs.get('echo_data', b'')
            self.address = kwargs.get('address', b'0.0.0.0')

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields UDP supports and UDP's
        PKT type ID.

        Returns:
            :tuple: PQTYPES.t_udp and a tuple of the supported field names.
        """
        return (PQ_ICMP,
                (b'icmp.checksum', b'icmp.code', b'icmp.seq', b'icmp.mtu',
                 b'icmp.ident', b'icmp.originate_timestamp', b'icmp.pointer'
                 b'icmp.receive_timestamp', b'icmp.redir_gw',
                 b'icmp.transmit_timestamp', b'icmp.type'))

    cpdef object get_field_val(self, bytes field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
        """
        cdef:
            uint32_t ts_secs, ts_mills
        if field == b'icmp.checksum':
            return self.checksum
        elif field == b'icmp.code':
            return self.code
        elif field == b'icmp.ident':
            return self.identifier
        elif field == b'icmp.originate_timestamp':
            return self.orig_ts
        elif field == b'icmp.receive_timestamp':
            return self.rec_ts
        elif field == b'icmp.redir_gw':
            return self.address
        elif field == b'icmp.seq':
            return self.sequence
        elif field == b'icmp.transmit_timestamp':
            return self.trans_ts
        elif field == b'icmp.type':
            return self.type
        elif field == b'icmp.mtu':
            return self.mtu
        elif field == b'icmp.pointer':
            return self.pointer
        elif field == b'icmp.data_time':
            if (self.type in (ICMP_TYPE_ECHO_REPLY, ICMP_TYPE_ECHO) and
                    len(self.echo_data) >= 8):
                ts_secs, ts_mills = unpack('!II', self.echo_data[:8])
                return b'{0}.{1}'.format(ts_secs, ts_mills)
            else:
                return b'0.0'
        else:
            return None

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a IP packet class instance in network order  for 
        writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by IP to payload classes. IP supports the 
                following keyword arguments:

        Returns: 
            :bytes: network order byte string representation of this IP 
                instance.
        """
        cdef:
            bytes pkt_hdr_bytes = b''
            bytes before_check = b'{0}{1}'.format(chr(self.type),
                                                  chr(self.code))
            bytes after_check = b''
            bytes nullcheck = b'\000\000'
            bint for_icmp = 1
            bint _csum = kwargs.get('csum', 0)

        if self.type in (ICMP_TYPE_DU, ICMP_TYPE_SRC_QUENCH, ICMP_TYPE_TIME_EX,
                         ICMP_TYPE_REDIR, ICMP_TYPE_PER_PROB):
            kwargs['for_icmp'] = for_icmp

        if (self.type in (ICMP_TYPE_ECHO_REPLY,
                          ICMP_TYPE_ECHO,
                          ICMP_TYPE_INFO,
                          ICMP_TYPE_INFO_REPLY)):
            after_check =  b'{0}{1}'.format(pack('!HH', self.identifier,
                                                        self.sequence),
                                            self.echo_data)
        elif self.type == ICMP_TYPE_DU:
            after_check = (b'\000\000{0}{1}'
                           b''.format(pack('!H', self.mtu),
                                      self.hdr_pkt.pkt2net(kwargs)))
        elif (self.type in (ICMP_TYPE_SRC_QUENCH,
                            ICMP_TYPE_TIME_EX)):
            after_check = b'\000\000\000\000{0}'.format(
                self.hdr_pkt.pkt2net(kwargs))
        elif self.type == ICMP_TYPE_REDIR:
            after_check = b'{0}{1}'.format(self.address.tostring(),
                                           self.hdr_pkt.pkt2net(kwargs))
        elif self.type == ICMP_TYPE_PER_PROB:
            after_check = b'{0}\000\000\000{1}'.format(
                chr(self.pointer),
                self.hdr_pkt.pkt2net(kwargs)
            )
        elif (self.type in (ICMP_TYPE_TS,
                            ICMP_TYPE_TS_REPLY)):
            after_check = pack('!HHIII',  self.identifier, self.sequence,
                                          self.orig_ts, self.rec_ts,
                                          self.trans_ts)
        else:
            # type is not supported yet. Just try to return the bytes we got
            if self.have_data:
                return self._buffer.tostring()
            else:
                return b''

        if _csum:
            self.checksum = checksum(b'{0}{1}{2}'.format(before_check,
                                                         nullcheck,
                                                         after_check))
        return b'{0}{1}{2}'.format(before_check,
                                   pack('!H', self.checksum),
                                   after_check)

    property address:
        def __get__(self):
            return socket.inet_ntoa(self._address)
        def __set__(self, bytes val):
            cdef bytes t
            if is_ipv4(val):
                t = socket.inet_aton(val)
                self._address = array('B', t)
            else:
                raise ValueError("address must be a dot notation "
                                 "IPv4 string. (1.1.1.1)")


cdef class IP(PKT):
    def __init__(self, *args, **kwargs):
        """
        Initialize a IP object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an IP packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an IP packet
            :version (unsigned char): IP version of this packet. Only 4 is
                supported. Default is 4.
            :iphl (unsigned char): Internet Protocol Header Length in 32-bit
                'words'. Minimum valid value is 5. Default is 5.
            :tos (unsigned char): IP type of service. Now primarily used to
                store DSCP values and ECN values. ECN is the low 2 bits.
            :total_len (uint16_t): The total lenght of the IP packet including
                the header and data.
            :ident (uint16_t): Primarily used for uniquely identifying the
                group of fragments of a single IP datagram. Used with
                frag_offset and flag_m.
            :flag_x (1 or 0): Flag bit zero implemented as x bit. See RFC 3514
                for appropriate use ;-)
            :flag_d (1 or 0): Don't fragment flag.
            :flag_m (1 or 0): More fragments flag.
            :frag_offset (uint16_t): This IP packet fragment offset from the
                beginning of the original un-fragmented IP datagram measured in
                units of eight-byte blocks.
            :ttl (unsigned char): The time to live for the IP datagram.
                Decremented by routers as a method to prevent endless circular
                routes. Default is 64.
            :checksum (uint16_t): The 16-bit checksum field.
            :src (bytes): IPv4 src address in dot notation. Default is
                '0.0.0.0'.
            :dst (bytes): IPv4 dst address in dot notation Default is
                '0.0.0.0'.
            :payload (bytes or PKT): The payload of this packet. Payload can
                be a PKT sub class or a byte string.
            :l7_ports (dict): A dictionary where the keys are layer 4 port
                numbers and the values are PKT subclass packet classes. Used by
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
                unpack('!HHH', self._buffer[2:8])
            self.ttl = self._buffer[8]
            self.proto = self._buffer[9]
            self.checksum = unpack('!H', self._buffer[10:12])[0]
            self.src_nochk = self._buffer[12:16]
            self.dst_nochk = self._buffer[16:20]
            if len(self._buffer[(self.iphl * 4):]):
                if self.proto == PROTO_UDP:
                    self.payload = UDP(self._buffer[(self.iphl * 4):],
                                       l7_ports = self.l7_ports)
                elif self.proto == PROTO_TCP:
                    self.payload = TCP(self._buffer[(self.iphl * 4):],
                                       l7_ports = self.l7_ports)
                elif self.proto == PROTO_ICMP:
                    self.payload = ICMP(self._buffer[(self.iphl * 4):])
                else:
                    self.payload = NullPkt(self._buffer[(self.iphl * 4):],
                                           l7_ports = self.l7_ports)
            else:
                self.payload = PKT()
        else:
            self.version = kwargs.get('version', IPV4_VER)
            self.iphl = kwargs.get('iphl', IPV4_MIN_HDR_LEN)
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
                if self.proto == PROTO_UDP:
                    self.payload = UDP(kwargs['payload'],
                                       l7_ports = self.l7_ports)
                elif self.proto == PROTO_TCP:
                    self.payload = TCP(kwargs['payload'],
                                       l7_ports = self.l7_ports)
                elif self.proto == PROTO_ICMP:
                    self.payload = ICMP(kwargs['payload'])
                else:
                    self.payload = NullPkt(kwargs['payload'],
                                           l7_ports = self.l7_ports)
            else:
                self.payload = PKT()

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields IP supports and
        IP's PKT type ID.

        Returns:
            :tuple: PQTYPES.t_ip and a tuple of the supported
                field names.
        """
        return (PQ_IP,
                (b'ip.version', b'ip.hdr_len', b'ip.tos', b'ip.len', b'ip.id',
                 b'ip.flags', b'ip.flags.df', b'ip.flags.mf',
                 b'ip.frag_offset', b'ip.ttl', b'ip.proto', b'ip.src',
                 b'ip.dst', b'ip.checksum'))

    cpdef object get_field_val(self, bytes field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
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
        """Used to export a IP packet class instance in network order  for 
        writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by IP to payload classes. IP supports the 
                following keyword arguments:
            :csum (0 or 1): Determines if this IP instance should re-calculate 
                its checksum.
            :update (0 or 1): Determines if this IP instance and any sub layers
                should update size counters. For IP this means updating the
                total_len variable.
            :for_icmp (0 or 1): Return on the 64 bits of the header needed
                for ICMP packets.
            :ipv4_pheader (Ip4Ph): IPv4 pseudo header used in checksum 
                calculation.

        Returns: 
            :bytes: network order byte string representation of this IP 
                instance.
        """
        cdef:
            bint_csum, _update, _icmp
            bytes _pload_bytes, ip_ph
            Ip4Ph _ph

        _pload_bytes = b''
        ip_ph = b''

        _icmp = kwargs.get('for_icmp', 0)
        if _icmp:
            _csum = 0
            _update = 0
        else:
            _csum = kwargs.get('csum', 0)
            _update = kwargs.get('update', 0)

        # support a user passing in a pheader of their own for negative testing
        kwargs['ipv4_pheader'] = kwargs.get('ipv4_pheader', self.ipv4_pheader)
        if isinstance(self.payload, PKT):
            if _icmp:
                _pload_bytes = self.payload.pkt2net({})
            else:
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
            return get_char_nibble(self._version_iphl, 4)
        def __set__(self, unsigned char val):
            """ Set the IP Version. """
            if val in (IPV4_VER, IPV6_VER):
                set_char_nibble(&self._version_iphl, val, 4)
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
            return get_short_nibble(self._flags_offset, 12) >> 1

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
    """ Very limited implementation of MPLS (RFC 3031). Supports only IPv4 and
    Ethernet payloads. And only detects the difference by looking at the
    first nibble of the payload bytes.
    """

    def __init__(self, *args, **kwargs):
        """Initialize a MPLS object. Note on data types for Args. Only the
        stack bit and the TTL use the full size of the data types specified
        below. label used only 20 bits and the traffic class uses 3 bits.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an MPLS packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an MPLS packet
            :label (uint32_t): 20 bit MPLS label value.
            :tc (unsigned char): Traffic Class (QoS and ECN). 3 bits used
            :s (0 or 1): Bottom of label stack bit.
            :ttl (unsigned char): Time to live for this label.
            :payload (PKT or bytes): The payload of this packet.
            :l7_ports (dict): Keys are layer 4 port numbers and the values are
                PKT subclass packet classes. Used by the app_layer() in layer
                7 protocols to determine what class should be used to decode
                the payload string or byte array. MPLS only passes this option
                on to subsequent packet layers.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'MPLS'
        self.pq_type, self.query_fields = MPLS.query_info()
        cdef:
            unsigned char use_buffer
        use_buffer, self._buffer = self.from_buffer(args, kwargs)

        if use_buffer:
            self._data = unpack('!I', self._buffer[:4])[0]
            if self.s and self._buffer[4:]:
                if self._buffer[4] >> 4 == IPV4_VER:
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
        """Provides pcap_query with the query fields MPLS supports and MPLS's
        PKT type ID.

        Returns:
            :tuple: PQTYPES.t_mpls and a tuple of the supported field names.
        """
        return (PQ_MPLS,
                (b'mpls.bottom.label', b'mpls.bottom.tc',
                 b'mpls.bottom.stack_bit', b'mpls.bottom.ttl',
                 b'mpls.top.label', b'mpls.top.tc',
                 b'mpls.top.stack_bit', b'mpls.top.ttl'))

    cpdef get_field_val(self, bytes field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch. This function is
        different from other protocols in that it detects if this is or is not
        the botton of stack MPLS label.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns: 
            :object: value of the field.
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
        """Used to export a MPLS packet class instance in network order 
        for writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by MPLS to payload classes. MPLS has no options
                that it directly supports.

        Returns: 
            :bytes: network order byte string representation of this MPLS 
                instance.
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
    """Implements Ethernet II frame without CRC.
    """
    def __init__(self, *args, **kwargs):\

        """Initialize a Ethernet II object.

        Args:
            :args (list): Optional one element list containing network order
                bytes of an Ethernet packet
            :data (bytes): Optional keyword argument containing network order
                bytes of an Ethernet packet
            :src_mac (bytes): Layer 2 source address in colon notation. For 
                example the layer 2 broadcast MAC would be 'ff:ff:ff:ff:ff:ff'
            :dst_mac (bytes): Layer 2 destination address in colon notation.
            :type (uint16_t): EtherType of the payload. Common values are 
                0x0800 for IPv4 and 0x0806 for ARP.
            :payload (PKT or bytes): The payload of this packet. Payload can be 
                a PKT sub class or a byte string.
            :l7_ports (dict): A dictionary where the keys are layer 4 port 
                numbers and the values are PKT subclass packet classes. Used 
                by app_layer to determine what class should be used to decode
                the payload string or byte array.
        """
        super(self.__class__, self).__init__(*args, **kwargs)
        self.pkt_name = b'Ethernet'
        self.tpid = 0
        self._tci = 0
        self.pq_type, self.query_fields = Ethernet.query_info()
        cdef:
            unsigned char use_buffer
            uint16_t vlan_hdr_add

        use_buffer, self._buffer = self.from_buffer(args, kwargs)
        vlan_hdr_add = 0
        if use_buffer:
            self._dst_mac = self._buffer[:6]
            self._src_mac = self._buffer[6:12]
            self.type = unpack('!H', self._buffer[12:14])[0]
            if self.type == ETH_TYPE_8021Q:
                self.tpid = ETH_TYPE_8021Q
                self._tci, self.type = unpack('!HH', self._buffer[14:18])
                vlan_hdr_add = 4
            if self.type == ETH_TYPE_IPV4:
                self.payload = IP(self._buffer[14 + vlan_hdr_add:],
                                  l7_ports = self.l7_ports)
            elif self.type == ETH_TYPE_ARP:
                self.payload = ARP(self._buffer[14 + vlan_hdr_add:])
            elif self.type in (ETH_TYPE_MPLS_UCAST,
                               ETH_TYPE_MPLS_MCAST):
                self.payload = MPLS(self._buffer[14 + vlan_hdr_add:])
            else:
                self.payload = NullPkt(self._buffer[14 + vlan_hdr_add:])
        else:
            self.src_mac = kwargs.get('src_mac', b'00:00:00:00:00:00')
            self.dst_mac = kwargs.get('dst_mac', b'00:00:00:00:00:00')
            self.type = kwargs.get('type', ETH_TYPE_IPV4)
            self.tpid = kwargs.get('tpid', 0)
            if self.tpid == ETH_TYPE_8021Q:
                self.priority_code = kwargs.get('priority_code', 0)
                self.drop_eligible = kwargs.get('drop_eligible', 0)
                self.vlan_id = kwargs.get('vlan_id', 0)
            self.payload = kwargs.get('payload', PKT())

    @classmethod
    def query_info(cls):
        """Provides pcap_query with the query fields Ethernet supports and
        Ethernet's PKT type ID.

        Returns:
            :tuple: PQTYPES.t_eth and a tuple of the supported
                field names.
        """
        return (PQ_ETH,
                (b'eth.type', b'eth.src', b'eth.dst'))

    cpdef object get_field_val(self, bytes field):
        """Returns the value of the Wireshark format field name. Implemented as 
        an if, elif, else set because Cython documentation shows that this 
        form is turned that into an efficient case switch.

        Args:
            :field (bytes): name of the desired field in Wireshark format. For 
                example: arp.proto.type or tcp.flags.urg

        Returns:
            :object: the value of the field.
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
            return b':'.join(b'%02d' % x for x in self._src_mac)
        def __set__(self, bytes val):
            self._src_mac = array('B', (int(x, 16) for x in val.split(b':')))

    property dst_mac:
        def __get__(self):
            return b':'.join(b'%02d' % x for x in self._dst_mac)
        def __set__(self, bytes val):
            self._dst_mac = array('B', (int(x, 16) for x in val.split(b':')))

    property priority_code:
        """ The priority_code. """
        def __get__(self):
            """ Return the priority_code value. """
            return (self._tci >> 13) & 0b111
        def __set__(self, unsigned char val):
            """ Set the priority_code value. """
            if val <= 0b111:
                self._tci = (self._tci & ~(0b111 << 13)) | (val << 13)
            else:
                raise ValueError("priority_code valid values are 0-7")

    property drop_eligible:
        """ Set or get the drop_eligible bit. """
        def __get__(self):
            """ Return the drop_eligible bit. """
            return (self._tci >> 12) & 1
        def __set__(self, unsigned char val):
            """ Set the drop_eligible bit. """
            if val == 1:
                set_bit(&self._tci, 12)
            elif val == 0:
                unset_bit(&self._tci, 12)
            else:
                raise ValueError("drop_eligible bit must be 0 or 1")

    property vlan_id:
        """ Set or get vlan_id. """
        def __get__(self):
            """ Return the vlan_id. """
            return self._tci & 0xfff
        def __set__(self, uint16_t val):
            """ Set the vlan_id. """
            if val <= 0xfff:
                self._tci = (self._tci & ~0xfff) | val
            else:
                raise ValueError("vlan_id has a max value of: ".format(0xfff))

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a Ethernet packet class instance in network order 
        for writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by Ethernet to payload classes. Ethernet has no 
                options that it directly supports.

        Returns: 
            :bytes: network order byte string representation of this Ethernet 
                instance.
        """
        cdef:
            bytes _pload_bytes
        _pload_bytes = b''

        if isinstance(self.payload, PKT):
            _pload_bytes = self.payload.pkt2net(kwargs)
        if self.tpid == ETH_TYPE_8021Q:
            return b'{0}{1}{2}{3}'.format(self._dst_mac.tostring(),
                                          self._src_mac.tostring(),
                                          pack('!HHH', self.tpid,
                                                       self._tci,
                                                       self.type),
                                          _pload_bytes)
        else:
            return b'{0}{1}{2}{3}'.format(self._dst_mac.tostring(),
                                          self._src_mac.tostring(),
                                          pack('!H', self.type),
                                          _pload_bytes)
