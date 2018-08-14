# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

import re
import struct
import socket
from cpython.array cimport array
from libc.stdint cimport uint16_t

from steelscript.packets.core.inetpkt cimport PKT, set_bit, unset_bit, \
    set_short_nibble, get_short_nibble

# Regex to see if data is a valid domain name
hostname_re = re.compile(r"^(?:(?!-|[^.]+_)[A-Za-z0-9-_]{1,63}(?<!-)"
                          "(?:\.|$))$")
domainname_re = re.compile(r"^(?=.{1,253}\.?$)(?:(?!-|[^.]+_)[A-Za-z0-9-_]"
                            "{1,63}(?<!-)(?:\.|$)){2,}$")

email_re = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")


cdef array hostname_to_label_array(bytes hostname):
    """ Convert a hostname or FQDN to DNS label notation. For example:
        www.riverbed.com becomes [3,119,119,119,8,114,...,100,3,99,111,109,0]
        Args:
            :hostname (bytes): A "dot notation" host name as defined in RFC 
                1123

        Returns: 
            :bytes: DNS label notation list as shown in TCP/IP Illustrated 
                Chapter 14 or RFC 1035
    """
    cdef:
        array out
        bytes part, ch

    if domainname_re.match(hostname) or hostname_re.match(hostname):
        out = array('B')
        for part in hostname.split('.'):
            out.append(len(part))
            for ch in part:
                out.append(ord(ch))
        out.append(0)
        return out
    else:
        raise ValueError("hostname_to_label_array(hostname): hostname "
                         "argument must be valid RFC 1123 FQDN. Argument "
                         "was: {0}".format(hostname))

cdef bytes write_dns_name_bytes(bytes dns_name,
                                uint16_t* offset,
                                dict labels,
                                bint compress=1):
    """ Used to write DNS name into packet data. See read_dns_name_bytes for 
        a description of the name formats.
        Args:
            :byte_array (array): packet data as array('B').
            :offset (uint16_t*): pointer to location in the packet where this 
                name starts
            :label_store (dict): A per packet store of previously seen labels 
                with their offsets in the packet data.
            :compress (bint): Should compression be used if possible. Default
                is 1 for yes

        Returns: 
            :bytes: human readable name.
    """
    cdef:
        list parts
        array out_array

    if dns_name == b'':
        offset[PNTR] += 1
        out_array = array('B', [0])
    else:
        parts = dns_name.encode('UTF-8').split('.')
        parts.append(b'')
        if compress:
            # see if this label is present already. Write it an update bytes.
            if dns_name in labels:
                offset[PNTR] += 2
                out_array = array('B',
                                  struct.pack("!H",
                                              LABEL + labels[dns_name]))
            else:
                labels[dns_name] = offset[PNTR]
                out_array = array('B', [len(parts[0])])
                out_array.extend(array('B', parts[0]))
                offset[PNTR] += len(out_array)
                out_array.extend(array('B',
                                       write_dns_name_bytes(
                                           b'.'.join(parts[1:-1]),
                                           offset,
                                           labels,
                                           compress)))
        else:
            for part in parts:
                out_array = array('B')
                out_array.append(len(part))
                out_array.extend(array('B', part))
            offset[PNTR] += len(out_array)

    return out_array.tostring()

cdef bytes read_dns_name_bytes(array byte_array,
                               uint16_t* offset,
                               dict label_store):
    """ Used to read DNS name labels out of DNS packets. These labels can be in
        two formats. Uncompressed as '3www8riverbed3com0'. This would have a
        decimal representation of:
            [3,119,119,119,8,114,105,...,101,100,3,99,111,109,0]
        or in the packet data as:
            '\x03www\x08ri...ed\x03com\x00'
        The second format is compressed. With compressed data some part of the
        name has previously been seen. In that case the name will be as a 16bit
        value where the 2 most significant bits are set to '11' and the
        remaining 14 bits specify the number of bytes into the packet where the
        name can be found. So if 'www.riverbed.com' the first query in a DNS
        packet then it would have been seen at byte 12. So a later reference to
        it would look like '\xc0\x0c' or 49164 in decimal.

        Args:
            :byte_array (array): packet data as array('B').
            :offset (uint16_t*): pointer to location in the packet where this 
                name starts
            :label_store (dict): A per packet store of previously seen labels 
                with their offsets in the packet data.

        Returns: 
            :bytes: human readable name.
    """
    cdef:
        uint16_t location, index
        bytes c_label, cur_label
        unsigned char b1
        bint read_on
        list labels
        list return_parts

    read_on = 1
    labels = list()
    return_parts = list()

    while read_on:
        b1 = byte_array[offset[PNTR]]
        if 1 <= b1 <= 63:
            # This is the first time we have seen this label OR this packet
            # is not using compression.
            c_label = \
                byte_array[offset[PNTR] + 1: offset[PNTR] + 1 + b1].tostring()
            labels.append((offset[PNTR], c_label, ))
            return_parts.append(c_label)
            offset[PNTR] += b1 + 1
        elif b1 == 0:
            # DNS name is done
            read_on = 0
            offset[PNTR] += 1
        else:
            location = struct.unpack(
                "!H",
                byte_array[offset[PNTR]: offset[PNTR] + 2])[0]
            offset[PNTR] += 2
            # Strip off the top two bits
            location = location & 0x3fff
            if location in label_store:
                return_parts.append(label_store[location])
                labels.append((location, label_store[location], ))
            else:
                raise ValueError("read_dns_name_bytes encountered unexpected "
                                 "compressed data in byte_array. Array bytes "
                                 "are: {0}"
                                 "".format(byte_array[offset[PNTR] - 2:]))
            # Compressed labels come at the end. We break now
            read_on = 0
    for index in range(len(labels)):
        cur_label = b'.'.join((x[1] for x in labels[index:]))
        if cur_label not in label_store:
            label_store[cur_label] = labels[index][0]
            label_store[labels[index][0]] = cur_label
        else:
            # Suppose this packet is not using compression? But this
            # is not the first time we have seen this label so move on.
            pass
    return b'.'.join(return_parts)


cdef tuple parse_resource(array byte_array,
                          uint16_t* offset,
                          dict label_store):
    """ Used to parse the initialization values for a DNSResource object from
        an array of bytes. 

        Args:
            :byte_array (array): packet data as array('B').
            :offset (uint16_t*): pointer to location in the packet where this 
                DNSResource starts
            :label_store (dict): A per packet store of previously seen labels 
                with their offsets in the packet data. Used to call
                read_dns_name_bytes() or parse_soa()

        Returns: 
            :tuple: arguments that make up *this DNSResource object
    """
    cdef:
        uint16_t r_type, r_class, r_d_len
        uint32_t r_ttl
        bytes d_name, r_data

    d_name = read_dns_name_bytes(byte_array, offset, label_store)
    r_type, r_class, r_ttl, r_d_len = struct.unpack(
        "!HHIH",
        byte_array[offset[PNTR]:offset[PNTR] + 10])
    offset[PNTR] += 10
    if r_type in (DNSTYPE_NS, DNSTYPE_CNAME, DNSTYPE_PTR):
        r_data = read_dns_name_bytes(byte_array,
                                     offset,
                                     label_store)
    elif r_type == DNSTYPE_A:
        r_data = socket.inet_ntop(socket.AF_INET,
                                  byte_array[offset[PNTR]:offset[PNTR] + 4])
        offset[PNTR] += 4
    elif r_type == DNSTYPE_AAAA:
        r_data = socket.inet_ntop(socket.AF_INET6,
                                  byte_array[offset[PNTR]:offset[PNTR] + 16])
        offset[PNTR] += 16
    elif r_type == DNSTYPE_SOA:
        r_data = parse_soa(byte_array, offset, &r_d_len, label_store)
    else:
        r_data = byte_array[offset[PNTR]:offset[PNTR] + r_d_len].tostring()
        offset[PNTR] += r_d_len
    return d_name, r_type, r_class, r_ttl, r_d_len, r_data


cdef bytes parse_soa(array data, uint16_t* offset, uint16_t* rlen,
                     dict label_store):
    """Used to parse the human readable value for a SOA type 
       DNSResource.res_data string from an array of bytes. 

        Args:
            :byte_array (array): packet data as array('B').
            :offset (uint16_t*): pointer to location in the packet where this 
                DNSResource starts
            :rlen (uint16_t*): pointer a uint16_t with the length in bytes of
                this SOA records resource data. Used to check from the
                unexpected case where a user directly feeds a parsed SOA to
                parse_soa() 
            :label_store (dict): A per packet store of previously seen labels 
                with their offsets in the packet data. Used to call
                read_dns_name_bytes() or parse_soa()

        Returns: 
            :bytes: human readable representation of SOA record.
    """
    cdef:
        uint16_t count, original_offset, index
        bytes mname, rname
        uint32_t serial, refresh, retry, expire, minimum

    original_offset = offset[PNTR]
    count = data[offset[PNTR]:offset[PNTR] + rlen[PNTR]].count(ord(b' '))

    if (count <= 7 and
            len(data[offset[PNTR]:offset[PNTR] + rlen[PNTR]]) == rlen[PNTR]):
        # its in binary format
        mname = read_dns_name_bytes(data, offset, label_store)
        rname = read_dns_name_bytes(data, offset, label_store)
        rname = rname.replace(b'.', b'@', 1)
        serial, refresh, retry, expire, minimum = struct.unpack('!IIIII',
                                          data[offset[PNTR]:offset[PNTR] + 20])
        offset[PNTR] += 20
        return (b'SOA mname: {0}, rname: {1}, serial: {2}, refresh: {3}, '
                b'retry: {4}, expire: {5}, minimum: {6}'
                b''.format(mname, rname, serial, refresh, retry, expire,
                           minimum))
    elif count == 15:
        # its already in printable format and being manually added. No need to
        # alter the offset values.
        return data.tostring()
    else:
        raise ValueError(b'parse_soa called on invalid soa data. Count was:{1}'
                         b', Data was: {0}'.format(data, count))


cdef bytes pack_soa(bytes res_data, uint16_t* offset, dict labels,
                    bint compress=1):
    """ Function that packs the parts of a human readable SOA record (as
        created by parse_soa()).
        Args:
            :res_data (bytes): The human readable form of SOA record.
            :offset (uint16_t*): Start of this SOA as an offset into the packed
                packet data.
            :labels (dict): All the name labels in this packet as a dictionary.
            :compress (bint): Boolean governing compression
        Returns:
            :bytes: Network order representation of this SOA record. 
    """
    cdef:
        bytes p_bytes
        list parts
        uint32_t serial, refresh, retry, expire, minimum

    p_bytes = b''
    parts = res_data.split()
    if len(parts) == 15:
        p_bytes += write_dns_name_bytes(parts[SOA_MNAME][:-1], offset, labels,
                                        compress)
        parts[SOA_RNAME] = parts[SOA_RNAME].replace(b'@', b'.')
        p_bytes += write_dns_name_bytes(parts[SOA_RNAME][:-1], offset, labels,
                                        compress)
        offset[PNTR] += 20

        return b'{0}{1}'.format(p_bytes,
                                struct.pack("!IIIII",
                                            int(parts[SOA_SER][:-1]),
                                            int(parts[SOA_REF][:-1]),
                                            int(parts[SOA_RET][:-1]),
                                            int(parts[SOA_EXP][:-1]),
                                            int(parts[SOA_MIN])))
    else:
        raise ValueError(b'pack_soa called on invalid soa data. Data was: {0}'
                         b''.format(res_data))

cdef class DNSQuery:

    def __init__(self,
                 bytes query_name,
                 uint16_t query_type,
                 uint16_t query_class):
        """ Simple class to wrap DNS queries
            Args:
                :query_name (bytes): The name for this query
                :query_type (uint16_t): query type. See DNSTYPE_ enums defined
                    in dns.pxd
                :query_class (uint16_t): query class. See RCLASS_ enums defined
                    in dns.pxd
        """

        self.query_type = query_type
        self.query_class = query_class
        self.query_name = query_name

    def __repr__(self):
        return ("DNSQuery(query_name={0}, query_type={1}, query_class={2})"
                "".format(self._query_name, self.query_type,
                          self.query_class))

    @property
    def query_name(self):
        return self._query_name

    @query_name.setter
    def query_name(self, val):
        if (domainname_re.match(val) or
                hostname_re.match(val) or
                self.query_type in (DNSTYPE_TXT,
                                    DNSTYPE_OPT)):
            self._query_name = val
        else:
            raise ValueError(
                "DNSQuery.query_name must be either a valid host name. "
                "Value was {0}".format(val))

    cdef bytes pack(self, uint16_t* offset, dict labels, bint compress=1):
        cdef:
            bytes out
        out = write_dns_name_bytes(self._query_name, offset, labels, compress)
        offset[PNTR] += 4
        return out + struct.pack('!HH', self.query_type, self.query_class)


cdef class DNSResource:
    """ Wrapper class for DNS resource record data. Includes some special
        handling for IPv4 and IPv6 record types, SOA records, and common DNS
        name record types like CNAME and PTR
        Args:
            :domain_name (bytes): string human readable dot notation fqdn for
                this resource. www.riverbed.com or 1.in-addr.arpa
            :res_type (uint16_t): type of resource A, CNAME, PTR, AAAA
            :res_class (uint16_t): Class of resource. Almost always 1 for inet.
            :res_ttl (uint32_t): How long this resource can live in seconds.
            :res_len (uint16_t): Length in bytes of res_data
            :res_data (bytes): Data for this resource as specified by type,
                class, and len
    """

    def __init__(self,
                 bytes domain_name,
                 uint16_t res_type,
                 uint16_t res_class,
                 uint32_t res_ttl,
                 uint16_t res_len,
                 bytes res_data):
        self.res_type = res_type
        self.res_class = res_class
        self.res_ttl = res_ttl
        self.res_len = res_len
        self.domain_name = domain_name
        self.res_data = res_data

    def __repr__(self):
        return ("DNSResource(domain_name={0}, res_type={1}, res_class={2}, "
                "res_ttl={3}, res_len={4}, res_data={5})"
                "".format(self._domain_name,
                          self.res_type,
                          self.res_class,
                          self.res_ttl,
                          self.res_len,
                          self.res_data))

    property domain_name:
        def __get__(self):
            return self._domain_name

        def __set__(self, bytes val):
            if (domainname_re.match(val) or
                    hostname_re.match(val) or
                    val == b'' or
                    self.res_type in (DNSTYPE_TXT,
                                      DNSTYPE_OPT)):
                self._domain_name = val
            else:
                raise ValueError(
                    "DNSResource.domain_name must be either a valid host "
                    "name. Value was {0}".format(ord(val)))

    cdef bytes pack(self, uint16_t* offset,
                          dict labels,
                          bint compress=1,
                          bint update=1):
        cdef:
            bytes name
            bytes r_data
        name = write_dns_name_bytes(self._domain_name, offset,
                                    labels, compress)
        offset[PNTR] += 10
        if self.res_type in (DNSTYPE_NS, DNSTYPE_CNAME, DNSTYPE_PTR):
            r_data = write_dns_name_bytes(self.res_data, offset,
                                          labels, compress)
        elif self.res_type == DNSTYPE_A:
            r_data = socket.inet_pton(socket.AF_INET, self.res_data)
            offset[PNTR] += 4
        elif self.res_type == DNSTYPE_AAAA:
            r_data = socket.inet_pton(socket.AF_INET6, self.res_data)
            offset[PNTR] += 16
        elif self.res_type == DNSTYPE_SOA:
            r_data = pack_soa(self.res_data, offset, labels, compress)
        else:
            r_data = self.res_data
            offset[PNTR] += len(r_data)
        if update:
            self.res_len = len(r_data)
        return b'{0}{1}{2}'.format(name,
                                   struct.pack("!HHIH",
                                               self.res_type,
                                               self.res_class,
                                               self.res_ttl,
                                               self.res_len),
                                   r_data)


cdef class DNS(PKT):
    """ Wrapper for RFC 1035 DNS packet data. Reads and writes.

    """
    def __init__(self, *args, **kwargs):
        super(DNS, self).__init__(*args, **kwargs)
        self.pkt_name = b'DNS'
        self.pq_type, self.query_fields = DNS.query_info()
        cdef:
            bint use_buffer
            uint32_t i
            uint16_t offset
            bytes query_name
            uint16_t query_type, query_class
            tuple resource_args

        use_buffer, self._buffer = self.from_buffer(args, kwargs)

        self._flags = 0
        self.queries = list()
        self.answers = list()
        self.authority = list()
        self.ad = list()
        self.labels = dict()
        offset = 0

        if use_buffer:
            # read the first 12 bytes into six unsigned shorts.
            (self.ident,
             self._flags,
             self.query_count,
             self.answer_count,
             self.auth_count,
             self.ad_count) = struct.unpack('!6H', self._buffer[:12])
            # add those 12 bytes to the offset index.
            offset = 12
            # for each query and or resource record we have parse the data.
            if self.query_count:
                for i in range(self.query_count):
                    # read and or update our labels
                    query_name = read_dns_name_bytes(self._buffer,
                                                     &offset,
                                                     self.labels
                    )
                    # unpack the remainder of the query.
                    query_type, query_class = struct.unpack(
                        '!HH',
                        self._buffer[offset:offset + 4]
                    )
                    self.queries.append(DNSQuery(query_name,
                                                   query_type,
                                                   query_class))
                    offset += 4
            # Now unpack the resources by the 3 remaining types.
            if self.answer_count:
                for _ in range(self.answer_count):
                    resource_args = parse_resource(self._buffer,
                                                   &offset,
                                                   self.labels
                    )
                    self.answers.append(DNSResource(*resource_args))
            if self.auth_count:
                for _ in range(self.auth_count):
                    resource_args = parse_resource(self._buffer,
                                                   &offset,
                                                   self.labels
                    )
                    self.authority.append(DNSResource(*resource_args))
            if self.ad_count:
                for _ in range(self.ad_count):
                    resource_args = parse_resource(self._buffer,
                                                   &offset,
                                                   self.labels
                    )
                    self.ad.append(DNSResource(*resource_args))

        else:
            self.ident = kwargs.get('ident', 0)
            self.query_resp = kwargs.get('query_resp', 0)
            self.op_code = kwargs.get('op_code', 0)
            self.authoritative = kwargs.get('authoritative', 0)
            self.truncated = kwargs.get('truncated', 0)
            self.recursion_requested = kwargs.get('recursion_requested', 0)
            self.recursion_available = kwargs.get('recursion_available', 0)
            self.authentic_data = kwargs.get('authentic_data', 0)
            self.check_disabled = kwargs.get('check_disabled', 0)
            self.resp_code = kwargs.get('resp_code', 0)
            self.query_count = kwargs.get('query_count', 0)
            self.answer_count = kwargs.get('answer_count', 0)
            self.auth_count = kwargs.get('auth_count', 0)
            self.ad_count = kwargs.get('ad_count', 0)

    @classmethod
    def query_info(cls):
        """
        Used by pcap_query to derive what PKT class ID this class has AND
        what query fields it supports. ANY PKT based class that wants to be
        supported by steelscript.packets.query.pcap_query's PcapQuery must
        implment this class method and optimaly provide a
        get_field_val(<field_name>) function as well.
        return: uint16_t pq_type, tuple_of_string query_fields"""
        return (DNS_PACKET_TYPE,
                (b'dns.ident', b'dns.query_resp', b'dns.op_code',
                 b'dns.authoritative',
                 b'dns.truncated', b'dns.recursion_requested',
                 b'dns.recursion_available',
                 b'dns.authentic_data', b'dns.check_disabled',
                 b'dns.resp_code',
                 b'dns.query_count', b'dns.answer_count', b'dns.auth_count',
                 b'dns.ad_count'))


    @classmethod
    def default_ports(cls):
        """
        Used by pcap_query to deterimine what layer 4 ports should be parsed
        by the layer 4 protocols (TCP, UDP) as THIS packet type."""
        return [DNS_PACKET_PORT]


    cpdef object get_field_val(self, bytes field):
        """ Used to fetch field data values for DNS packets. Does not yet have
            support for retrieving query and resource record values.
            Args:
                :field (bytes): name of the field
            Returns:
                :object: the value of the field in this packet.
        """
        if field == b'dns.ident':
            return self.ident
        elif field == b'dns.query_resp':
            return self.query_resp
        elif field == b'dns.op_code':
            return self.op_code
        elif field == b'dns.authoritative':
            return self.authoritative
        elif field == b'dns.truncated':
            return self.truncated
        elif field == b'dns.recursion_requested':
            return self.recursion_requested
        elif field == b'dns.recursion_available':
            return self.recursion_available
        elif field == b'dns.authentic_data':
            return self.authentic_data
        elif field == b'dns.check_disabled':
            return self.check_disabled
        elif field == b'dns.resp_code':
            return self.resp_code
        elif field == b'dns.query_count':
            return self.query_count
        elif field == b'dns.answer_count':
            return self.answer_count
        elif field == b'dns.auth_count':
            return self.auth_count
        elif field == b'dns.ad_count':
            return self.ad_count
        else:
            return None

    property query_resp:
        def __get__(self):
            return (self._flags >> 15) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 15)
            elif val == 1:
                set_bit(&self._flags, 15)
            else:
                raise ValueError("DNS query_resp bit must be 0 or 1.")

    property op_code:
        def __get__(self):
            return get_short_nibble(self._flags, 11)

        def __set__(self, unsigned char val):
            if 0 <= val <= 15:
                set_short_nibble(&self._flags, val, 11)
            else:
                raise ValueError("DNS op_code must be between 0 and 15.")

    property authoritative:
        def __get__(self):
            return (self._flags >> 10) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 10)
            elif val == 1:
                set_bit(&self._flags, 10)
            else:
                raise ValueError("DNS authoritative bit must be 0 or 1.")

    property truncated:
        def __get__(self):
            return (self._flags >> 9) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 9)
            elif val == 1:
                set_bit(&self._flags, 9)
            else:
                raise ValueError("DNS truncated bit must be 0 or 1.")

    property recursion_requested:
        def __get__(self):
            return (self._flags >> 8) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 8)
            elif val == 1:
                set_bit(&self._flags, 8)
            else:
                raise ValueError("DNS recursion_requested bit must be 0 or 1.")

    property recursion_available:
        def __get__(self):
            return (self._flags >> 7) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 7)
            elif val == 1:
                set_bit(&self._flags, 7)
            else:
                raise ValueError("DNS recursion_available bit must be 0 or 1.")

    property authentic_data:
        def __get__(self):
            return (self._flags >> 5) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 5)
            elif val == 1:
                set_bit(&self._flags, 5)
            else:
                raise ValueError("DNS authentic_data bit must be 0 or 1.")

    property check_disabled:
        def __get__(self):
            return (self._flags >> 4) & 1

        def __set__(self, unsigned char val):
            if val == 0:
                unset_bit(&self._flags, 4)
            elif val == 1:
                set_bit(&self._flags, 4)
            else:
                raise ValueError("DNS check_disabled bit must be 0 or 1.")

    property resp_code:
        def __get__(self):
            return get_short_nibble(self._flags, 0)

        def __set__(self, unsigned char val):
            if 0 <= val <= 15:
                set_short_nibble(&self._flags, val, 0)
            else:
                raise ValueError("DNS resp_code must be between 0 and 15.")

    cpdef bytes pkt2net(self, dict kwargs):
        """Used to export a DNS packet class instance in network order for 
        writing to a socket or into a pcap file. 

        Args:
            :kwargs (dict): list of arguments defined by PKT sub classes. 
                Passed along by UDP to payload classes. UDP supports the 
                following keyword arguments:
            :update (0 or 1): Determines if this DNS instance should
                    re-calculate size values.
            :compress (0 or 1): Compress labels. Default is 1 to compress.
        Returns: 
            :bytes: network order byte string representation of this DNS 
                instance.
        """
        cdef:
            bint update, compress
            uint16_t offset
            bytes p_bytes
            dict pack_labels
            DNSQuery query
            DNSResource resource

        update = kwargs.get('update', 0)
        compress = kwargs.get('compress', 1)
        pack_labels = dict()
        offset = 12

        if update:
            self.query_count = len(self.queries)
            self.answer_count = len(self.answers)
            self.auth_count = len(self.authority)
            self.ad_count = len(self.ad)

        p_bytes = struct.pack('!HHHHHH', self.ident,
                                         self._flags,
                                         self.query_count,
                                         self.answer_count,
                                         self.auth_count,
                                         self.ad_count)

        for query in self.queries:
            p_bytes += query.pack(&offset, pack_labels, compress)
        for resource in self.answers + self.authority + self.ad:
            p_bytes += resource.pack(&offset, pack_labels, compress)

        return p_bytes