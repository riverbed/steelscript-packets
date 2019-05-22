#!/usr/bin/env python
# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

import re
import struct
import socket
from array import array
from collections import namedtuple

from steelscript.packets.core.inetpkt import PKT


# Helper function to create named tuple from a dict.
def dict_to_namedtuple(the_dict, the_name):
    return namedtuple(the_name, the_dict.keys())(**the_dict)

# Static variable defining the pcap_query type for this packet class
# Best practice is to use the default layer 4 port of this protocol.
DNS_PACKET_TYPE = 53
DNS_PACKET_PORT = DNS_PACKET_TYPE


# Some static dns info mostly taken from:
# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
dnstypes = {
    0: "ANY", 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 11: "WKS", 12: "PTR",
    13: "HINFO", 15: "MX", 16: "TXT", 24: "SIG", 25: "KEY", 27: "GPOS",
    28: "AAAA", 29: "LOC", 31: "EID", 33: "SRV", 36: "KX", 37: "CERT",
    41: "OPT", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID", 50: "NSEC3",
    51: "NSEC3PARAM", 251: "IXFR", 252: "AXFR", 255: "ALL", 65535: "RESERVED"
}
tkv = dict()
for k, v in dnstypes.iteritems():
    tkv[v] = k
DNSTYPES = dict_to_namedtuple(tkv, 'DNSTYPES')

dnsrclass = {1: 'IN', 254: 'NONE', 255: 'ANY'}
tkv = dict()
for k, v in dnsrclass.iteritems():
    tkv[v] = k
DNSRCLASS = dict_to_namedtuple(tkv, 'DNSRCLASS')

# Regex to see if data is a valid fqdn
hostname_re = re.compile(r"^(?:(?!-|[^.]+_)[A-Za-z0-9-_]{1,63}(?<!-)"
                          "(?:\.|$))$")
domainname_re = re.compile(r"^(?=.{1,253}\.?$)(?:(?!-|[^.]+_)[A-Za-z0-9-_]"
                            "{1,63}(?<!-)(?:\.|$)){2,}$")


# Some helper functions to get and set nibbles and bits. Steelscript.packets
# has some of these as well but they are written as strongly typed and only
# available in the c world.
def set_nibble(word, nibble, which=None, offset=None):
    if which is not None:
        shift = 4 * which
    elif offset is not None:
        shift = offset
    else:
        shift = 0
    return (word & ~(0xf << shift)) | (nibble << shift)


def get_nibble(word, which=None, offset=None):
    if which is not None:
        return (word >> (4 * which)) & 0xF
    elif offset is not None:
        return (word >> offset) & 0xF
    else:
        return word & 0xF


def set_bit(flags, offset):
    mask = 1 << offset
    if not flags & mask:
        return flags | mask


def unset_bit(flags, offset):
    mask = ~(1 << offset)
    if not flags & mask:
        return flags & mask


def hostname_to_label_array(hostname):
    """
    Convert a hostname or FQDN to DNS label notation. For example:
    www.riverbed.com becomes [3,119,119,119,8,114,...,100,3,99,111,109,0]
    :param hostname: A "dot notation" host name as defined in RFC 1123
    :return: DNS label notation list as shown in TCP/IP Illustrated
    Chapter 14
    """
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


def read_dns_name_bytes(byte_array, start, label_store):
    """
    reads a byte array from start until the end of a label and returns
    the 'human' representation. Handles DNS decompression of labels.
    :param byte_array: The packet data in a byte array
    :param start: The offset to start reading this label
    :param label_store: A per packet store of previously seen labels with
           their offsets in the packet data
    :return: tuple of:
            (the current position in the packet data after the label has
             been decoded,
             the human readable (dot notation) query or resource name)
    """

    read_on = True
    buff_indx = start
    labels = list()
    return_parts = list()
    while read_on:
        b1 = byte_array[buff_indx]
        if 1 <= b1 <= 63:
            # This is the first time we have seen this label OR this packet
            # is not using compression.
            c_label = byte_array[buff_indx + 1: buff_indx + 1 + b1].tostring()
            labels.append((buff_indx, c_label, ))
            return_parts.append(c_label)
            buff_indx = buff_indx + b1 + 1
        elif b1 == 0:
            # DNS name is done
            read_on = False
            buff_indx += 1
        else:
            location = struct.unpack("!H",
                                     byte_array[buff_indx: buff_indx + 2])[0]
            buff_indx += 2
            # Strip off the top two bits
            location = location & 0x3fff
            if location in label_store:
                return_parts.append(label_store[location])
                labels.append((location, label_store[location], ))
            else:
                raise ValueError("read_dns_name_bytes encountered unexpected "
                                 "compressed data in byte_array. Array bytes "
                                 "are: {0}".format(byte_array[buff_indx - 2:]))
            # Compressed labels come at the end. We break now
            read_on = False
    for index in range(len(labels)):
        cur_label = '.'.join((x[1] for x in labels[index:]))
        if cur_label not in label_store:
            label_store[cur_label] = labels[index][0]
            label_store[labels[index][0]] = cur_label
        else:
            # Suppose this packet is not using compression? But this
            # is not the first time we have seen this label so move on.
            pass
    return buff_indx, '.'.join(return_parts)


def parse_resource(byte_array, start, label_store):
    """
    Parse the data that makes of a resource record.
    :param byte_array: packet data as a byte stream
    :param start: location in the packet where this DNSResource starts
    :param label_store: A per packet store of previously seen labels with
           their offsets in the packet data. Used to call
           read_dns_name_bytes()
    :return: tuple of:
                (position in the byte stream after parsing this DNSResource,
                 arguments that make up *this DNSResource object)
    """
    buff_indx, d_name = read_dns_name_bytes(byte_array, start, label_store)
    r_type, r_class, r_ttl, r_d_len = struct.unpack(
        "!HHIH",
        byte_array[buff_indx:buff_indx + 10])
    buff_indx += 10
    if r_type in (DNSTYPES.NS, DNSTYPES.CNAME, DNSTYPES.PTR):
        buff_indx, r_data = read_dns_name_bytes(byte_array,
                                                buff_indx,
                                                label_store)
    elif r_type == DNSTYPES.A:
        r_data = socket.inet_ntop(socket.AF_INET,
                                  byte_array[buff_indx:buff_indx + 4])
        buff_indx += 4
    elif r_type == DNSTYPES.AAAA:
        r_data = socket.inet_ntop(socket.AF_INET6,
                                  byte_array[buff_indx:buff_indx + 16])
        buff_indx += 16
    else:
        r_data = byte_array[buff_indx:buff_indx + r_d_len].tostring()
        buff_indx += r_d_len
    return buff_indx, (d_name, r_type, r_class, r_ttl, r_d_len, r_data)


class DNSQuery(object):

    def __init__(self, query_name, query_type, query_class):
        """
        Simple class to wrap DNS queries
        :param query_name: The name for this query
        :param query_type: query type. See dnstypes
        :param query_class: query class. See dnsrclass
        """

        self.query_type = query_type
        self.query_class = query_class
        self.query_name = query_name

    def __repr__(self):
        return ("DNSQuery(query_name={0}, query_type={1}, query_class={2})"
                "".format(self._query_name, self._query_type,
                          self._query_class))

    @property
    def query_name(self):
        return self._query_name

    @query_name.setter
    def query_name(self, val):
        if (domainname_re.match(val) or
                hostname_re.match(val) or
                    self._query_type in (DNSTYPES.TXT,
                                         DNSTYPES.OPT)):
            self._query_name = val
        else:
            raise ValueError(
                "DNSQuery.query_name must be either a valid host name.")

    @property
    def query_type(self):
        return self._query_type

    @query_type.setter
    def query_type(self, val):
        if 0 <= val <= 0xffff:
            self._query_type = val
        else:
            raise ValueError(
                "DNSQuery.query_type must be between 0 and {0}".format(0xffff))

    @property
    def query_class(self):
        return self._query_class

    @query_class.setter
    def query_class(self, val):
        if 0 <= val <= 0xffff:
            self._query_class = val
        else:
            raise ValueError(
                "DNSQuery.query_class must be between 0 and {0}".format(
                    0xffff))


class DNSResource(object):
    """
    DNSResource(domain_name', 'res_type', 'res_class', 'res_ttl',
                 'res_len', 'res_data)
    :param domain_name: string human readable dot notation fqdn for this
           resource. www.riverbed.com or 1.in-addr.arpa
    :param res_type: type of resource A, CNAME, PTR, AAAA
    :param res_class: Class of resource. Almost always 1 for inet.
    :param res_ttl: How long this resource can live in seconds.
    :param res_len: Length in bytes of res_data
    :param res_data: Data for this resource as specified by type, class, and
           len
    """

    def __init__(self, domain_name, res_type, res_class, res_ttl,
                 res_len, res_data):
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
                          self._res_type,
                          self._res_class,
                          self._res_ttl,
                          self._res_len,
                          self._res_data))

    @property
    def domain_name(self):
        return self._domain_name

    @domain_name.setter
    def domain_name(self, val):
        if (domainname_re.match(val) or
                hostname_re.match(val) or
                val == b'' or
                self.res_type in (DNSTYPES.TXT,
                                  DNSTYPES.OPT)):
            self._domain_name = val
        else:
            raise ValueError(
                "DNSResource.domain_name must be either a valid host name.")

    @property
    def res_type(self):
        return self._res_type

    @res_type.setter
    def res_type(self, val):
        if 0 <= val <= 0xffff:
            self._res_type = val
        else:
            raise ValueError(
                "DNSResource.res_type must be between 0 and {0}"
                "".format(0xffff))

    @property
    def res_class(self):
        return self._res_class

    @res_class.setter
    def res_class(self, val):
        if 0 <= val <= 0xffff:
            self._res_class = val
        else:
            raise ValueError(
                "DNSResource.res_class must be between 0 and {0}".format(
                    0xffff))

    @property
    def res_ttl(self):
        return self._res_ttl

    @res_ttl.setter
    def res_ttl(self, val):
        if 0 <= val <= 0xffffffff:
            self._res_ttl = val
        else:
            raise ValueError(
                "DNSResource.res_ttl must be between 0 and {0}".format(
                    0xffffffff))

    @property
    def res_len(self):
        return self._res_len

    @res_len.setter
    def res_len(self, val):
        if 0 <= val <= 0xffff:
            self._res_len = val
        else:
            raise ValueError(
                "DNSQuery.res_len must be between 0 and {0}".format(
                    0xffff))

    @property
    def res_data(self):
        return self._res_data

    @res_data.setter
    def res_data(self, val):
        self._res_data = val


class DNS(PKT):
    def __init__(self, *args, **kwargs):
        super(DNS, self).__init__(*args, **kwargs)
        self.pkt_name = b'DNS'
        # get the class numeric type ID and our list of supported packet query
        # fields.
        self.pq_type, self.query_fields = DNS.query_info()
        # Call the base class from_buffer() to see if we are initializing from
        # data or kwargs
        use_buffer, self._buffer = self.from_buffer(args, kwargs)

        # Set up some internal variables and data containers.
        # initialize the flags and codes field to 0
        self._flags = 0
        # lists to hold our resource records by type
        self.queries = list()
        self.answers = list()
        self.authority = list()
        self.ad = list()
        # our label container to support label compression of names.
        self.labels = dict()
        # our current location in the buffer when parsing data.

        if use_buffer:
            # read the first 12 bytes into six unsigned shorts.
            (self.ident,
             self._flags,
             self.query_count,
             self.answer_count,
             self.auth_count,
             self.ad_count) = struct.unpack('!6H', self._buffer[:12])
            # add those 12 bytes to the buffer index.
            offset = 12
            # for each query and or resource record we have parse the data.
            if self.query_count:
                for _ in range(self.query_count):
                    # read and or update our labels
                    offset, query_name = read_dns_name_bytes(
                        self._buffer,
                        offset,
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
                    offset, resource_args = parse_resource(
                        self._buffer,
                        offset,
                        self.labels
                    )
                    self.answers.append(DNSResource(*resource_args))
            if self.auth_count:
                for _ in range(self.auth_count):
                    offset, resource_args = parse_resource(
                        self._buffer,
                        offset,
                        self.labels
                    )
                    self.authority.append(DNSResource(*resource_args))
            if self.ad_count:
                for _ in range(self.ad_count):
                    offset, resource_args = parse_resource(
                        self._buffer,
                        offset,
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
        return [DNS_PACKET_TYPE]


    def get_field_val(self, field):
        """
        The simplest form of the get_field_val function.
        :param field: name of the field
        :return:
        """
        if field in self.query_fields:
            return getattr(self, field.split('.')[1], None)
        else:
            raise AttributeError("Invalid DNS field name {0}".format(field))

    @property
    def query_resp(self):
        return (self._flags >> 15) & 1

    @query_resp.setter
    def query_resp(self, val):
        if val == 0:
            self._flags = unset_bit(self._flags, 15)
        elif val == 1:
            self._flags = set_bit(self._flags, 15)
        else:
            raise ValueError("DNS query_resp bit must be 0 or 1.")

    @property
    def op_code(self):
        return get_nibble(self._flags, offset=11)

    @op_code.setter
    def op_code(self, val):
        if 0 <= val <= 15:
            self._flags = set_nibble(self._flags, val, offset=11)
        else:
            raise ValueError("DNS op_code must be between 0 and 15.")

    @property
    def authoritative(self):
        return (self._flags >> 10) & 1

    @authoritative.setter
    def authoritative(self, val):
        if val == 0:
            self._flags = unset_bit(self._flags, 10)
        elif val == 1:
            self._flags = set_bit(self._flags, 10)
        else:
            raise ValueError("DNS authoritative bit must be 0 or 1.")

    @property
    def truncated(self):
        return (self._flags >> 9) & 1

    @truncated.setter
    def truncated(self, val):
        if val == 0:
            self._flags = unset_bit(self._flags, 9)
        elif val == 1:
            self._flags = set_bit(self._flags, 9)
        else:
            raise ValueError("DNS truncated bit must be 0 or 1.")

    @property
    def recursion_requested(self):
        return (self._flags >> 8) & 1

    @recursion_requested.setter
    def recursion_requested(self, val):
        if val == 0:
            self._flags = unset_bit(self._flags, 8)
        elif val == 1:
            self._flags = set_bit(self._flags, 8)
        else:
            raise ValueError("DNS recursion_requested bit must be 0 or 1.")

    @property
    def recursion_available(self):
        return (self._flags >> 7) & 1

    @recursion_available.setter
    def recursion_available(self, val):
        if val == 0:
            self._flags = unset_bit(self._flags, 7)
        elif val == 1:
            self._flags = set_bit(self._flags, 7)
        else:
            raise ValueError("DNS recursion_available bit must be 0 or 1.")

    @property
    def authentic_data(self):
        return (self._flags >> 5) & 1

    @authentic_data.setter
    def authentic_data(self, val):
        if val == 0:
            self._flags = unset_bit(self._flags, 5)
        elif val == 1:
            self._flags = set_bit(self._flags, 5)
        else:
            raise ValueError("DNS authentic_data bit must be 0 or 1.")

    @property
    def check_disabled(self):
        return (self._flags >> 4) & 1

    @check_disabled.setter
    def check_disabled(self, val):
        if val == 0:
            self._flags = unset_bit(self._flags, 4)
        elif val == 1:
            self._flags = set_bit(self._flags, 4)
        else:
            raise ValueError("DNS check_disabled bit must be 0 or 1.")

    @property
    def error_code(self):
        return get_nibble(self._flags, offset=0)

    @error_code.setter
    def error_code(self, val):
        if 0 <= val <= 15:
            self._flags = set_nibble(self._flags, val, offset=0)
        else:
            raise ValueError("DNS error_code must be between 0 and 15.")
