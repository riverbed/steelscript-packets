steelscript.packets.core.inetpkt API
====================================

The inetpkt defines the basic set of steelscript.packets packet classes

.. currentmodule:: steelscript.packets.core.inetpkt


:py:class:`PKT` Class
---------------------
PKT serves as the base class for all steelscript packet classes. In addition
to the functions detailed below it also provides stub implementations of two
class methods and an instance function required to support PcapQuery:

- PKT.query_info():" Returns a two element tuple. The first element is the PKT
  protocol type ID. The second element is a tuple of field names supported by
  this PKT type's get_field_val(field) function.

- PKT.default_ports(): Returns a list of layer 4 ports and is used by PcapQuery
  to build a l7_ports argument when decoding packets. Returns an empty list if
  not implemented by a PKT subclass

- Instance.get_field_val(field): Returns this packet's value for the field name
  passed in. Returned as an object. PKT class instances return None.

In addition PKT supports pkt2net(**kwargs). Each PKT class subclass must
implement this method. It provides a way for PKT classes to write themselves in
network order either to sockets or PCAP files.

.. autoclass:: PKT
   :members: __init__ get_layer get_layer_by_type from_buffer

   .. automethod:: __init__(*args, dict l7_ports={}, **kwargs)
   .. automethod:: get_layer(name, instance=1, found=0)
   .. automethod:: get_layer_by_type(pq_type, instance=1, found=0)
   .. automethod:: from_buffer(*args, **kwargs)


:py:class:`Ethernet` Class
--------------------------
.. autoclass:: Ethernet
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

Ethernet PcapQuery supported fields:
   - eth.type: returns Ethernet.type
   - eth.src: returns Ethernet.src_mac
   - eth.dst: returns Ethernet.dst_mac


:py:class:`IP` Class
--------------------
RFC 791 Internet Protocol with flag bit zero implemented as x or 'evil' bit.::

   +0                   1                   2                   3  +
   +0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1+
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

.. autoclass:: IP
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(csum=0, update=0, ipv4_pheader=None)

IP PcapQuery supported fields:
   - ip.version: returns IP.version
   - ip.hdr_len: returns IP.iphl
   - ip.tos: returns IP.tos
   - ip.len: returns IP.total_len
   - ip.id: returns IP.ident
   - ip.flags: returns IP.flags
   - ip.flags.df: returns IP.flag_d
   - ip.flags.mf: returns IP.flag_m
   - ip.frag_offset: returns IP.frag_offset
   - ip.ttl: returns IP.ttl
   - ip.proto: returns IP.proto
   - ip.src: returns IP.src
   - ip.dst: returns IP.dst
   - ip.checksum: returns IP.checksum


:py:class:`ARP` Class
---------------------
Implements RFC 826 Address Resolution Protocol. See schematic to follow::

   +0                   1                   2                   3  +
   +0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1+
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Hardware Type        |         Protocol Type         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Hardware Len |    Proto Len  |           Operation           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Sender Hardware Addr (Hardware Len Bytes)           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Sender Protocol Addr (Proto Len Bytes)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Target Hardware Addr (Hardware Len Bytes)           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Target Protocol Addr (Proto Len Bytes)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

.. autoclass:: ARP
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

ARP PcapQuery supported fields:
   - arp.hw.type: returns ARP.hardware_type
   - arp.proto.type: returns ARP.proto_type
   - arp.hw.size: returns ARP.hardware_len
   - arp.proto.size: returns ARP.proto_len
   - arp.opcode: returns ARP.operation
   - arp.src.hw_mac: returns ARP.sender_hw_addr
   - arp.src.proto_ipv4: returns ARP.sender_proto_addr
   - arp.dst.hw_mac: returns ARP.target_hw_addr
   - arp.dst.proto_ipv4: returns ARP.target_proto_addr


:py:class:`UDP` Class
---------------------
Implements RFC 768 User Datagram Protocol. See schematic to follow::

   +0      7 8     15 16    23 24    31+
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

.. autoclass:: UDP
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

UDP PcapQuery supported fields:
   - udp.srcport: returns UDP.sport
   - udp.dstport: returns UDP.dport
   - udp.length: returns UDP.ulen
   - udp.checksum: returns UDP.checksum
   - udp.payload: returns UDP.payload as bytes
   - udp.payload.offset[x:y]: returns UDP.payload bytes x to y as bytes

:py:class:`TCP` Class
---------------------
Implements RFC 793 Transmission Control Protocol with some additions and
limited options support. See schematic to follow::

   +0                   1                   2                   3  +
   +0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1+
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

.. autoclass:: TCP
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

TCP PcapQuery supported fields:
   - tcp.srcport: returns TCP.sport
   - tcp.dstcport: returns TCP.dport
   - tcp.seq: returns TCP.sequence
   - tcp.ack: returns TCP.acknowledgment
   - tcp.hdr_len: returns TCP.data_offset
   - tcp.len: returns TCP.ws_len
   - tcp.flags: returns TCP.flags
   - tcp.flags.urg: returns TCP.flag_urg
   - tcp.flags.ack: returns TCP.flag_ack
   - tcp.flags.push: returns TCP.flag_psh
   - tcp.flags.reset: returns TCP.flag_rst
   - tcp.flags.syn: returns TCP.flag_syn
   - tcp.flags.fin: returns TCP.flag_fin
   - tcp.window_size_va: returns TCP.window
   - tcp.checksum: returns TCP.checksum
   - tcp.urgent_pointer: returns TCP.urg_ptr
   - tcp.payload: returns TCP.payload as bytes
   - tcp.payload.offset[x:y: returns TCP.payload bytes x to y as bytes


:py:class:`MPLS` Class
----------------------
.. autoclass:: MPLS
   :members: __init__ query_info default_ports get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: default_ports
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

MPLS PcapQuery supported fields:
   - mpls.top.label: returns first MPLS.label where MPLS.s is 0
   - mpls.top.tc: returns first MPLS.tc where MPLS.s is 0
   - mpls.top.stack_bit: returns first MPLS.s where MPLS.s is 0
   - mpls.top.ttl: returns first MPLS.ttl where MPLS.s is 0
   - mpls.bottom.label: returns MPLS.label where MPLS.s is 1
   - mpls.bottom.tc: returns MPLS.tc where MPLS.s is 1
   - mpls.bottom.stack_bit: returns MPLS.s where MPLS.s is 1
   - mpls.bottom.ttl: returns MPLS.ttl where MPLS.s is 1

NOTE: There should only ever be a single MPLS layer in a packet with the s bit
set to 1. There can be a number with bottom of stack bit set to 0



:py:class:`NullPkt` Class
-------------------------
.. autoclass:: NullPkt
   :members: __init__ query_info get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, data=b'')
   .. automethod:: query_info
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)


:py:class:`Ip4Ph` Class
-----------------------
.. autoclass:: Ip4Ph
   :members:

   .. automethod:: __init__(src, dst, reserved, proto, payload_len)


:py:class:`NetflowSimple` Class
-------------------------------
.. autoclass:: NetflowSimple
   :members: __init__ query_info default_ports get_field_val pkt2net
   :show-inheritance:

   .. automethod:: __init__(*args, **kwargs)
   .. automethod:: query_info
   .. automethod:: default_ports
   .. automethod:: get_field_val(field)
   .. automethod:: pkt2net(**kwargs)

NetflowSimple PcapQuery supported fields:
   - netflow.version: returns NetflowSimple.version
   - netflow.count: returns NetflowSimple.count
   - netflow.sys_uptime: returns NetflowSimple.sys_uptime
   - netflow.unix_secs: returns NetflowSimple.unix_secs
   - netflow.unix_nano_seconds: returns NetflowSimple.unix_nano_seconds