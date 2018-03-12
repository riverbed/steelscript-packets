.. py:currentmodule:: steelscript.packets.core.inetpkt

SteelScript Packets Tutorial
=============================

This tutorial will show you how to decode and create packets, create packets
classes, plus read, write and query pcap files using  steelscript packets.
This tutorial assumes a basic understanding of Python (if not, see the
`Beginner's Guide to Python
<http://wiki.python.org/moin/BeginnersGuide>`_).  In addition, you should be
somewhat familiar with sockets, packets, and general low level networking
ideas.

Throughout the examples, you will be expected to fill in details specific to
your environment.  These will be called out using a dollar sign ``$<name>`` --
for example ``$dst_host`` indicates you should fill in the host name or IP
address of a destination host.

Whenever you see ``>>>``, this indicates an interactive session using the
Python shell.  The command that you are expected to type follows the ``>>>``.
The result of the command follows.  Any lines with a ``#`` are just comments
to describe what is happening.  In many cases the exact output will depend on
your environment, so it may not match precisely what you see in this tutorial.


Steelscript Packets Overview
----------------------------

Steelscript Packets provides a set of low level classes to create, decode,
and query packet and pcap data. The libraries are written in Cython and
compiled into Python extensions. They are divided into inetpkt, pcap, and
pcap_query modules. This tutorial will show you how to add a additional
protocol into steelscript.packets protos namespace. First as a pure python
implementation and then as a Cython extension.

This tutorial will cover a range of topics starting with basic packet creation.
From there we will develop examples of:

   - Sending a receiving PKT based packets with raw python sockets.
   - Reading and writing packets from PCAP files.
   - Building a :py:class:`PKT <PKT>` based layer 7 packet class in pure python. In our case we will build DNS
   - Converting the python based DNS class to a cython based class.
   - Using PcapQuery to query data from built in :py:class:`PKT <PKT>` based classes.
   - Using our own :py:class:`PKT <PKT>` based DNS class with PcapQuery. We will do this both with the pure Python implantation and our Cython implantation.



Steelscript Packets Basic Uses
------------------------------

To start, start python from the shell or command line:

.. code-block:: bash

   $ python
   Python 2.7.5 (default, Nov  6 2016, 00:28:07)
   [GCC 4.8.5 20150623 (Red Hat 4.8.5-11)] on linux2
   Type "help", "copyright", "credits" or "license" for more information.
   >>>

Building a basic Ethernet packet
--------------------------------

.. code-block:: python

   >>> from steelscript.packets.core.inetpkt import Ethernet, ETHERTYPES

   >>> eth_pkt1 = Ethernet(src_mac='00:00:00:00:00:00',
   >>>                     dst_mac='ff:ff:ff:ff:ff:ff',
   >>>                     type=ETHERTYPES.ipv4)

   >>> eth_pkt1.type
   2048
   >>> kw_args = dict()
   >>> eth_pkt1.pkt2net(kw_args)
   '\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00'


This was a humble start to be sure but lets take a look at it step by step.
The fist step was to import Ethernet and the ETHERTYPES constants from inetpkt.
Then we built a single Ethernet packet with src_mac, dst_mac and type
arguments. Technically only the dst_mac argument was required since the other
two are the default values. Next we called eth_pkt1's type property.
:py:class:`PKT <PKT>` based classes pkt2net method requires a single
keyword dictionary argument. Ethernet itself does not support any keyword args
but would pass them along to sub layers if they existed. So we created
kw_args and used it to call pkt2net(). The output is eth_pkt1 as bytes in
network order.

Building an Ethernet-IP-UDP packet
----------------------------------

Lets look at a full :py:class:`Ethernet <Ethernet>`-:py:class:`IP <IP>`-:py:class:`UDP <UDP>`
example.

We will use this same packet shortly to show sending a packet out on the
network. So you will need to have the following values available:

- local_iface_name: The name of the local interface you want to use (eg.
   'eth0', 'em0', 'enp0s8')
- src_mac: local MAC address. `ifconfig` command should show this. On my test
   system it is '08:00:27:f4:6b:ac'
- dst_mac: A remote mac address you would like to send this packet to. I will
   be sending this packet through a router so I will use the MAC address of my
   default gw. If your target system is on the same broadcast network as your
   test system them you can use the target systems MAC address.
- src_ip: The source IPv4 address. The IP address of the local interface.
- dst_ip: The destination IPv4 address.

.. code-block:: python

   >>> from steelscript.packets.core.inetpkt import Ethernet, IP, UDP, PROTO

   >>> pkt = Ethernet(dst_mac='$dst_mac',
   >>>                src_mac='$src_mac',
   >>>                payload=IP(src='$src_ip',
   >>>                           dst='$dst_ip',
   >>>                           proto=PROTO.udp
   >>>                           payload=UDP(sport=45678,
   >>>                                       dport=1025,
   >>>                                       payload=b'Our Test UDP Packet')
   >>>                           )
   >>>                )

   >>> kw_args = {'csum': 1, 'update': 1}

   >>> pkt.pkt2net(kw_args)
   '\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x00/\x00\x00\x00\x00@\x111j\xc0\xa8d\x01\xc0\xa8d\x02\xb2n\x04\x01\x00\x1b\xb0\xc5Our Test UDP Packet'
   >>>
   >>> # Now we want to directly access a PKT sub layer of the Ethernet packet.
   >>>udp = pkt.get_layer('UDP')

   >>>udp.payload
   'NullPkt: Our Test UDP Packet'

Notice what happened with the UDP layers payload. Because UDP had no l7_ports
entry for port 1025 it did not attempt to decode 'Our Test UDP Packet' as
packet data. It simply placed the data, as is, into the payload of a NullPkt
object. NullPkt's basic function is to store packet data that can't be decoded.
The user can then dive into the NullPkt payload and perform their own analysis
or, more likely, ignore those packets.

Another key item to note is that the IP proto had to be set. Other packet
Libraries will do "smart" things like set this for you. steelscript.packets
has its origins in testing so it will rarely intercede to correct mistakes. We
assume you have a good reason if you set the Ethertype to ARP and then make the
Ethernet payload IP.


Sending a Ethernet-IP-UDP packet with a RAW socket
--------------------------------------------------

For this exercise we are going to use the same packet from above. The steps
are:

#. Build a socket.
#. Build the packet. We will skip this because we built the packet above.
#. tcpdump on the destination host to see if the packet arrives.
#. Send the packet.

Note: Because of the use of the use of the AF_PACKET socket family and the use
of SOCK_RAW these tutorial steps must be done on Linux as the root user.
AF_PACKET does not exist on MacOS and SOCK_RAW always requires root privileges.

.. code-block:: python

   >>> import socket

   >>> sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, proto=0)
   >>> # common values for $local_iface are 'eth0', 'eth1' ...
   >>> sock.bind(('$local_iface_name', 0))
   >>> sock.setblocking(0)

   >>> # Now send the packet
   >>> bytes_sent = sock.send(pkt.pkt2net(kw_args))
   >>> if bytes_sent == len(pkt.pkt2net(kw_args)):
   >>>     print "All packet bytes sent."
   >>> else:
   >>>     print "Send failed for some reason."
   "All packet bytes sent."

A quick note about the proto argument on a RAW socket. You can also,
optionally, use the protocol number for the protocol you want to send instead
of specifying 0 as the protocol. The 0 here is not necessary as it is the
default. If you are willing to craft all parts of the packet data, as
we are here, then it seems to work fine. If you are interested in experimenting
with other values then see ETH_P* values defined in if_ether.h (linux)

IMPORTANT: If you do try a number other than 0 remember to run it through
socket.ntohs() to pack it into 16bits in the correct order. Obviously not
something that is required for 0. You will see an example of this in the next
section.

Sending and Receiving Packets: An ARP example
---------------------------------------------
For this section we are going to build an ARP packet, send it, then listen for
a reply. When the reply comes we will decode it and see what the response
contains.

.. code-block:: python

   >>> import socket
   >>> # See ETH_P_ALL in if_ether.h We will use this value to make sure our
   >>> # Recv socket gets ALL packets.
   >>> ETH_P_ALL = 3
   >>> from steelscript.packets.core.inetpkt import Ethernet, ARP, ETHERTYPES

   >>> # Build a send and receive socket.
   >>> s_snd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
   >>> s_snd.bind(('$local_iface_name', 0))
   >>> # NOTE this one is slightly different
   >>> s_rec = socket.socket(socket.AF_PACKET,
   >>>                       socket.SOCK_RAW,
   >>>                       proto=socket.htons(ETH_P_ALL))
   >>> s_rec.bind(('$local_iface_name', 0))
   >>> s_rec.setblocking(0)
   >>> # Lets only wait 2 seconds for a response.
   >>> s_rec.settimeout(2)

In this last section we built a send and receive socket. The only things
different about the receive socket is that we set its protocol to a special
value defined in if_ether.h that receives info on all packet types. As I
understand it that makes this socket be in something akin to promiscuous mode.
We also made sure the receive socket would not block if no data were present
and has a timeout of 2 seconds.

Now we can build the ARP packet. We want to listen for the response to this
packet so it is important to use the real MAC address of the local system. For
this exercise pick a target IP address you know is on your local network. Ping
it to make sure it is listening. We will call that IP address the '$target_ip'

.. code-block:: python

   >>> pkt = Ethernet(src_mac='$src_mac',
                      dst_mac='ff:ff:ff:ff:ff:ff',
                      type=ETHERTYPES.arp,
                      payload=ARP(sender_hw_addr='$src_mac',
                                  sender_proto_addr='$src_ip',
                                  target_proto_addr='$target_ip')
                     )

   >>> # Now to send the ARP and get the response back.
   >>> # We don't need to see more than 1500 bytes of any packet.
   >>> DEFAULT_MTU = 1500
   >>> s_snd.send(pkt.pkt2net({}))

   >>> while True:
   >>>     try:
   >>>         pkt_data = s_rec.recv(DEFAULT_MTU)
   >>>         p = Ethernet(pkt_data)
   >>>         if (p.type == ETHERTYPES.arp):
   >>>             arp_pkt = p.get_layer('ARP')
   >>>             if (arp_pkt.target_proto_addr == '$src_ip' and
   >>>                 arp_pkt.target_hw_addr == '$src_mac' and
   >>>                 arp_pkt.sender_proto_addr == '$target_ip'):
   >>>                     print("The MAC address for {0} is {1}".format(
   >>>                         '$target_ip',
   >>>                         p.payload.sender_hw_addr)
   >>>                     )
   >>>                     break
   >>>     except:
   >>>         print "Did not get reply."
   >>>         break
   The MAC address for 192.168.56.1 is 08:00:27:54:f5:ae

Assuming the correct values were correct you will get something like the output
above. Lets go through this line by line.

#. First we build an ARP packet using our MAC address as the src and the
   broadcast MAC address as the destination.
#. We added our MAC and IP as the sender info in the actual ARP part of the
   packet.
#. Then we used our sender socket to send the packet. Note that Ethernet and
   ARP don't have options for pkt2net() so we could use an empty dictionary for
   the kwargs.
#. Above we had set the timeout on the receive socket to be 2 seconds. So we
   can safely loop around waiting on an exception or a response. The exeception
   will happen at 2 seconds.
#. Within the while/try loop we try to read 1500 bytes of data off the socket
   and initialize an Ethernet packet from the data. If the ethernet packet's
   type is ARP we get the ARP portion of that packet as arp_pkt.
#. If the ARP data matches a response to our ARP request then the
   sender_hw_addr will be the MAC address we are looking for.

In short we have ARPed for a MAC address manually. You may wonder why I didn't
set the target_hw_addr in the request. That is because the ARP classes default
value of '00:00:00:00:00' is correct for an arp request. In addition the ARP
class has a default value of 1 (request) for operation so we don't have to set
that either.


Reading and Writing Packets from PCAP files
-------------------------------------------
This next section will go over the mechanics of reading and writing packet
data from PCAP files. Steelscript.packets has support both libpcap format PCAP
files and the newer PCAPNG files. The PCAPNG implementation does not cover all
features of PCAPNG. However, it will read PCAPNG network captures as created
by the popular Wireshark set of tools. It is mean to provide a feature set
equivalent to the features supported for libpcap PCAP format.

The file we are going to use for this exercise is :download:`http.pcap`

Before going on save that file to the your current directory.

If you were to open that file in Wireshark you would note that it has 11 tcp
packets. The host 10.38.130.25 is the server listening on port 80. The
connection is initiated by host 10.38.64.13. The packets from 10.38.64.13 have
invalid checksums. This is probably because this was the capture host and the
checksum operation was being offloaded to the NIC. The packets would have been
captured prior to that operation. But we want to do two things. One is to
'anonymize' the packets by changing the IP addresses. Since the original IP
addresses are already RFC1918 addresses this would not really be nessesary. The
second thing is to correct the checksums. To do those things we will:

#. Open 'http.pcap' for read.
#. Open 'http_fixed.pcap' for write.
#. Create a PCAPReader object using the open 'http.pcap' file handle as the
   single argument.
#. Create a PCAPWriter object using the open 'http_fixed.pcap' file handle
   as the single argument.
#. For each packet we will change the following items:

   #. Change IP address 10.38.64.13 to 192.168.1.1
   #. Change IP address 10.38.130.25 to 192.168.101.101

#. Write the packet to the PCAPWriter with the checksums re-calculated.
#. Close the files.

Here is the code:

.. code-block:: python

   >>> from steelscript.packets.core.pcap import PCAPReader, PCAPWriter
   >>> from steelscript.packets.core.inetpkt import Ethernet

   >>> f_read = open('./http.pcap', 'rb')
   >>> f_write = open('./http_fixed.pcap', 'wb+')

   >>> rdr = PCAPReader(f_read)
   >>> wrtr = PCAPWriter(f_write)

   >>> # PCAPReader is an iterator that yields a tuple of:
   >>> #     packet timestamp, pkt bytes (network order array.array of unsigned
   >>> #     chars), and packet the ethertype
   >>> # 1 is the ethertype value for Ethernet packets
   >>> pkt_type_ethernet = 1
   >>> # a set of keywork args for our call to pkt2net. Checksum and update
   >>> # length variables.
   >>> pkt2net_args = {'csum': 1, 'update': 1}

   >>> for pkt_ts, pkt_data, pkt_type in rdr:
   >>>     if pkt_type == pkt_type_ethernet:
   >>>         pkt = Ethernet(pkt_data)
   >>>         ip = pkt.get_layer('IP')
   >>>         if ip.pkt_name == 'IP':
   >>>             if ip.src == '10.38.64.13':
   >>>                 ip.src = '192.168.100.1'
   >>>             if ip.dst == '10.38.64.13':
   >>>                 ip.dst = '192.168.100.1'
   >>>             if ip.src == '10.38.130.25':
   >>>                 ip.src = '192.168.100.101'
   >>>             if ip.dst == '10.38.130.25':
   >>>                 ip.dst = '192.168.100.101'
   >>>         wrtr.writepkt(pkt.pkt2net(pkt2net_args), pkt_ts)

   >>> rdr.close()
   >>> wrtr.close()

Lets take a look at what happened in the main for loop. This naturally starts
with the tuple returned by iterating into the rdr object. We get the packet
timestamp, packet data, and packet type. From there we do the following:

#. Check that the packet data returned is actually for an Ethernet packet.
#. Assuming that it is we initialize an Ethernet PKT instance from the data.
#. Get the IP layer of the packet. get_layer() will return the IP layer if it
   exists OR will return a NullPkt if no IP layer is present.
#. Test to see if the PKT object we got back from get_layer is actually and IP
   packet. If it is then replace the IP addresses.
#. Use PCAPReaders ``writepkt()`` function to write the packet to the new PCAP
   file. Not that we use the pkt2net_args from above to force checksum
   calculation.
#. Finally we call close on both the reader and writer. This will, in turn call
   close on the underlying files.

You can now open up the http_fixed.pcap file and find that the packets are all
present with exactly the same timestamps. Only the IPs have changes and all
packets now have appropriate checksums.


Building a PKT based packet class in pure Python
------------------------------------------------

This example is going to be a bit longer than the preceding examples. For this
example we are going to partially implement the DNS layer 7 protocol. We will
add specific support for NS, CNAME, PTR, A, and AAAA records. In addition the
class will have generic (un-parsed) support for a number of other record types.

DNS uses a hostname compression scheme and our example will support that. Our
class has support for a label store and I provide some comments describing DNS
labels. I will not fully describe how those functions operate because the
purpose of this document is to provide information on steelscript.packets. For
anyone interested I suggest looking at 'TCP/IP Illustrated, Volume 1: The
Protocols' by Kevin R. Fall and W. Richard Stevens. There is a chapter on DNS
that includes a description of DNS compression.

The focus of this section will be on showing the user how build a PKT type
starting with a schematic of a packet type and, hopefully, some accompanying
documentation of the packet type's field relationships. The PKT type will be
able to initialize off of data (a byte sting or array.array of unsigned chars),
or it can be initialized from keyword arguments. In addition I will implement
the methods required to support pcap_query. Those are the class methods
query_info() and default_ports() plus the standard method get_field_val()

The following specification is from RFC 1035 section 4. Note that this
schematic includes the security extensions defined in RFC 2065::

    +                               1  1  1  1  1  1+
    + 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5+
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    +                      ID                       +
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    +QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   +
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    +                    QDCOUNT                    +
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    +                    ANCOUNT                    +
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    +                    NSCOUNT                    +
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    +                    ARCOUNT                    +
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

- ID: a 16 bit identifier generated by the program that created the query. ID
  is implemented in our packet class as the property 'ident'.
- QR: a flag indicating if this is a query or response. Implemented in the
  example class as 'query_resp'.
- OPCODE: 4 bit operation code. Per RFC1035: value 0 is for standard query, 1
  for inverse query, 2 for server status. Per wikipedia: 'if the value is 1,
  the present packet is a reply; if it is 2, the present packet is a status;
  if the value is 0, the present packet is a request.' 'op_code' in our
  example.
- AA: Flag indicating if the server is an authority for the record.
  'authoritative' in our example.
- TC: Flag indicating if the message was truncated. 'truncated' in our example.
- RD: Recursion desired flag. Set on a query if the client would like the
  server to pursue the record recursively on its behalf. 'recursion_requested'
  in the example.
- RA: Recursion available flag. Set in a response to indicate if the server
  can perform recursive queries. 'recursion_available' in the example.
- Z: always set to 0. Not implemented.
- AD: Defined in RFC 2065 as 'authentic data'. 'authentic_data' in the example.
- CD: Defined in RFC 2065 as 'checking disabled'. 'check_disabled' in the
  example.
- RCODE: Response code. 0 for no errors other values in RFC 1035. 'resp_code'
  in the example.
- QDCOUNT: 16bits. Number of queries in this packet. 'query_count' in the
  example.
- ANCOUNT: 16bits. Number of answers in this packet. 'answer_count' in the
  example.
- NSCOUNT: 16bits. Number of name server resource records in this packet.
  'auth_count' in the example.
- ARCOUNT: 16bits. Number of additional resource records in this packet.
  'ad_count' in the example.

First thing that pops out at us is that this packet type consists of 6
unsigned short values. The second one contains the flags and codes. So parsing
this packet will be fairly simple. A single call to
``stuct.unpack('!6H', <data>)`` will be sufficient to unpack this data.
'!6H' means the following: '!' in network order, '6' the count of values,
'H' is the struct modules code for unsigned 16 bits (short). So naturally
we pass this call 12 bytes of the packet. All of the examples that follow
come directly from the `dns_purepy.py` file that is in the protos sub directory
of the steelscript.packets package.

.. code-block:: python

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
            self.buff_indx = 0

            if use_buffer:
                # read the first 12 bytes into six unsigned shorts.
                (self.ident,
                 self._flags,
                 self.query_count,
                 self.answer_count,
                 self.auth_count,
                 self.ad_count) = struct.unpack('!6H', self._buffer[:12])
                # add those 12 bytes to the buffer index.
                self.buff_indx = 12
                # for each query and or resource record we have parse the data.
                if self.query_count:
                    for _ in range(self.query_count):
                        # read and or update our labels
                        self.buff_indx, query_name = read_dns_name_bytes(
                            self._buffer,
                            self.buff_indx,
                            self.labels
                        )
                        # unpack the remainder of the query.
                        query_type, query_class = struct.unpack(
                            '!HH',
                            self._buffer[self.buff_indx:self.buff_indx + 4]
                        )
                        self.queries.append(DNSQuery(query_name,
                                                       query_type,
                                                       query_class))
                        self.buff_indx += 4
                # Now unpack the resources by the 3 remaining types.
                if self.answer_count:
                    for _ in range(self.answer_count):
                        self.buff_indx, resource_args = parse_resource(
                            self._buffer,
                            self.buff_indx,
                            self.labels
                        )
                        self.answers.append(DNSResource(*resource_args))
                if self.auth_count:
                    for _ in range(self.auth_count):
                        self.buff_indx, resource_args = parse_resource(
                            self._buffer,
                            self.buff_indx,
                            self.labels
                        )
                        self.authority.append(DNSResource(*resource_args))
                if self.ad_count:
                    for _ in range(self.ad_count):
                        self.buff_indx, resource_args = parse_resource(
                            self._buffer,
                            self.buff_indx,
                            self.labels
                        )
                        self.ad.append(DNSResource(*resource_args))

In the above code snippet we can see the basics of parsing packets from sockets
or from PCAP data. For the DNS header we have a static 12 byte data segment to
parse. The name portion of a query and the size of a resource record are
variable so parsing them means using the packets hints to determine how much
data to read. Lets take a look at read_dns_name_bytes() to see how we do that
with DNS names (compressed or otherwise).

.. code-block:: python

   def read_dns_name_bytes(byte_array, start, label_store):

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

The key thing to note in this piece of code is that DNS names are always
terminated by a byte with the value 0. A DNS name may also be encoded
(compressed) as described in section 4.1.4 of RFC 1035. The key thing to note
is that a name will be present in one of two formats. First it may look like:

'3www8riverbed3com0' actually encoded as 3,119,119,119,8,114,105...,0

or if that riverbed.com had first been seen at byte 16 of the DNS packet AND
the name we wanted to represent was 'mx1.riverbed.com' that would be encoded as
3,109,120,49,192,16

The last '192,16' part is of the most interest. In binary those two bytes are
0b1100000000010000. The first two bits signify that this is not a length
designation but an offset designation. The '010000' portion of the remaining
bits are 16 in binary. So the message is that the next label is present in this
packet at byte 16 and you should read it from that location. So to construct
mx1.riverbed.com you read the 'mx1' part at the current location and then
append whatever label is found starting at byte 16. In our example that would
be riverbed.com IF www.riverbed.com started at byte 12.

Knowing that we can see that the code above reads a single byte into its
buffer. The top two bits of this byte specify if it is a location rather than
a label. That means the max size of a label must be 63 bytes since that is the
max value of 6 bits. If the value is between 1 and 63 this is a label so we
read it, add it to our temporary store and then index to the next label,
location, or termination. If the value is 0 we stop reading and index past.
Otherwise the value is a location and we read the location data. Lastly we
parse all the labels we have found, update their entries in the instance
label_store, and finally return our current location in the buffer and the
full name.

What I hope I have shown in these last two examples is the basic mechanics of
parsing packets. For the most part packets have three basic types of fields.
The first are fixed fields. They are always present and always the same size.
The first piece of code showing the DNS classes ``__init__()`` function showed
the basics of parsing these fields. The other two types are variable size and
conditional fields. DNS does not have conditional fields but the mechanics of
variable sized fields are fundamentally similar. In either case there will be
clues within the packet data to tell you about the data that follows. In the
case of DNS we have the query, answer, auth, and ad count variables letting
us know if we should attempt to parse query and or resource record fields.
Within both of those data types we have the conventions for encoding names into
labels to tell us how much data we should read for a given name field. There
are a number of other conventions used in other protocols and most are
documented fairly well in RFCs or other sources.

Using Our Example Class - Quick Demo
------------------------------------

Lets do a quick demo of using our DNS class to decode a couple of DNS packets
and print out the details. We will go further into this after we demonstrate
converting this class to a Cython class.

The file we are going to use for this exercise is :download:`dns.pcap`

.. code-block:: python

   >>> from steelscript.packets.core.pcap import PCAPReader
   >>> from steelscript.packets.core.inetpkt import Ethernet
   >>> from steelscript.packets.protos.dns_purepy import DNS

   >>> dns_file = open("dns.pcap", 'rb')
   >>> dns_rdr = PCAPReader(dns_file)
   >>> """
   >>> Now we create a l7_ports argument. This will be used by layer 4 protos
   >>> like (in this case) UDP to determine what class they should use to
   >>> decode their payload. It is a dictionary and they keys are the l4
   >>> port numbers and the values are the classes to be used. In this case
   >>> DNS returns a one element array of default ports [53] so we just take
   >>> the first one.
   >>> """
   >>> l7_ports = {DNS.default_ports()[0]: DNS}
   >>> # only want the data so assign the timestamp and type to nothing.
   >>> _, pkt_data, _ = dns_rdr.next()
   >>> dns_pkt = Ethernet(pkt_data, l7_ports=l7_ports)
   >>> dns = dns_pkt.get_layer('DNS')
   >>> dns.query_count
   1
   >>> dns.queries[0]
   DNSQuery(query_name=riverbed.com, query_type=1, query_class=1)
   >>> _, pkt_data, _ = dns_rdr.next()
   >>> dns_pkt2 = Ethernet(pkt_data, l7_ports=l7_ports)
   >>> dns2 = dns_pkt2.get_layer('DNS')
   >>> dns2.answer_count
   1
   >>> dns2.answers[0]
   DNSResource(domain_name=riverbed.com, res_type=1, res_class=1, res_ttl=300, res_len=4, res_data=208.70.196.59)
   >>> dns2.auth_count
   4
   >>> dns2.authority[0]
   DNSResource(domain_name=riverbed.com, res_type=2, res_class=1, res_ttl=432000, res_len=6, res_data=ns2.riverbed.com)

Some notes about these values. The top of dns_purepy.py has some dictionaries
you can use to decode the meanings of some of these values. You will not that
the class is 1 in all of these. in the dnsrclass dict you will note that 1
stands for 'IN' which, in turn, stands for internet. The type values are in
dnstypes. 1 is 'A' and 2 is 'NS'

Using a custom PKT based class with PcapQuery
---------------------------------------------

This next code snippet is simply to introduce you to pcap_query and show you
that this pure python class can be used with it.

.. code-block:: python

   >>> # To the above imports we add one more.
   >>> from steelscript.packets.query.pcap_query import PcapQuery
   >>> # Rewind back to the start of the DNS pcap file so we read all
   >>> # packets.
   >>> dns_file.seek(0)
   >>> fields = ['frame.time_epoch', 'ip.src', 'ip.dst', 'udp.srcport',
   >>>           'udp.dstport', 'dns.query_count', 'dns.answer_count',
   >>>           'dns.auth_count']
   >>> # pcap_query can convert timestamps into datetime objects if desired.
   >>> # Not doing that here.
   >>> pq.pcap_query(file_handle=dns_file,
   >>>               wshark_fields=fields,
   >>>               starttime=0.0,
   >>>               endtime=0.0,
   >>>               as_datetime=0)
   [[1493834478.390878, '192.168.255.160', '192.168.255.1', 49883, 53, 1, 0, 0],
    [1493834478.51328, '192.168.255.1', '192.168.255.160', 53, 49883, 1, 1, 4],
    [1493834485.406963, '192.168.255.160', '192.168.255.1', 57556, 53, 1, 0, 0],
    [1493834485.490302, '192.168.255.1', '192.168.255.160', 53, 57556, 1, 4, 4],
    [1493834493.955906, '192.168.255.160', '192.168.255.1', 52047, 53, 1, 0, 0],
    [1493834493.978792, '192.168.255.1', '192.168.255.160', 53, 52047, 1, 5, 0]]


Converting the Python Based DNS Class to a Cython Based Class
-------------------------------------------------------------

There are some advantages to implementing our DNS class in Cython. They mostly
have to do with memory efficiency and speed. In the case of steelscript.packets
there are also some helper functions for setting and getting bits and nibbles
that are cdef functions and therefor not available to a pure python class. This
is the reason that dns_purepy.py has the functions set_nibble, get_nibble,
set_bit, and get_bit. We will get rid of those as we convert to Cython and use
the faster strongly typed ones in steelscript.packets.

Converting to Cython mostly has to do with strongly typing our classes. For
example, our DNS header is made up of 6 unsigned shorts. So we will simply
define 6 uint16_t variables in our dns.pxd file for the DNS class. In the
DNSResource class we will be able to get rid of some of the getter and setter
functions because Cython will enforce value limitations on type. And,
conversely, the ident, query_count, answer_count, auth_count, and ad_count
variables in the header will be protected as if they had setter functions
without any of the overhead.

While we convert to Cython we are also going to implement a ``pkt2net()``
function for the DNS class to allow us to write DNS packets to a socket or PCAP
file.

The complete code for these examples is in the files `dns.pyx` and `dns.pxd` in
the same directory as dns_purepy.py. `.pyx` files are Cython implementation
files. They serve the same function as `.c` or `.cpp` files in c and c++.
`.pxd` file serve the same function as `.h` files in the c languages. They
are used to define variables and function signatures. They are necessary if
you want your classes and functions to `cimport` into other Cython code.

Lets look at the delaration of the DNS class in `dns.pxd`:

.. code-block:: cython

   cdef class DNS(PKT):
       cdef:
           array _buffer
           public uint16_t ident, query_count, answer_count, auth_count, ad_count
           uint16_t _flags
           public list queries, answers, authority, ad
           dict labels

       cpdef object get_field_val(self, bytes field)

       cpdef bytes pkt2net(self, dict kwargs)

Notice that each variable has been declared with a type. Some are declared
public so that outside code can directly access them. All those not specified
public are private and internal to the class only.

Another change is the way get_field_val is declared:

.. code-block:: cython

    cpdef object get_field_val(self, bytes field):
        """
        ...
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

Note that the return type is object. This is because the fields have many
different types. It is simpler to define it as object and let the Cython worry
about how to cast them. Also, this code is now a large set of if, elif, else.
That pattern is used because under the covers Cython re-writes this in c as a
very efficient case switch block.

Inside the DNS class definition you can also see that all internal variable
have been declared with a type.

.. code-block:: cython

   cdef class DNS(PKT):
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

But the basic implementation is identical with the exception of the class
property getter and setter functions. They are implmented in the older Cython
manner on purpose. Cython does support Python's `@property` decorator. The
problem is that I chose to use a pointer to the _flags field because that is so
much more efficient under c. For some reason this raises an error when using
the `@property` decorator.

A quick note on Cython pointers. To declare a pointer you write `<type>* name`.
For example a pointer to a int would be `int* int_pntr`. You can't create a
pointer to a Python type like a list or dict. To get the address of a variable
to assign to a pointer you do `&variable`. The only part that is not intuitive
is how Cython dereferences pointers. To dereference `int_pntr` from above and
get the int's value you would do `int_pntr[0]`. I always declare a static enum
PNTR or POINTER set to 0 so that it is easy to read. `int_pntr[0]` looks like
list indexing and might confuse. `int_pntr[PNTR]` at least provides a clue that
list indexing is not in play.

The only other big change is that we implemented writing DNS packets out in
network order. To do that we implemented `DNS.pkt2net()` and the accompanying
`pack()` functions in the DNSQuery and DNSResource classes. The following
section covers the basics of packing objects in network order.

Implementing a network order packing function - pkt2net()
---------------------------------------------------------

Packing packet classes in network order can be fairly simple. Since we have
kept all of the flag values in a single 16 bit unsigned integer packing the
DNS header is simply a matter of packing all 12 bytes into 6 unsigned shorts.

.. code-block:: cython
    p_bytes = struct.pack('!HHHHHH', self.ident,
                                     self._flags,
                                     self.query_count,
                                     self.answer_count,
                                     self.auth_count,
                                     self.ad_count)

The `H` is the struct objects code for unsigned short and the `!` is structs.
Like other PKT based packet classes DNS's pkt2net uses the `update` kwarg, if
present, to trigger re-setting its sizing variables.

From here we call `pack()` on each query present in the queries list and then
`pack()` on each of the resources in the 3 resource type lists. There is only
one data format for the queries but multiple formats for the resources.
Resource data, called res_data in our demo implementation can be single
strings like txt records or A and AAAA records. Or it can be more complex data
like a SOA record. For this example we have implemented a parser for SOA data
that contains 7 fields. We have not implemented a parser for MX records. Those
contain 2 fields. Look in section 3 of RFC 1035 for details. Since this is a
demo class we also chose to implement the res_data parsing as parsing into
strings and out of strings. However, a more complete implementation could use
a PKT based class to wrap this data. A good way to intoduce yourself to packet
parsing and writing would be to implement a parser and packer routine for MX
records. If you decide to do that and would like pointers then the Steelscript
team has a community page on Riverbed Splash at: `https://splash.riverbed.com/community/product-lines/steelscript`

`pack_soa(bytes res_data, uint16_t* offset, dict labels, bint compress=1)` is a
good function to look at the mechanics of packing packet data. The SOA record
consists of 2 name fields of varable length followed by 5 unsigned 32 bit
values. The human readable SOA record looks like this:
    SOA mname: <name>, rname: <name>, serial: <X>, refresh: <X>, \
    retry: <X>, expire: <X>, minimum: <X>'

So after that string is split on white space index 2 of the returned list will
be the mname value. SOA_MNAME = 2 is specified in dns.pxd so that the code is
more readable. Note that the end of each of the first 6 values is left off
because it is a comma. The result of the 2 packed names and the single call to
pack the 5 unsigned INTs will be a correctly formatted network order SOA
record.

Using our DNS class to get information from a DNS server
--------------------------------------------------------

In this example we will use a standard socket and simply write a DNS packet we
generate into it. We don't have to be root for this example since we are going
to bind to a non-privileged port.

.. code-block:: python

    >>> import socket
    >>> from steelscript.packets.protos.dns import DNS, DNSQuery, DNSTYPE_A, \
    >>>     DNSTYPE_SOA, RCLASS_IN

    >>> LOCAL_PORT = 50111
    >>> LOCAL_IP = <your_systems_public_ip> # '10.1.1.1' for example
    >>> REMOTE_PORT = 53
    >>> REMOTE_IP = <your_DNS_server_address> # '10.0.0.1' for example

    >>> query_ident = 0x3e4e # any random 16bit number will do
    >>> # we want the server to perform a recursive query for us.
    >>> dns = DNS(ident=query_ident, recursion_requested=1)
    >>> dns.queries.append(DNSQuery('cnn.com', DNSTYPE_A, RCLASS_IN))

    >>> # IPv4/UDP socket
    >>> sock = socket.socket(socket.AF_INET,
    >>>                      socket.SOCK_DGRAM)
    >>> sock.bind((LOCAL_IP, LOCAL_PORT))

    >>> sock.sendto(dns.pkt2net({b'update': 1}), (REMOTE_IP, REMOTE_PORT))
    >>> data, addr = sock.recvfrom(1024)
    >>> dns_a_reply = DNS(data)

    >>> dns.ident = dns.ident + 1
    >>> dns.queries[0] = DNSQuery('cnn.com', DNSTYPE_SOA, RCLASS_IN)

    >>> sock.sendto(dns.pkt2net({b'update': 1}), (REMOTE_IP, REMOTE_PORT))
    >>> data, addr = sock.recvfrom(1024)
    >>> dns_soa_reply = DNS(data)

    >>> dns_a_reply.answers
    [DNSResource(domain_name=cnn.com, res_type=1, res_class=1, res_ttl=60, res_len=4, res_data=151.101.65.67),
     DNSResource(domain_name=cnn.com, res_type=1, res_class=1, res_ttl=60, res_len=4, res_data=151.101.129.67),
     DNSResource(domain_name=cnn.com, res_type=1, res_class=1, res_ttl=60, res_len=4, res_data=151.101.193.67),
     DNSResource(domain_name=cnn.com, res_type=1, res_class=1, res_ttl=60, res_len=4, res_data=151.101.1.67)]

    >>> dns_soa_reply.answers
    [DNSResource(domain_name=cnn.com, res_type=6, res_class=1, res_ttl=900, res_len=65, res_data=SOA mname: ns-47.awsdns-05.com, rname: awsdns-hostmaster@amazon.com, serial: 1, refresh: 7200, retry: 900, expire: 1209600, minimum: 86400)]

So we have basically recreated the `dig` command in a few lines of python.

Summary
-------

I hope this tutorial was helpful in laying out the basics of using and
extending steelscript.packets.
