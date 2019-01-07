#!/usr/bin/env python

import unittest
import logging
from array import array

from steelscript.packets.core.inetpkt import IP_CONST, Ethernet, ARP, IP, \
    UDP, TCP
from steelscript.packets.core.pcap import PCAPWriter, PCAPReader

logger = logging.getLogger(__name__)

C = IP_CONST()
icmp_pkt_data = array('B', [0, 11, 134, 99, 252, 32, 8, 0, 39, 64, 45, 200, 8,
                            0, 69, 0, 0, 28, 0, 0, 0, 0, 64, 1, 202, 227, 10,
                            38, 25, 153, 10, 38, 130, 25, 8, 0, 61, 86, 15,
                            255, 170, 170])
icmp_destun_pkt_data = array('B', [124, 122, 145, 108, 216, 21, 196, 179, 1,
                                   211, 170, 123, 8, 0, 69, 0, 0, 56, 69, 255,
                                   0, 0, 64, 1, 237, 106, 10, 38, 25, 198, 10,
                                   38, 25, 74, 3, 3, 17, 104, 0, 0, 0, 0, 69,
                                   96, 0, 56, 41, 139, 0, 0, 128, 17, 201,
                                   110, 10, 38, 25, 74, 10, 38, 25, 198, 227,
                                   106, 8, 6, 0, 36, 0, 0])

class PacketsTest(unittest.TestCase):

    def test_Ethernet_pkt(self):
        pkt = Ethernet(dst_mac='01:02:03:04:05:06')
        pkt.src_mac = '06:05:04:03:02:01'
        pkt.type = C.ETH_TYPE_IPV4

        self.assertEqual(pkt.dst_mac, '01:02:03:04:05:06')
        self.assertEqual(pkt.src_mac, '06:05:04:03:02:01')
        self.assertEqual(pkt.type, C.ETH_TYPE_IPV4)

        pkt.dst_mac = '01:01:01:01:01:01'
        self.assertEqual(pkt.dst_mac, '01:01:01:01:01:01')
        self.assertEqual(pkt.src_mac, '06:05:04:03:02:01')

        def try_bad_mac(obj):
            obj.dst_mac = "this ain't a mac!"
            return obj.pkt2net({})

        self.assertRaises(ValueError, try_bad_mac, pkt)

    def test_ARP_pkt(self):
        pkt = Ethernet(dst_mac='ff:ff:ff:ff:ff:ff',
                       src_mac='06:05:04:03:02:02')
        pkt.type = C.ETH_TYPE_ARP
        # ARP defaults:
        # hw type Ethernet
        # proto type IP
        # operation 1 (request)
        pkt.payload = ARP(sender_hw_addr='06:05:04:03:02:02',
                          sender_proto_addr='1.2.3.4',
                          target_hw_addr='00:00:00:00:00:00',
                          target_proto_addr='4.3.2.1')

        # Write the packet above to a byte string and create a new
        # ethernet packet from it.
        pkt_copy = Ethernet(pkt.pkt2net({}))
        a = pkt.get_layer("ARP")
        b = pkt_copy.get_layer("ARP")
        self.assertEqual(a.sender_hw_addr, b.sender_hw_addr)
        self.assertEqual(a.sender_proto_addr, b.sender_proto_addr)
        self.assertEqual(a.target_hw_addr, b.target_hw_addr)
        self.assertEqual(a.target_proto_addr, b.target_proto_addr)

        def try_bad_opcode(obj):
            arp = obj.get_layer('ARP')
            arp.operation = 14

        self.assertRaises(ValueError, try_bad_opcode, pkt_copy)

    def test_IP_UDP_pkt(self):
        pkt = Ethernet(dst_mac='03:02:03:04:05:06',
                       src_mac='06:05:04:03:02:03')

        pkt.payload = IP(proto=C.PROTO_UDP,
                         src='10.1.2.3',
                         dst='10.3.2.1',
                         payload=UDP(sport=34567,
                                     dport=53))

        """
        Write this packet out to a pcap file
        """
        dfile = open('packets.devtest.ip_udp.pcap', 'wb+')
        wrt = PCAPWriter(dfile)
        wrt.writepkt(pkt.pkt2net({'csum': 1, 'update': 1}), 0)
        wrt.close()

        """
        Read the copy packet in from the pcap file just created.
        """
        dfile = open('packets.devtest.ip_udp.pcap', 'rb')
        rdr = PCAPReader(dfile)
        pkt_copy = Ethernet(next(rdr)[1])
        rdr.close()

        a_IP = pkt.get_layer("IP")
        b_IP = pkt_copy.get_layer("IP")
        self.assertEqual(a_IP.proto, b_IP.proto)
        self.assertEqual(a_IP.src, b_IP.src)
        self.assertEqual(a_IP.dst, b_IP.dst)
        self.assertEqual(a_IP.total_len, b_IP.total_len)
        self.assertEqual(a_IP.checksum, b_IP.checksum)

        a_UDP = pkt.get_layer("UDP")
        b_UDP = pkt_copy.get_layer("UDP")
        self.assertEqual(a_UDP.sport, b_UDP.sport)
        self.assertEqual(a_UDP.dport, b_UDP.dport)
        self.assertEqual(a_UDP.checksum, b_UDP.checksum)

    def test_IP_TCP_pkt(self):
        pkt = Ethernet(dst_mac='05:02:03:04:05:06',
                       src_mac='06:05:04:03:02:05')

        pkt.payload = IP(proto=C.PROTO_TCP,
                         src='10.1.2.5',
                         dst='10.5.2.1',
                         payload=TCP(sport=34567,
                                     dport=80,
                                     sequence=200,
                                     flag_syn=1,
                                     options=b'this is not a real option.'))

        """
        Write this packet out to a pcap file
        """
        dfile = open('packets.devtest.ip_tcp.pcap', 'wb+')
        wrt = PCAPWriter(dfile)
        wrt.writepkt(pkt.pkt2net({'csum': 1, 'update': 1}), 0)
        wrt.close()

        """
        Read the copy packet in from the pcap file just created.
        """
        dfile = open('packets.devtest.ip_tcp.pcap', 'rb')
        rdr = PCAPReader(dfile)
        pkt_copy = Ethernet(next(rdr)[1])
        rdr.close()

        a_IP = pkt.get_layer("IP")
        b_IP = pkt_copy.get_layer("IP")
        self.assertEqual(a_IP.proto, b_IP.proto)
        self.assertEqual(a_IP.src, b_IP.src)
        self.assertEqual(a_IP.dst, b_IP.dst)
        self.assertEqual(a_IP.total_len, b_IP.total_len)
        self.assertEqual(a_IP.checksum, b_IP.checksum)

        a_TCP = pkt.get_layer("TCP")
        b_TCP = pkt_copy.get_layer("TCP")
        self.assertEqual(a_TCP.sport, b_TCP.sport)
        self.assertEqual(a_TCP.dport, b_TCP.dport)
        self.assertEqual(a_TCP.flag_syn, b_TCP.flag_syn)
        self.assertEqual(a_TCP.checksum, b_TCP.checksum)

    def test_IP_ICMP_pkt(self):
        pkt = Ethernet(icmp_pkt_data)
        icmp = pkt.get_layer_by_type(C.PQ_ICMP)
        self.assertEqual(icmp.type, C.ICMP_TYPE_ECHO)
        self.assertEqual(icmp.identifier, 0xfff)
        self.assertEqual(icmp.sequence, 0xaaaa)

        pkt_du = Ethernet(icmp_destun_pkt_data)
        icmp = pkt_du.get_layer_by_type(C.PQ_ICMP)
        self.assertEqual(icmp.type, C.ICMP_TYPE_DU)
        self.assertEqual(icmp.code, C.ICMP_DU_CODE_PORT_UNREACH)
        self.assertEqual(icmp.identifier, 0)
        self.assertEqual(icmp.sequence, 0)
        self.assertEqual(icmp.checksum, 4456)
        self.assertEqual(icmp.hdr_pkt.payload.dport, 2054)


if __name__ == '__main__':
    unittest.main()
