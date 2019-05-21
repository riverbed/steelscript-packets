#!/usr/bin/env python

import json
import unittest
import logging
import pandas
from array import array

from steelscript.packets.core.inetpkt import IP_CONST, Ethernet, ARP, IP, \
    UDP, TCP, NullPkt
from steelscript.packets.core.pcap import PCAPReader, PCAPWriter, \
    get_pkts_header

from steelscript.packets.query.pcap_query import PcapQuery

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

igmp_pkt_data = array('B', [1, 0, 94, 127, 255, 250, 0, 28, 35, 170, 190, 173,
                            8, 0, 70, 0, 0, 32, 140, 98, 0, 0, 1, 2, 230, 146,
                            192, 168, 1, 64, 239, 255, 255, 250, 148, 4, 0, 0,
                            22, 0, 250, 4, 239, 255, 255, 250])

igmp_json = """
{"eth.src":{"0":"00:1b:11:10:26:11","1":"00:1c:23:aa:be:ad",
            "2":"00:02:02:19:51:28","3":"00:02:02:19:51:28",
            "4":"00:02:02:19:51:28","5":"00:1b:11:10:26:11",
            "6":"00:02:02:19:51:28","7":"00:02:02:19:51:28",
            "8":"00:02:02:19:51:28","9":"00:02:02:19:51:28",
            "10":"00:1b:11:10:26:11","11":"00:02:02:19:51:28",
            "12":"00:02:02:19:51:28","13":"00:02:02:19:51:28",
            "14":"00:1b:11:10:26:11","15":"00:02:02:19:51:28",
            "16":"00:1c:23:aa:be:ad","17":"00:02:02:19:51:28"},
"eth.dst":{"0":"01:00:5e:00:00:01","1":"01:00:5e:7f:ff:fa",
           "2":"01:00:5e:0a:0a:0a","3":"01:00:5e:01:01:03",
           "4":"01:00:5e:00:00:02","5":"01:00:5e:01:01:03",
           "6":"01:00:5e:01:01:04","7":"01:00:5e:01:01:04",
           "8":"01:00:5e:01:01:04","9":"01:00:5e:00:00:02",
           "10":"01:00:5e:01:01:04","11":"01:00:5e:01:01:05",
           "12":"01:00:5e:01:01:05","13":"01:00:5e:01:01:05",
           "14":"01:00:5e:00:00:01","15":"01:00:5e:0a:0a:0a",
           "16":"01:00:5e:7f:ff:fa","17":"01:00:5e:01:01:05"},
"ip.src":{"0":"192.168.1.2","1":"192.168.1.64","2":"192.168.11.201",
          "3":"192.168.11.201","4":"192.168.11.201","5":"192.168.1.2",
          "6":"192.168.11.201","7":"192.168.11.201","8":"192.168.11.201",
          "9":"192.168.11.201","10":"192.168.1.2","11":"192.168.11.201",
          "12":"192.168.11.201","13":"192.168.11.201","14":"192.168.1.2",
          "15":"192.168.11.201","16":"192.168.1.64","17":"192.168.11.201"},
"ip.dst":{"0":"224.0.0.1","1":"239.255.255.250","2":"225.10.10.10",
          "3":"225.1.1.3","4":"224.0.0.2","5":"225.1.1.3","6":"225.1.1.4",
          "7":"225.1.1.4","8":"225.1.1.4","9":"224.0.0.2","10":"225.1.1.4",
          "11":"225.1.1.5","12":"225.1.1.5","13":"225.1.1.5","14":"224.0.0.1",
          "15":"225.10.10.10","16":"239.255.255.250","17":"225.1.1.5"},
"igmp.type":{"0":17,"1":22,"2":22,"3":22,"4":23,"5":17,"6":22,"7":22,"8":22,
             "9":23,"10":17,"11":22,"12":22,"13":22,"14":17,"15":22,"16":22,
             "17":22},
"igmp.max_resp":{"0":100,"1":0,"2":0,"3":0,"4":0,"5":10,"6":0,"7":0,"8":0,
                 "9":0,"10":10,"11":0,"12":0,"13":0,"14":100,"15":0,"16":0,
                 "17":0},
"igmp.maddr":{"0":"0.0.0.0","1":"239.255.255.250","2":"225.10.10.10",
              "3":"225.1.1.3","4":"225.1.1.3","5":"225.1.1.3","6":"225.1.1.4",
              "7":"225.1.1.4","8":"225.1.1.4","9":"225.1.1.4",
              "10":"225.1.1.4","11":"225.1.1.5","12":"225.1.1.5",
              "13":"225.1.1.5","14":"0.0.0.0","15":"225.10.10.10",
              "16":"239.255.255.250","17":"225.1.1.5"}}
"""

igmp_file = './test/igmp_v2.pcap'

igmpv3_member_report = (b'\x01\x00^\x00\x00\x16\x00%.Q\xc3\x81\x08\x00FX\x008'
                        b'\x02F\x00\x00\x01\x02\x80!\xc0\xa8\x01B\xe0\x00\x00'
                        b'\x16\x94\x04\x00\x00"\x00\x00\x19\x00\x00\x00\x03'
                        b'\x02\x00\x00\x00\xef\xc3\x07\x02\x02\x00\x00\x00'
                        b'\xef\xff\xff\xfa\x02\x00\x00\x00\xef\xc3\x01_')
igmpv3_member_query = (b'\x01\x00^\x00\x00\x01\x00&Dl\x1e\xda\x08\x00F\xc0'
                       b'\x00$\x18\x0f@\x00\x01\x02)]\xc0\xa8\x01\xfe\xe0'
                       b'\x00\x00\x01\x94\x04\x00\x00\x11\x18\xec\xd3\x00'
                       b'\x00\x00\x00\x02\x14\x00\x00\x00\x00\x00\x00\x00'
                       b'\x00\x00\x00\x00\x00')

class TestPackets(unittest.TestCase):

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
                                     dport=53,
                                     payload=NullPkt()))

        """
        Write this packet out to a pcap file
        """
        wrt = PCAPWriter(filename='./test/packets.devtest.ip_udp.pcap')
        wrt.dump_pkt(pkt.pkt2net({'csum': 1, 'update': 1}))
        wrt.close()

        """
        Read the copy packet in from the pcap file just created.
        """
        rdr = PCAPReader(filename='./test/packets.devtest.ip_udp.pcap')
        pkt_copy = Ethernet(next(rdr)[2])
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
        wrt = PCAPWriter(filename='./test/packets.devtest.ip_tcp.pcap')
        wrt.dump_pkt(pkt.pkt2net({'csum': 1, 'update': 1}))
        wrt.close()

        """
        Read the copy packet in from the pcap file just created.
        """
        rdr = PCAPReader(filename='./test/packets.devtest.ip_tcp.pcap')
        pkt_copy = Ethernet(next(rdr)[2])
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

    def test_IP_IGMP_pkt(self):
        pkt = Ethernet(igmp_pkt_data)
        igmp = pkt.get_layer_by_type(C.PQ_IGMP)
        igmpv3_report = Ethernet(igmpv3_member_report)
        igmpv3r = igmpv3_report.get_layer_by_type(C.PQ_IGMP)
        igmpv3_query = Ethernet(igmpv3_member_query)
        igmpv3q = igmpv3_query.get_layer_by_type(C.PQ_IGMP)

        self.assertEqual(igmp.version, 2)
        self.assertEqual(igmp.type, C.IGMP_V2_MEMBER_REPORT)
        self.assertEqual(igmp.max_resp, 0)
        self.assertEqual(igmp.checksum, 0xfa04)
        self.assertEqual(igmp.group_address, '239.255.255.250')
        self.assertEqual(igmp.group_address, '239.255.255.250')
        # IGMP v3
        self.assertEqual(igmpv3r.version, 3)
        self.assertEqual(igmpv3r.type, C.IGMP_V3_MEMBER_REPORT)
        self.assertEqual(igmpv3r.num_records, 3)
        self.assertEqual(igmpv3r.group_records[0].type, 2)
        self.assertEqual(igmpv3r.group_records[0].group_address,
                         '239.195.7.2')
        self.assertEqual(igmpv3r.group_records[1].group_address,
                         '239.255.255.250')
        self.assertEqual(igmpv3r.group_records[2].group_address,
                         '239.195.1.95')
        self.assertEqual(igmpv3q.version, 3)
        self.assertEqual(igmpv3q.type, C.IGMP_MEMBER_QUERY)
        self.assertEqual(igmpv3q.max_resp, 0x18)
        self.assertEqual(igmpv3q.qrv, 2)
        self.assertEqual(igmpv3q.qqic, 20)

    def test_pcap_query(self):
        w_fields = ['eth.src', 'eth.dst', 'ip.src', 'ip.dst',
                    'igmp.type', 'igmp.max_resp', 'igmp.maddr']
        pcap_query = PcapQuery(filename=igmp_file,
                               wshark_fields=w_fields)
        # Use PcapQuery object to do a manual query
        # Specifying that we want a dataframe back
        df1 = pcap_query.query(dataframe=True)
        json_out = df1.to_json()

        # Create it again against the same file with the same fields
        pcap_query = PcapQuery(filename=igmp_file,
                               wshark_fields=w_fields)

        # use a PcapQuery object in iterator context
        data = list(pcap_query)
        df2 = pandas.DataFrame(data, columns=w_fields)

        # both methods return the same data and it is as expected
        self.assertTrue(df1.equals(df2))
        self.assertEqual(json.loads(igmp_json), json.loads(json_out))


if __name__ == '__main__':
    unittest.main()
