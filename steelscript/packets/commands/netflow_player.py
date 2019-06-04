#!/usr/bin/env python

import sys
import argparse

from steelscript.packets.core.pcap import netflow_replay_raw_sock, \
    netflow_replay_system_sock


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Netflow Replayer.')
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument('-f', '--file',
                          help=("Full path to the pcap file you want to "
                                "replay."),
                          type=str)
    required.add_argument('--dest_ip',
                          help="IP address to the send packets to.",
                          type=str)
    optional.add_argument('--spoofing',
                          dest='spoofing',
                          action='store_true',
                          help=("If specified then source spoofing is "
                                "enabled. The allows you to specify the src "
                                "IP address, source port, and dest MAC and "
                                "the local network device to use. On most "
                                "systems this feature requires root access. "
                                "The default is --no-spoofing"))
    optional.add_argument('--no-spoofing',
                          dest='spoofing',
                          action='store_false')
    optional.set_defaults(spoofing=False)
    optional.add_argument('--pcap_dst_port',
                          help=("Destination port for the packets in the pcap "
                                "file that should be replayed. Default is "
                                "2055."),
                          type=int,
                          default=2055)
    optional.add_argument('--dest_port',
                        help=("Destination port for the destination IP. "
                              "Default is 2055."),
                        type=int,
                        default=2055)
    optional.add_argument('--device',
                          help=("The name of the network interface to use to "
                                "send packets. This setting is ignored if "
                                "--spoofing is not specified."),
                          type=str,
                          default='')
    optional.add_argument('--dest_mac',
                          help=("MAC address to set as the dst_mac of all "
                                "packets sent. This setting is ignored if "
                                "--spoofing is not specified. Default is"
                                "broadcast ('ff:ff:ff:ff:ff:ff')"),
                          type=str,
                          default='ff:ff:ff:ff:ff:ff')
    optional.add_argument('--src_ip',
                          help=("The src IP that should be set for all "
                                "outbound packets. This setting is ignored if "
                                "--spoofing is not specified."),
                          type=str,
                          default='')
    optional.add_argument('--src_mac',
                          help=("The src MAC that should be set for all "
                                "outbound packets. This setting is ignored if "
                                "--spoofing is not specified."),
                          type=str,
                          default='')
    optional.add_argument('--blast',
                        help=("Boolian value. If not set to 0 will result in "
                              "the packets being sent as fast as possible."),
                        type=int,
                        default=0)
    return parser.parse_args()


def main():
    rval = 0
    args = parse_args(sys.argv[1:])
    if args.spoofing:
        if args.device != '':
            rval = netflow_replay_raw_sock(args.device,
                                           args.file,
                                           args.pcap_dst_port,
                                           args.dest_ip,
                                           args.dest_mac,
                                           args.dest_port,
                                           src_ip=args.src_ip,
                                           src_mac=args.src_mac,
                                           blast_mode=args.blast)
        else:
            raise ValueError("A valid network device must be specified in "
                             "order to use spoofing.")
    else:
        rval = netflow_replay_system_sock(args.file,
                                          args.pcap_dst_port,
                                          args.dest_ip,
                                          args.dest_port,
                                          blast_mode=args.blast)
    sys.exit(rval)

if __name__ == "__main__":
    main()
