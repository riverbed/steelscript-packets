# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdlib cimport malloc, free
from posix.time cimport clock_gettime, timespec, CLOCK_REALTIME
from libc.stdint cimport uint16_t

from threading import Event
import tzlocal
import re
import os

from steelscript.packets.core.inetpkt cimport PKT, Ethernet, IP, TCP, ICMP, \
    IGMP, UDP, ARP, MPLS, NullPkt, PQ_FRAME, PQ_TCP, PQ_UDP
from steelscript.packets.core.pcap cimport PCAPSocket, PCAPReader, \
    pcap_pkthdr_t, findalldevs

# Regex to determine if the field matches a payload offset pattern.
offset_re = re.compile(r'^(udp|tcp)\.payload\.offset\[(\d*):(\d*)\]$')
NOT_FOUND = -1

ERRBUF_SIZE = 256
PLOAD_F_LEN = 18

cdef bint valid_dev(str dev):
    cdef:
        int fad_rval
        list devices = list()
        char * errors = <char *> malloc(ERRBUF_SIZE * sizeof(char))
    fad_rval = findalldevs(devices, errors)
    free(errors)
    if not fad_rval and dev in devices:
        return 1
    return 0

cdef bint valid_file(str file):
    try:
        if not os.path.exists(file):
           return 0
        elif not os.path.isfile(file):
            return 0
        elif not os.access(file, os.R_OK):
            return 0
        else:
            return 1
    except:
        return 0


cdef class Frame:
    def __cinit__(self, ts, hdr):
        self.ts = ts
        self.hdr = hdr

    cpdef object get_field_val(self, str field):
        if field == 'frame.time_epoch':
            return self.ts
        elif field == 'frame.len':
            return self.hdr.len
        elif field == 'frame.caplen':
            return self.hdr.caplen
        else:
            return None

    @classmethod
    def query_info(cls):
        return (PQ_FRAME,
                ('frame.time_epoch', 'frame.len', 'frame.caplen'))

    @classmethod
    def default_ports(cls):
        return []


def get_field_val_f(int layer_index, str field_name):
    def f(list layers_list):
        func = getattr(layers_list[layer_index], 'get_field_val')
        return func(field_name)
    return f


cdef class PcapQuery:
    """Object that performs pcap_query. Supports adding additional packet
    classes. Also supports custom layer 7 port mapping.
    """
    def __init__(self, *args, **kwargs):
        """Create a PcapQuery object.

        Args:
            :devicename (str): Device to use as a pkt source. If the
                string matches any device on the local system that will be
                used otherwise an Exception will be raised. Will cause
                Exception if specified alone with filename.
            :filename (str): Path to pcap file to use as a pkt source. If the
                file can be opened it will be used otherwise an Exception will
                be raised. Will cause Exception if specified alone with
                devicename.
            :wshark_fields (list of str): A list of strings that specifies what
                data and in what order is returned. These will be the header
                columns if the data is returned in list context.
            :pkt_classes (list): A list of additional packet classes to be
                used.  Each class must have a class function query_info() that
                returns a tuple of packet type and a tuple of supported field
                names. See the steelsript.packets tutorial for implementation
                details.
            :l7_ports (dict): A dictionary containing a map of port numbers
                (the keys) and packet classes (the values) to be used by layer
                4 protocols like TCP and UDP to decode payload.
            :bpf_filter (str): A BPF filter to add to the packet source. Works
                for both device and file queries.
            :snaplen (int): Length of data to read off the wires. Only effects
                devicename PcapQuery objects.
            :promisc (int): Operate the network socket in promiscuous mode.
                Only effects devicename PcapQuery objects.
            :to_ms (int): The number of millisecs to wait and buffer packets
                before returning data. Default is 50. Values of 10 - 100 seem
                reasonable. Only effects devicename PcapQuery objects.
                If the traffic will be intermittent you will want to set this
                to a higher number or PcapQuery may return no data.
            :stop_event (threading.Event or equivalent. Must support
                foo.is_set()) used to stop iteration in a threading or
                multiprocess context.
        """
        cdef:
            list default_classes
            uint16_t ptype, port
            int snaplen, promisc, to_ms, rval
            tuple pfields
            str pfield, dev, file
            object pkt_class

        dev = kwargs.get('devicename')
        file = kwargs.get('filename')
        self.use_device = 0
        if dev and file:
            raise ValueError("'devicename' and 'filename' can't be specified "
                             "together. Please include one or the other.")
        elif dev:
            if valid_dev(dev):
                self.use_device = 1
                self.srcname = dev
            else:
                raise ValueError('Could not find {} on this system. Please'
                                 'specify a valid device.'.format(dev))
        elif file:
            if valid_file(file):
                self.srcname = file
            else:
                raise ValueError('Could not open {} for reading. Please check '
                                 'permissions or specify a valid file.'
                                 ''.format(dev))
        else:
            raise ValueError("Either 'devicename' or 'filename' must be "
                             "defined.")

        if self.use_device:
            snaplen = kwargs.get('snaplen', 0)
            promisc = kwargs.get('promisc', 1)
            to_ms = kwargs.get('to_ms', 50)
            self.reader = PCAPSocket(devicename=self.srcname,
                                     snaplen=snaplen,
                                     promisc=promisc,
                                     to_ms=to_ms)
        else:
            self.reader = PCAPReader(filename=self.srcname)

        if self.reader and kwargs.get('bpf_filter'):
            rval = self.reader.add_bpf_filter(kwargs.get('bpf_filter'))
            if rval != 0:
                raise ValueError("Could not compile bpf_filter: '{}'"
                                 "".format(kwargs.get('bpf_filter')))

        self.layer_order = list()
        self.field_functions = list()
        self.fields = dict()
        self.l7_ports = dict()
        self.wshark_fields = kwargs.get('wshark_fields', list())


        default_classes = [Frame, Ethernet, IP, ICMP, IGMP, TCP, UDP, ARP,
                           MPLS]
        if ('pkt_classes' in kwargs and
                isinstance(kwargs['pkt_classes'], list)):
            default_classes.extend(kwargs['pkt_classes'])

        for pkt_class in default_classes:
            ptype, pfields = pkt_class.query_info()
            for pfield in pfields:
                self.fields[pfield[:PLOAD_F_LEN]] = ptype
            for port in pkt_class.default_ports():
                self.l7_ports[port] = pkt_class
        self.l7_ports.update(kwargs.get('l7_ports', dict()))

        if not self.fields_supported(self.wshark_fields):
            raise ValueError("2This PcapQuery object does not support the "
                             "following wshark_fields list: {0} {1}"
                             "".format(self.wshark_fields, self.fields))

        for pfield in self.wshark_fields:
            ptype = self.fields[pfield[:PLOAD_F_LEN]]
            if ptype not in self.layer_order:
                self.layer_order.append(ptype)
            self.field_functions.append(get_field_val_f(
                self.layer_order.index(ptype), pfield))
        self.timeout = kwargs.get('timeout', 10.0)
        self.stop_event = kwargs.get('stop_event', Event())
        self.local_tz = tzlocal.get_localzone()

    cpdef dict show_fields(self):
        return self.fields

    cpdef bint fields_supported(self, list field_names):
        """Helper function that checks a list of field names to see if THIS
        instance of PcapQuery can service all of the fields. Used, for example,
        by steelscript.wireshark.pcap.PcapFile.query(). Determines if PcapQuery
        instance will be able to perform a particular query. If 
        fields_supported returns 0 then 
        steelscript.wireshark.pcap.PcapFile.query() will fall back on using
        tshark with its larger set of supported fields.

        Args:
            :field_names (list): Field names to be used by a follow up query.

        Returns: 
            :bool: 1 if all fields are supported, 0 otherwise.
        """
        cdef:
            list fields
            object groups
            unsigned char field_failed, found
            str this_field

        field_failed = 0
        for this_field in field_names:
            found = 0
            if this_field[:PLOAD_F_LEN] in ('tcp.payload.offset',
                                            'udp.payload.offset'):
                groups = offset_re.match(this_field)
                if groups:
                    if int(groups.groups()[1]) < int(groups.groups()[2]):
                        found = 1
                    else:
                        print("tcp|udp.payload.offset[x:y] x >= y!!")
                        print("{0}:{1}".format(int(groups.groups()[1]),
                                               int(groups.groups()[2])))
            elif this_field in self.fields:
                found = 1

            if not found:
                field_failed = 1
        if field_failed:
            return 0
        else:
            return 1

    def __iter__(self):
        return self

    def __next__(self):
        cdef:
            PKT spkt
            bytes pkt
            timespec ts1, ts2
            double comp_ts1, comp_ts2
            uint16_t pq_type
            pcap_pkthdr_t hdr
            list layers
        pkt = b''
        layers = list()
        if not self.stop_event.is_set():
            ts, hdr, pkt = next(self.reader)
            if pkt:
                spkt = Ethernet(pkt, l7_ports=self.l7_ports)
                for pq_type in self.layer_order:
                    if pq_type == PQ_FRAME:
                        layers.append(Frame(ts, hdr))
                    else:
                        layers.append(spkt.get_layer_by_type(pq_type))
                return tuple(x(layers) for x in self.field_functions)
        raise StopIteration()

    def query(self,
              starttime=0.0,
              endtime=0.0,
              num_packets=0,
              dataframe=0):
        """Manual query function. 

        Args:
            :starttime (double): Timestamp for the first packet of interest.
                Default is 0.0 meaning no start time.
            :endtime (double): Timestamp of the last packet of interest.
                Default is 0.0 meaning no end time.
            :num_packets (int): Number of packets to inspect prior to
                returning.
                Default is 0 meaning all packets.
                NOTE: if both endtime and num_packets are specified then the
                first one to match will be in effect.
                num_packets is the count of packets that match the timeframe
                AND the specified fields. Packets outside the timeframe OR that
                don't have any of the specified fields are not counted.
            :dataframe (boolean int) Return data as a pandas dataframe if
                pandas is installed.


        Returns: 
            :default is to return a list of tuples with the data in the order
                that the wshark_fields were specified when creating the
                PcapQuery object.
        """
        cdef:
            bint count_packets, st, et
            int pkts, no_result
            PKT spkt
            bytes pkt
            double ts
            uint16_t pq_type
            pcap_pkthdr_t hdr
            tuple row
            list layers, data
        if num_packets:
            count_packets = 1
        else:
            count_packets = 0
        if starttime != 0.0:
            st = 1
        else:
            st = 0
        if endtime != 0.0:
            et = 1
        else:
            et = 0

        pkts = 0
        no_result = len(self.field_functions)
        layers = list()
        data = list()
        for ts, hdr, pkt in self.reader:
            if not pkt:
                break
            else:
                if st and ts < starttime:
                    continue
                elif et and ts > endtime:
                    break
                elif count_packets and pkts > num_packets:
                    break
                elif self.stop_event.is_set():
                    break
                else:
                    spkt = Ethernet(pkt, l7_ports=self.l7_ports)
                    layers = list()
                    for pq_type in self.layer_order:
                        if pq_type == PQ_FRAME:
                            layers.append(Frame(ts, hdr))
                        else:
                            layers.append(spkt.get_layer_by_type(pq_type))
                    row = tuple(x(layers) for x in self.field_functions)
                    if row.count(None) != no_result:
                        data.append(row)
                        pkts += 1
                    else:
                        continue
        if dataframe:
            if data:
                try:
                    import pandas
                except ImportError as e:
                    raise ImportError("pcap_query's rdf option requires "
                                      "pandas. Please pip install pandas. "
                                      "Error was: {0}".format(e))
                return pandas.DataFrame(data, columns=self.wshark_fields)
            else:
                return None
        else:
            return data