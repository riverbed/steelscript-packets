# cython: profile=False

# Copyright (c) 2017 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from cpython.array cimport array
import datetime
import tzlocal
import pytz
import re

from libc.stdint cimport uint16_t
from steelscript.packets.core.inetpkt cimport PKT, Ethernet, IP, TCP, ICMP, \
    UDP, ARP, MPLS, NullPkt, PQ_FRAME, PQ_TCP, PQ_UDP
from steelscript.packets.core.pcap cimport PCAPReader, pktypes

# Regex to determine if the field matches a payload offset pattern.
offset_re = re.compile(r'^(udp|tcp)\.payload\.offset\[(\d*):(\d*)\]$')
NOT_FOUND = -1


cdef class PcapQuery:
    """Object that performs pcap_query. Supports adding additional packet classes.
    Also supports custom layer 7 port mapping.
    """
    def __init__(self, *args, **kwargs):
        """Create a PcapQuery object.

        Args:
            :pkt_classes (list): A list of additional packet classes to be
                used.  Each class must have a class function query_info() that
                returns a tuple of packet type and a tuple of supported field
                names. See the steelsript.packets tutorial for implementation
                details.
            :l7_ports (dict): A dictionary containing a map of port numbers
                (the keys) and packet classes (the values) to be used by layer
                4 protocols like TCP and UDP to decode payload.
        """
        cdef:
            list default_classes
            uint16_t ptype, port
            tuple pfields
            bytes pfield
            object pkt_class

        self.fields = dict()
        self.l7_ports = dict()
        default_classes = [Ethernet, IP, ICMP, TCP, UDP, ARP, MPLS]
        if ('pkt_classes' in kwargs and
                isinstance(kwargs['pkt_classes'], list)):
            default_classes.extend(kwargs['pkt_classes'])
        for pkt_class in default_classes:
            ptype, pfields = pkt_class.query_info()
            for pfield in pfields:
                self.fields[pfield] = ptype
            for port in pkt_class.default_ports():
                self.l7_ports[port] = pkt_class
        self.l7_ports.update(kwargs.get('l7_ports', dict()))
        self.local_tz = tzlocal.get_localzone()

    cpdef unsigned char fields_supported(self, list field_names):
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
            bytes this_field

        field_failed = 0
        for this_field in field_names:
            found = 0
            if this_field in self.fields:
                found = 1
            elif this_field == b'frame.time_epoch':
                found = 1
            elif this_field[:18] in (b'tcp.payload.offset',
                                     b'udp.payload.offset'):
                groups = offset_re.match(this_field)
                if groups:
                    if int(groups.groups()[1]) < int(groups.groups()[2]):
                        found = 1
                    else:
                        print "tcp|udp.payload.offset[x:y] x >= y!!"
                        print "{0}:{1}".format(int(groups.groups()[1]),
                                               int(groups.groups()[2]))
            if not found:
                field_failed = 1

        if field_failed:
            return 0
        else:
            return 1

    cpdef pcap_query(self,
                     object file_handle,
                     list wshark_fields,
                     double starttime,
                     double endtime,
                     unsigned char rdf=0,
                     unsigned char as_datetime=1):
        """Perform the actual pcap query. ONLY Ethernet packets are supported
        at this time.

        Args:
            :file_handle (object): The open PCAP file object to read data from.
            :wshark_fields (list): A list of the fields that the query should
                populate in the output data.
            :starttime (double): Start time of the query.
            :endtime (double): End time of the query
            :rdf (0 or 1): Return data as Pandas Dataframe. Requires pandas 
                be installed.
            :as_datetime (0 or 1): Cast all timestamps into datetime.datetime() 
                objects. Slower that simply returning timestamps.

        Returns:
            :list or pandas dataframe: contains single entry for each matching 
                packet in the pcap. 
        """
        cdef:
            list return_vals, offsets, id_name, name_idx
            list layer_ids, layers
            dict id_index
            tuple i_n
            uint16_t pkt_id, link_type, layer_index
            bytes fname, rep_fname
            double ts
            array pkt
            Ethernet e
            PCAPReader rdr

        layer_index = 0
        return_vals = list()
        id_name = list()
        name_idx = list()
        id_index = dict()
        layer_ids = list()
        layers = list()


        for fname in wshark_fields:
            if fname == b'frame.time_epoch':
                id_name.append((PQ_FRAME, fname))
            elif fname.find(b'payload.offset') == NOT_FOUND:
                id_name.append((self.fields[fname], fname))
            elif fname.find(b'payload.offset') >= 0:
                if fname[:3] == b'tcp':
                    id_name.append((PQ_TCP, fname))
                elif fname[:3] == b'udp':
                    id_name.append((PQ_UDP, fname))
                else:
                    print("invalid payload.offset[x:y] field name!! "
                          "Use fields_supported to check fields.")
            else:
                print("invalid query field name!! Use fields_supported "
                      "to check fields.")
        for i_n in id_name:
            if i_n[0] in id_index:
                name_idx.append((i_n[1], id_index[i_n[0]]))
            else:
                layers.append(NullPkt())
                id_index[i_n[0]] = layer_index
                name_idx.append((i_n[1], layer_index))
                layer_ids.append(i_n[0])
                layer_index += 1

        rdr = PCAPReader(file_handle)
        for ts, pkt, link_type in rdr:
            if (link_type == 1 and
                    ((starttime == 0.0 == endtime) or
                     (starttime <= ts <= endtime) or
                     (starttime == 0.0 and ts <= endtime) or
                     (starttime <= ts and endtime == 0.0))):
                e = Ethernet(pkt, l7_ports=self.l7_ports)
                layer_index = 0
                for pkt_id in layer_ids:
                    # This will populate the layer with a NullPkt if the
                    # packet does not have the right layer for the field.
                    layers[layer_index] = e.get_layer_by_type(pkt_id)
                    layer_index += 1
                return_vals.append(list())
                # we have all the objects now. Do the report and return.
                # order matters.
                for rep_fname, layer_index in name_idx:
                    if rep_fname == b'frame.time_epoch':
                        # the one and only field from FRAME
                        if as_datetime:
                            return_vals[-1].append((datetime.datetime
                                                    .utcfromtimestamp(ts)
                                                    .replace(tzinfo=pytz.utc)
                                                    .astimezone(self.local_tz)
                                                    )
                                                   )
                        else:
                            return_vals[-1].append(ts)

                    else:
                        # In the case of NullPkt this will return None.
                        return_vals[-1].append(
                            layers[layer_index].get_field_val(rep_fname)
                        )

        if rdf and return_vals:
            try:
                import pandas
            except ImportError as e:
                raise ImportError("pcap_query's rdf option requires pandas. "
                                  "Please pip install pandas. Error was: {0}"
                                  "".format(e.message))
            return pandas.DataFrame(return_vals, columns=wshark_fields)
        elif rdf and not return_vals:
            return None
        return return_vals
