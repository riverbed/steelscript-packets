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

from libc.stdint cimport int64_t, uint64_t, int32_t, uint32_t, uint16_t, \
    intptr_t
from steelscript.packets.core.inetpkt cimport PKT, Ethernet, IP, TCP, \
    UDP, ARP, MPLS, NullPkt, PQTYPES
from steelscript.packets.core.pcap cimport PCAPReader, pktypes

offset_re = re.compile(r'^(udp|tcp)\.payload\.offset\[(\d*):(\d*)\]$')
NOT_FOUND = -1

cdef class PcapQuery:

    def __init__(self, *args, **kwargs):
        cdef:
            list default_classes
            uint16_t ptype, port
            tuple pfields
            bytes pfield
            object pkt_class

        self.fields = dict()
        self.l7_ports = dict()
        default_classes = [Ethernet, IP, TCP, UDP, ARP, MPLS]
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
                id_name.append((PQTYPES.t_frame, fname))
            elif fname.find(b'payload.offset') == NOT_FOUND:
                id_name.append((self.fields[fname], fname))
            elif fname.find(b'payload.offset') >= 0:
                if fname[:3] == b'tcp':
                    id_name.append((PQTYPES.t_tcp, fname))
                elif fname[:3] == b'udp':
                    id_name.append((PQTYPES.t_udp, fname))
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
