steelscript.packets.query.pcap_query API
========================================

pcap_query provides a class to enable quick queryies over Ethernet packets in
a PCAP file. The query is extensible with additional
steelscript.packets.inetpkt.PKT based packet classes.

In order to be compatible with PcapQuery a PKT based class must be a layer 7
protocol and implement the query_info() and default_ports() classmethod
methods and also implement the get_field_val(field_name) instance method.
Adding support for PKT based classes at other levels would require submitting
changes to Ethernet or IP classes. And that is something, for the record, that
we encourage. Please see the steelscript.packets tutorial for info.

.. currentmodule:: steelscript.packets.query.pcap_query

:py:class:`PcapQuery` Class
----------------------------

.. autoclass:: PcapQuery
    :members:

    .. automethod:: __init__(pkt_classes, l7_ports)