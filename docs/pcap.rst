steelscript.packets.core.pcap API
=================================

The pcap module defines the PCAP and PCAPNG decoders and a PCAP Writer class

.. currentmodule:: steelscript.packets.core.pcap

:py:class:`PCAPReader` Class
----------------------------

.. autoclass:: PCAPReader
    :members:

    .. automethod:: __init__(file_handle, pk_format=pktypes.array_data)

:py:class:`PCAPWriter` Class
----------------------------

.. autoclass:: PCAPWriter
    :members:

    .. automethod:: __init__(file_handle, snap_len=1500, net_layer=1)
