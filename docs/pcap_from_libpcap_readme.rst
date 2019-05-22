
.. code:: ipython3

    """
    steelscript.packets.core.pcap changes README
    
    The first versions of steelscript.packets.core.pcap 
    were based on header classes and routines implemented
    in Cython. Starting in this current version all pcap
    functions are wrappers of libpcap's pcap.h and other
    files.
    """

.. code:: ipython3

    """
    There are two ways you can use the pcap and itnetpkt
    classes and functions in steelscript.packets.core
    
    The first way is to cimport them directly into a
    Cython routine. Because most operatios in that case
    will be execute as type C this way is faster.
    """
    %load_ext Cython

.. code:: cython

    %%cython -l pcap
    from steelscript.packets.core.pcap cimport PCAPSocket, PCAPReader, PCAPWriter
    from steelscript.packets.core.inetpkt cimport Ethernet
    
    cdef:
        PCAPSocket sock
        int to_ms = 100
        int pkt_count = 0
        double ts
        bytes pkt
        Ethernet packet
        list packets = list()
    
    # We in this case we are opening up socket directly on an
    # interface and listening for ICMP packets.
    # I want to packets back fast so I'm setting the wait
    # timeout to 100 ms.
    sock = PCAPSocket(devicename='en0', to_ms=to_ms)
    if sock:
        # I only care about ICMP so set a BPF
        sock.add_bpf_filter('icmp')
        for ts, hdr, pkt in sock:
            if not pkt:
                # This just means that in 100ms
                # a packet didn't come
                continue
            else:
                packet=Ethernet(pkt)
                packets.append((ts, packet.src_mac, packet.dst_mac,
                                packet.payload.src, packet.payload.dst,
                                packet.payload.payload.type,
                                packet.payload.payload.code))
                pkt_count += 1
                if pkt_count == 16:
                    break
    sock.close()
    sock = None
    for p in packets:
        print(p)



.. parsed-literal::

    (1552340224.00922, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340224.018224, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340225.014381, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340225.023236, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340226.014462, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340226.023174, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340227.019621, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340227.028296, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340228.024467, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340228.027678, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340229.029596, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340229.038351, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340230.029734, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340230.038541, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340231.034857, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340231.044165, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)


.. code:: ipython3

    """
    This same thing could be done in pure Python with a slight performance penalty by doing:
    """
    from steelscript.packets.core.pcap import PCAPSocket, PCAPReader, PCAPWriter
    from steelscript.packets.core.inetpkt import Ethernet
    
    to_ms = 100
    pkt_count = 0
    packets = list()
    
    sock = PCAPSocket(devicename='en0', to_ms=to_ms)
    if sock:
        # I only care about ICMP so set a BPF
        sock.add_bpf_filter('icmp')
        for ts, hdr, pkt in sock:
            if not pkt:
                # This just means that in 100ms
                # a packet didn't come
                continue
            else:
                packet=Ethernet(pkt)
                packets.append((ts, packet.src_mac, packet.dst_mac,
                                packet.payload.src, packet.payload.dst,
                                packet.payload.payload.type,
                                packet.payload.payload.code))
                pkt_count += 1
                if pkt_count == 16:
                    break
    sock.close()
    sock = None
    for p in packets:
        print(p)


.. parsed-literal::

    (1552340235.041642, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340235.050232, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340236.046737, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340236.055359, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340237.047716, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340237.056309, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340238.048016, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340238.056856, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340239.053151, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340239.062663, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340240.055299, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340240.064151, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340241.05883, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340241.06796, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)
    (1552340242.058927, 'f0:18:98:4c:ad:9f', '78:ac:c0:b4:07:15', '192.168.255.169', '192.168.255.1', 8, 0)
    (1552340242.063092, '78:ac:c0:b4:07:15', 'f0:18:98:4c:ad:9f', '192.168.255.1', '192.168.255.169', 0, 0)


.. code:: ipython3

    """
    All three pcap object types have the ability to dump packets to pcap files.
    Here are the differences in the three types:
    
    PCAPSocket: This object is an iterator. So access to its packets is via 
                ts, hdr, pkt = next(PCAPSocket) for a for loop with the same
                syntax
        kwargs:
            devicename (str): name of the device to open
            snaplen (int): the snaplen setting for the device. def. 0 == all data.
            promisc (int): If the device should open in promiscuous mode. def. 1 == True
            to_ms (int): Number of ms to wait before yeilding packets. def. 1000 = 1 second.
                values of 10 - 100 are good for interactive use.
                
        properties:
            stop_event = This is an internal threading event. It can be
                used to stop iteration when the PCAPSocket object is 
                used in a threading context. PCAPSockets will call
                close on all their objects if this event is set.
            network: The network address for this device if derivable
            netmask: The netmask address for this device if derivable
            
        calls:
            int set_snaplen(int snaplen) - set the snaplen on a running PCAPSocket
            int set_promisc(int promisc) - set/unset promisc
            int set_timeout(int timeout) - set timeout in ms.
            int getnonblock() - find out if this socket is in blocking mode
            int setnonblock(int nonblock) - set/unset nonblocking
            int sendpacket(bytes pktdata) - send packet data via this socket
            int add_bpf_filter(str bpf_filter) - set a Berkly BPF filter
            int open_pcap_dumper(str file_name) - set up a pcap file dump to file_name
            void close_pcap_dumper() - close and clean up a dumper file
            void dump_hdr_pkt(pcap_pkthdr_t hdr,
                              bytes data,
                              uint32_t tv_sec=0,
                              uint32_t tv_usec=0) - Dump a header and packet into a
                                  pcap dumper file. Optionaly overwrite the tv_sec
                                  and tv_usec values in the header.
            void dump_pkt(bytes data,
                          uint32_t tv_sec=0,
                          uint32_t tv_usec=0) - Dump a packet into a pcap dumper file.
                              a header will be automaticaly generated for the data. 
                              optionaly overwrite the timestamp values in the auto 
                              generated header.
            void close() - Close and release all C level variables.
            
            
    PCAPReader is a subset of PCAPSocket. It attaches to a filename so it has none of 
        PCAPSocket's functions for setting hardware parameters. 
        
        kwargs:
            filename (str): name of the file to open
            
        calls:
            int add_bpf_filter(str bpf_filter) - set a Berkly BPF filter
            int open_pcap_dumper(str file_name) - set up a pcap file dump to file_name
            void close_pcap_dumper() - close and clean up a dumper file
            void dump_hdr_pkt(pcap_pkthdr_t hdr,
                              bytes data,
                              uint32_t tv_sec=0,
                              uint32_t tv_usec=0) - Dump a header and packet into a
                                  pcap dumper file. Optionaly overwrite the tv_sec
                                  and tv_usec values in the header.
            void dump_pkt(bytes data,
                          uint32_t tv_sec=0,
                          uint32_t tv_usec=0) - Dump a packet into a pcap dumper file.
                              a header will be automaticaly generated for the data. 
                              optionaly overwrite the timestamp values in the auto 
                              generated header.
            void close() - Close and release all C level variables.
        
    PCAPWriter is a further subset that does not read a file or device. It has a NULL 
        or 'dead' (in libpcap parlance) pcap_t * device. It automaticaly opens a dumper
        when it is initialized.
        
        kwargs:
            filename (str): name of the pcap dump file to create
            
        calls:
            int open_pcap_dumper(str file_name) - set up a pcap file dump to file_name
            void close_pcap_dumper() - close and clean up a dumper file
            void dump_hdr_pkt(pcap_pkthdr_t hdr,
                              bytes data,
                              uint32_t tv_sec=0,
                              uint32_t tv_usec=0) - Dump a header and packet into a
                                  pcap dumper file. Optionaly overwrite the tv_sec
                                  and tv_usec values in the header.
            void dump_pkt(bytes data,
                          uint32_t tv_sec=0,
                          uint32_t tv_usec=0) - Dump a packet into a pcap dumper file.
                              a header will be automaticaly generated for the data. 
                              optionaly overwrite the timestamp values in the auto 
                              generated header.
            void close() - Close and release all C level variables.
            
        NOTE: calling open_pcap_dumper() on an already open PCAPWriter could result in
            a segfault. Call close first.
            
    """

.. code:: ipython3

    """
    As a final example we will open up a PCAPReader to read a large PCAP file.
    We want to filter down to only the arp packets (86 out of 1000045 packets
    in the file). And as we find them we want to write them out to a new file
    with exactly the same headers and timestamps.
    """
    
    from steelscript.packets.core.pcap import PCAPReader
    
    rdr = PCAPReader(filename='../pcaps/new_trace.pcap')
    rdr.add_bpf_filter('arp')
    rdr.open_pcap_dumper('arp_from_new_trace.pcap')
    
    for ts, hdr, pkt in rdr:
        # The BPF filters means only arp will be here
        rdr.dump_hdr_pkt(hdr, pkt)
        
    # When a PCAPReader hits the end of its packets it automaticaly
    # calls close on itself prior to raising StopIteration
    
    # If you break out of the loop prior then it is best to 
    # manualy call close()

.. code:: ipython3

    ls -l ./arp_from_new_trace.pcap


.. parsed-literal::

    -rw-r--r--  1 dvernon  staff  6904 Mar 11 17:37 ./arp_from_new_trace.pcap


