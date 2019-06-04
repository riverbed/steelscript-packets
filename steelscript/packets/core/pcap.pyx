# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

from libc.stdlib cimport malloc, free
from libc.stdint cimport uint32_t, uint64_t, uint16_t

import time
import socket
import struct
from threading import Event

from steelscript.packets.core.inetpkt cimport Ethernet, PKT, NetflowSimple, \
    PQ_NETFLOW_SIMPLE

DEF USECCONST = 1000000.00

VERSION_MAJOR = 2
VERSION_MINOR = 4
ERRBUF_SIZE = 256
ERROR = -1
ERROR_BREAK = -2
ERROR_NOT_ACTIVATED = -3
ERROR_ACTIVATED = -4
ERROR_NO_SUCH_DEVICE = -5
ERROR_RFMON_NOTSUP = -6
ERROR_NOT_RFMON = -7
ERROR_PERM_DENIED = -8
ERROR_IFACE_NOT_UP = -9
ERROR_CANTSET_TSTAMP_TYPE = -10
ERROR_PROMISC_PERM_DENIED = -11
ERROR_TSTAMP_PRECISION_NOTSUP = -12
WARNING = 1
WARNING_PROMISC_NOTSUP = 2
WARNING_TSTAMP_TYPE_NOTSUP = 3
NETMASK_UNKNOWN = 0xffffffff
TSTAMP_HOST = 0
TSTAMP_HOST_LOWPREC = 1
TSTAMP_HOST_HIPREC = 2
TSTAMP_ADAPTER = 3
TSTAMP_ADAPTER_UNSYNCED = 4
TSTAMP_PRECISION_MICRO = 0
TSTAMP_PRECISION_NANO = 1
ETH_NULL = 0
ETH_EN10MB = 1
ETH_IEEE802 = 6
ETH_ARCNET = 7
ETH_SLIP = 8
ETH_PPP = 9
ETH_FDDI = 10
ETH_ATM_RFC1483 = 11
ETH_RAW = 12
ETH_PPP_SERIAL = 50
ETH_PPP_ETHER = 51
ETH_C_HDLC = 104
ETH_IEEE802_11 = 105
ETH_LOOP = 108
ETH_LINUX_SLL = 113
ETH_LTALK = 114
PCAP_NETMASK_UNKNOWN = 0xffffffff

cdef class PCAP_CONST:
    def __cinit__(self):
        # Values taken from pcap.h. Names have leading PCAP_ removed in order
        # to avoid collisions with #define macros
        self.VERSION_MAJOR = VERSION_MAJOR
        self.VERSION_MINOR = VERSION_MINOR
        self.ERRBUF_SIZE = ERRBUF_SIZE
        self.ERROR = ERROR
        self.ERROR_BREAK = ERROR_BREAK
        self.ERROR_NOT_ACTIVATED = ERROR_NOT_ACTIVATED
        self.ERROR_ACTIVATED = ERROR_ACTIVATED
        self.ERROR_NO_SUCH_DEVICE = ERROR_NO_SUCH_DEVICE
        self.ERROR_RFMON_NOTSUP = ERROR_RFMON_NOTSUP
        self.ERROR_NOT_RFMON = ERROR_NOT_RFMON
        self.ERROR_PERM_DENIED = ERROR_PERM_DENIED
        self.ERROR_IFACE_NOT_UP = ERROR_IFACE_NOT_UP
        self.ERROR_CANTSET_TSTAMP_TYPE = ERROR_CANTSET_TSTAMP_TYPE
        self.ERROR_PROMISC_PERM_DENIED = ERROR_PROMISC_PERM_DENIED
        self.ERROR_TSTAMP_PRECISION_NOTSUP = ERROR_TSTAMP_PRECISION_NOTSUP
        self.WARNING = WARNING
        self.WARNING_PROMISC_NOTSUP = WARNING_PROMISC_NOTSUP
        self.WARNING_TSTAMP_TYPE_NOTSUP = WARNING_TSTAMP_TYPE_NOTSUP
        self.NETMASK_UNKNOWN = NETMASK_UNKNOWN
        self.TSTAMP_HOST = TSTAMP_HOST
        self.TSTAMP_HOST_LOWPREC = TSTAMP_HOST_LOWPREC
        self.TSTAMP_HOST_HIPREC = TSTAMP_HOST_HIPREC
        self.TSTAMP_ADAPTER = TSTAMP_ADAPTER
        self.TSTAMP_ADAPTER_UNSYNCED = TSTAMP_ADAPTER_UNSYNCED
        self.TSTAMP_PRECISION_MICRO = TSTAMP_PRECISION_MICRO
        self.TSTAMP_PRECISION_NANO = TSTAMP_PRECISION_NANO
        self.ETH_NULL = ETH_NULL
        self.ETH_EN10MB = ETH_EN10MB
        self.ETH_IEEE802 = ETH_IEEE802
        self.ETH_ARCNET = ETH_ARCNET
        self.ETH_SLIP = ETH_SLIP
        self.ETH_PPP = ETH_PPP
        self.ETH_FDDI = ETH_FDDI
        self.ETH_ATM_RFC1483 = ETH_ATM_RFC1483
        self.ETH_RAW = ETH_RAW
        self.ETH_PPP_SERIAL = ETH_PPP_SERIAL
        self.ETH_PPP_ETHER = ETH_PPP_ETHER
        self.ETH_C_HDLC = ETH_C_HDLC
        self.ETH_IEEE802_11 = ETH_IEEE802_11
        self.ETH_LOOP = ETH_LOOP
        self.ETH_LINUX_SLL = ETH_LINUX_SLL
        self.ETH_LTALK = ETH_LTALK

cpdef uint32_t ip2int(str addr):
    cdef:
        uint32_t ip
    uint32_t = struct.unpack("!I", socket.inet_aton(addr))[0]


cpdef str int2ip(uint32_t addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


cpdef char *lookupdev(char *errtext):
    cdef:
        char * errors = <char *> malloc(ERRBUF_SIZE * sizeof(char))
        char * device
    try:
        device = pcap_lookupdev(errors)
    finally:
        errtext = errors
    if not device:
        return NULL
    else:
        return device

cpdef int findalldevs(list devices, char *errtext):
    cdef:
        int rval
        pcap_if_t * ifaces
        pcap_if_t * current
        pcap_addr * cur_addr
    rval = ERROR
    rval = pcap_findalldevs(&ifaces, errtext)
    if not rval:
        current = ifaces
        while current:
            devices.append(current.name)
            current = current.next
    return rval

cdef int lookupnet(const char *device,
                   bpf_u_int32 * net,
                   bpf_u_int32 * mask,
                   char *errtext):
    cdef:
        int status
    status = pcap_lookupnet(device, net, mask, errtext)
    if status:
        net[0] = 0
        mask[0] = 0
    return status

cdef pcap_t *open_live(const char * device,
                       int snaplen,
                       int promisc,
                       int to_ms,
                       char *errtext):
    cdef:
        bpf_u_int32 net, mask
        int status
        pcap_t * pcap_live

    pcap_live = pcap_open_live(device, snaplen, promisc, to_ms, errtext)
    if not pcap_live:
        return NULL
    else:
        return pcap_live

cdef pcap_t *open_offline(const char * filename,
                          char *errtext):
    cdef:
        pcap_t * pcap_offline

    pcap_offline = pcap_open_offline(filename, errtext)
    if not pcap_offline:
        return NULL
    else:
        return pcap_offline

cdef pcap_t *open_dead(int linktype,
                       int snaplen):
    cdef:
        pcap_t * pcap_dead

    pcap_dead = pcap_open_dead(linktype, snaplen)
    return pcap_dead

cpdef pcap_pkthdr_t get_pkts_header(double ts, bytes data):
    cdef:
        pcap_pkthdr_t hdr
        uint32_t pkt_len = len(data)
        uint32_t t_sec = int(ts)
        uint32_t t_usec = int(str(ts).split('.')[1])

    hdr.ts.tv_sec = t_sec
    hdr.ts.tv_usec = t_usec
    hdr.caplen = hdr.len = pkt_len
    return hdr


cdef class PCAPBase:
    def __cinit__(self, *args, **kwargs):
        self.dumper = NULL
        self.have_dumper = 0
        self.start_ts = 0
        self.end_ts = 0

    cdef int _open_pcap_dumper(self, str file_name, pcap_t * sock):
        cdef:
            char * filename = b''
            bytes encoded

        encoded = file_name.encode()
        filename = encoded
        self.dumper = pcap_dump_open(sock, filename)
        if self.dumper is NULL:
            return ERROR
        else:
            self.have_dumper = 1
            return 0

    cpdef void close_pcap_dumper(self):
        if self.dumper is not NULL:
            pcap_dump_close(self.dumper)
        self.dumper = NULL
        self.have_dumper = 0

    cpdef void dump_hdr_pkt(self,
                            pcap_pkthdr_t hdr,
                            bytes data,
                            uint32_t tv_sec=0,
                            uint32_t tv_usec=0):
        cdef:
            const pcap_pkthdr * pcap_hdr
            unsigned char * buff

        if tv_sec:
            hdr.p_hdr.ts.tv_sec = tv_sec
            hdr.p_hdr.ts.tv_usec = tv_usec
        buff = data
        pcap_hdr = &hdr
        if self.dumper is not NULL:
            pcap_dump(<u_char *>self.dumper ,pcap_hdr , buff)

    cpdef void dump_pkt(self,
                        bytes data,
                        uint32_t tv_sec=0,
                        uint32_t tv_usec=0):
        cdef:
            const pcap_pkthdr * pcap_hdr
            pcap_pkthdr_t hdr
            unsigned char * buff

        hdr = get_pkts_header(time.time(), data)
        if tv_sec:
            hdr.ts.tv_sec = tv_sec
            hdr.ts.tv_usec = tv_usec
        buff = data
        pcap_hdr = &hdr
        if self.dumper is not NULL:
            pcap_dump(<u_char *>self.dumper ,pcap_hdr , buff)

    cdef int _add_bpf_filter(self,
                             str bpf_filter,
                             pcap_t * sock,
                             bpf_u_int32 mask):
        cdef:
            bpf_program bpfprog
            int rval
            bytes encoded
            char* fltr = b''

        encoded = bpf_filter.encode()
        fltr = encoded
        rval = pcap_compile(sock, &bpfprog, fltr, 1, mask)

        if rval == ERROR:
            raise Exception("Failed to compile BPF filter")
        else:
            rval = pcap_setfilter(sock, &bpfprog)
        return rval

    cpdef int add_bpf_filter(self, str bpf_filter):
        return 0

cdef class PCAPSocket(PCAPBase):
    def __cinit__(self, *args, **kwargs):
        self.dumper = NULL
        self.have_dumper = 0

    def __init__(self, *args, **kwargs):
        cdef:
            char * errors = <char *> malloc(ERRBUF_SIZE * sizeof(char))
            const char * dev
            object v_err
            bytes dn
            int snaplen, promisc, to_ms, status

        dn = kwargs.get('devicename', '').encode()
        dev = dn
        self.devicename = dev
        snaplen = kwargs.get('snaplen', 0)
        promisc = kwargs.get('promisc', 1)
        to_ms = kwargs.get('to_ms', 100)
        self.sock = open_live(self.devicename,
                              snaplen,
                              promisc,
                              to_ms,
                              errors)

        if self.sock is NULL:
            v_err = ValueError("PCAPSocket failed to open device {0}. "
                               "Error was: {1}".format(self.devicename,
                                                       errors))
            free(errors)
            raise v_err
        else:
            self.net = self.mask = 0
            status = lookupnet(self.devicename,
                               &self.net, &self.mask,
                               errors)
            if status == ERROR:
                self.mask = PCAP_NETMASK_UNKNOWN
        self.stop_event = Event()

    property network:
        """
        get and set payload bytes
        """
        def __get__(self):
            cdef:
                uint32_t net
            net = socket.ntohl(self.net)
            return int2ip(net)

    property netmask:
        """
        get and set payload bytes
        """
        def __get__(self):
            cdef:
                uint32_t mask
            mask = socket.ntohl(self.mask)
            return int2ip(mask)

    cpdef int set_snaplen(self, int snaplen):
        return pcap_set_snaplen(self.sock, snaplen)

    cpdef int set_promisc(self, int promisc):
        return pcap_set_promisc(self.sock, promisc)

    cpdef int set_timeout(self, int timeout):
        return pcap_set_timeout(self.sock, timeout)


    cpdef int getnonblock(self):
        cdef:
            char * errors = <char *> malloc(ERRBUF_SIZE * sizeof(char))
            int rval
        rval =  pcap_getnonblock(self.sock, errors)
        free(errors)
        return rval

    cpdef int setnonblock(self, int nonblock):
        cdef:
            char * errors = <char *> malloc(ERRBUF_SIZE * sizeof(char))
            int rval
            object err

        rval =  pcap_setnonblock(self.sock, nonblock, errors)
        free(errors)
        return rval

    cpdef int sendpacket(self, bytes pktdata):
        cdef:
            char * errors = <char *> malloc(ERRBUF_SIZE * sizeof(char))
            const unsigned char * buff = b''
            bytes error_out
            object err
            int rval, _len

        buff = pktdata
        _len = len(pktdata)
        rval = pcap_sendpacket(self.sock, buff, _len)

        if rval == ERROR:
            error_out = errors[0]
            err = Exception(error_out.decode())
            free(errors)
            raise err
        else:
            return _len

    cpdef int open_pcap_dumper(self, str file_name):
        return self._open_pcap_dumper(file_name, self.sock)

    cpdef int add_bpf_filter(self, str bpf_filter):
        return self._add_bpf_filter(bpf_filter, self.sock, self.mask)

    def __iter__(self):
        return self

    def __next__(self):
        cdef:
            pcap_pkthdr * hdr = NULL
            const unsigned char * buff
            int err = 1
            double ts
            bytes pkt = b''

        err = pcap_next_ex(self.sock, &hdr, &buff)
        if err in (ERROR, ERROR_BREAK) or self.stop_event.is_set():
            self.close()
            if self.have_dumper:
                self.close_pcap_dumper()
            raise StopIteration
        elif err == 0:
            return 0, None, None
        else:
            if hdr[0].ts.tv_usec > 0:
                ts = (hdr[0].ts.tv_sec + (hdr[0].ts.tv_usec / USECCONST))
            else:
                ts = hdr[0].ts.tv_sec
            pkt = <bytes> buff[:hdr[0].caplen]
            return ts, hdr[0], pkt

    cpdef void close(self):
        if self.dumper is not NULL:
            self.close_pcap_dumper()
        self.stop_event.set()
        if self.sock is not NULL:
            pcap_close(self.sock)
        self.sock = NULL

cdef class PCAPReader(PCAPBase):
    def __cinit__(self, *args, **kwargs):
        self.dumper = NULL

    def __init__(self, *args, **kwargs):
        cdef:
            char * errors = <char *> malloc(ERRBUF_SIZE * sizeof(char))
            const char * fname_p
            bytes fname_bytes
            str fname_srt
            object v_err
            str src_file

        fname_srt = kwargs.get('filename', '')
        fname_bytes = fname_srt.encode()
        fname_p = fname_bytes
        self.filename = fname_p
        self.have_dumper = 0
        self.reader = open_offline(self.filename, errors)

        if self.reader is NULL:
            v_err = ValueError("PCAPReader failed to open {0} for reading. "
                               "Error was: {1}".format(self.filename, errors))
            free(errors)
            raise v_err
        else:
            free(errors)

    cpdef int open_pcap_dumper(self, str file_name):
        return self._open_pcap_dumper(file_name, self.reader)

    cpdef int add_bpf_filter(self, str bpf_filter):
        return self._add_bpf_filter(bpf_filter, self.reader, NETMASK_UNKNOWN)

    def __iter__(self):
        return self

    def __next__(self):
        cdef:
            pcap_pkthdr * hdr = NULL
            const unsigned char * buff
            int err = 1
            double ts
            bytes pkt = b''

        err = pcap_next_ex(self.reader, &hdr, &buff)
        if err != 1:
            self.close()
            if self.have_dumper:
                self.close_pcap_dumper()
            raise StopIteration
        else:
            if hdr[0].ts.tv_usec > 0:
                ts = (hdr[0].ts.tv_sec + (hdr[0].ts.tv_usec / USECCONST))
            else:
                ts = hdr[0].ts.tv_sec
            pkt = <bytes> buff[:hdr[0].caplen]
            return ts, hdr[0], pkt

    cpdef list pkts(self):
        return list(self)

    cpdef void close(self):
        if self.dumper is not NULL:
            self.close_pcap_dumper()
        if self.reader is not NULL:
            pcap_close(self.reader)
            self.reader = NULL


cdef class PCAPWriter(PCAPBase):
    def __cinit__(self, *args, **kwargs):
        self.dumper = NULL

    def __init__(self, *args, **kwargs):
        cdef:
            object v_err
            int rval
            str fn

        self.snaplen = kwargs.get('snaplen', 0)
        fn = kwargs.get('filename', '')

        self.have_dumper = 1
        self.pcap_dead = open_dead(ETH_EN10MB, self.snaplen)

        if self.pcap_dead is NULL:
            v_err = ValueError("PCAPWriter failed to open a dead pcap_t *")
            raise v_err
        if fn:
            rval = self.open_pcap_dumper(fn)
            if rval:
                v_err = ValueError("PCAPWriter could not open a pcap_dumper_t")
                raise v_err

    cpdef int open_pcap_dumper(self, str file_name):
        return self._open_pcap_dumper(file_name, self.pcap_dead)

    cpdef void close(self):
        if self.dumper is not NULL:
            self.close_pcap_dumper()
        if self.pcap_dead is not NULL:
            pcap_close(self.pcap_dead)
            self.pcap_dead = NULL


cpdef dict pcap_info(str filename):
    """Helper function used by steelscript.wireshark and steelscript.appfwk
    PCAP manager to obtain information about pcap files.

    Args:
        :filename (str)

    Returns:
        :dict: Keys are first_timestamp, last_timestamp, total_packets,
            and total_bytes and will contain those metrics from the PCAP file
            opened as f.
    """
    cdef:
        PCAPReader rdr
        pcap_pkthdr_t hdr
        bytes pkt
        uint32_t pkts
        uint64_t byte_count
        double ts
        double first_ts
        dict rval

    rdr = PCAPReader(file_name=filename)
    ts, hdr, pkt = next(rdr)
    first_ts = ts
    pkts = 1
    byte_count = hdr.caplen
    for ts, hdr, pkt in rdr:
        pkts += 1
        byte_count += hdr.caplen
    rval = {'first_timestamp': first_ts,
            'last_timestamp': ts,
            'total_packets': pkts,
            'total_bytes': byte_count}
    return rval

cpdef int netflow_replay_raw_sock(str device,
                                  str pcap_file,
                                  uint16_t pcap_dst_port,
                                  str dest_ip,
                                  str dest_mac,
                                  uint16_t dest_port,
                                  str src_ip='',
                                  str src_mac='',
                                  unsigned char blast_mode=0):
    """
    Function to replay pcap files containing netflow versions 1-9.
    :param device: Device to bind our outgoing socket to.
    :param pcap_file: The file containing the packets we want to replay.
    :param pcap_dst_port: The UDP src port of the netflow packets we are 
           interested in.

    :param dest_ip: The IP address we want to send these packets to.
    :param dest_mac: The MAC address of the destination IP.
    :param dest_port: The port that the recipient device will be listening on.
    :param src_ip: The IP address we want to send these packets from.
    :param src_mac: The MAC address we want to send these packets from.
    :param blast_mode: bool value. 0 == play at the same pace as in the pcap or
           at the speed defined by speedup. 1 means blast as fast as possible.
           Overrides speedup if set.
    :param speedup: divide the inter-packet gap by this number.
    :return: std unix 0 or 1 for all is well and something went wrong.
    """

    cdef:
        PCAPSocket sender
        PCAPReader reader
        unsigned char do_src, do_mac
        double now, ts, offset, add
        pcap_pkthdr_t hdr
        bytes pkt
        Ethernet eth

    sender = PCAPSocket(devicename=device)
    sender.setnonblock(1)

    reader = PCAPReader(filename=pcap_file)
    reader.add_bpf_filter('udp dst port {0}'.format(pcap_dst_port))

    if src_ip == '':
        do_src = 0
    else:
        do_src = 1
    if src_mac == '':
        do_mac = 0
    else:
        do_mac = 1
    ts, hdr, pkt = next(reader)
    now = time.time()
    eth = Ethernet(pkt, l7_ports={pcap_dst_port: NetflowSimple})
    offset = now - ts
    eth.dst_mac = dest_mac
    eth.payload.dst = dest_ip
    eth.payload.payload.dport = dest_port
    eth.payload.payload.payload.unix_secs = int(now)
    if eth.payload.payload.payload != 9:
        eth.payload.payload.payload.unix_nano_seconds = int((now % 1) *
                                                            1000000)
    sender.sendpacket(eth.pkt2net({'csum': 1, 'update': 1}))
    for ts, hdr, pkt in reader:
        eth = Ethernet(pkt, l7_ports={pcap_dst_port: NetflowSimple})
        now = time.time()
        if not blast_mode and ts + offset >= now:
            add = (ts + offset) - now
            time.sleep(add)
            now += add
        if do_mac:
            eth.src_mac = src_mac
        eth.dst_mac = dest_mac
        if do_src:
            eth.payload.src = src_ip
        eth.payload.dst = dest_ip
        eth.payload.payload.dport = dest_port
        eth.payload.payload.payload.unix_secs = int(now)
        if eth.payload.payload.payload != 9:
            eth.payload.payload.payload.unix_nano_seconds = int((now % 1) *
                                                                1000000)
        sender.sendpacket(eth.pkt2net({'csum': 1, 'update': 1}))
    return 0


cpdef int netflow_replay_system_sock(str pcap_file,
                                     uint16_t pcap_dst_port,
                                     str dest_ip,
                                     uint16_t dest_port,
                                     unsigned char blast_mode=0):
    """
    Function to replay pcap files containing netflow versions 1-9.
    :param pcap_file: The file containing the packets we want to replay.
    :param pcap_dst_port: The UDP src port of the netflow packets we are 
           interested in.
    :param dest_ip: The IP address we want to send these packets to.
    :param dest_port: The port that the recipient device will be listening on.
    :param blast_mode: bool value. 0 == play at the same pace as in the pcap or
           at the speed defined by speedup. 1 means blast as fast as possible.
           Overrides speedup if set.
    :return: std unix 0 or 1 for all is well and something went wrong.
    """

    cdef:
        object sender
        PCAPReader reader
        double now, ts, offset, add
        pcap_pkthdr_t hdr
        bytes pkt
        Ethernet eth
        PKT nf

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    reader = PCAPReader(filename=pcap_file)
    reader.add_bpf_filter('udp dst port {0}'.format(pcap_dst_port))

    ts, hdr, pkt = next(reader)
    now = time.time()
    eth = Ethernet(pkt, l7_ports={pcap_dst_port: NetflowSimple})
    offset = now - ts
    nf = eth.get_layer_by_type(PQ_NETFLOW_SIMPLE)
    nf.unix_secs = int(now)
    if nf.version != 9:
        nf.unix_nano_seconds = int((now % 1) * 1000000)
    sender.sendto(nf.pkt2net({}), (dest_ip, dest_port))
    for ts, hdr, pkt in reader:
        eth = Ethernet(pkt, l7_ports={pcap_dst_port: NetflowSimple})
        nf = eth.get_layer_by_type(PQ_NETFLOW_SIMPLE)
        now = time.time()
        if not blast_mode and ts + offset >= now:
            add = (ts + offset) - now
            time.sleep(add)
            now += add
        nf.unix_secs = int(now)
        if nf.version != 9:
            nf.unix_nano_seconds = int((now % 1) * 1000000)
        sender.sendto(nf.pkt2net({}), (dest_ip, dest_port))
    return 0