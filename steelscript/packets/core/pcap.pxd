# cython: language_level=3

# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

# all of the previous pcap code has been moved out because all of our
# pcap processing is not based on a direct wrap of libpcap's pcap.h and
# related files

# Note: This means that socket operations (open_live) have been added to
# pcap's set of features.

from libc.stdio cimport FILE
from libc.time cimport time_t
from libc.stdint cimport uint16_t, uint32_t

DEF BUFFSIZE = 256
DEF PCAP_NETMASK_UNKNOWN = 0xffffffff

cdef:
    char VERSION_MAJOR
    char VERSION_MINOR
    uint16_t ERRBUF_SIZE
    char ERROR
    char ERROR_BREAK
    char ERROR_NOT_ACTIVATED
    char ERROR_ACTIVATED
    char ERROR_NO_SUCH_DEVICE
    char ERROR_RFMON_NOTSUP
    char ERROR_NOT_RFMON
    char ERROR_PERM_DENIED
    char ERROR_IFACE_NOT_UP
    char ERROR_CANTSET_TSTAMP_TYPE
    char ERROR_PROMISC_PERM_DENIED
    char ERROR_TSTAMP_PRECISION_NOTSUP
    char WARNING
    char WARNING_PROMISC_NOTSUP
    char WARNING_TSTAMP_TYPE_NOTSUP
    uint32_t NETMASK_UNKNOWN
    char TSTAMP_HOST
    char TSTAMP_HOST_LOWPREC
    char TSTAMP_HOST_HIPREC
    char TSTAMP_ADAPTER
    char TSTAMP_ADAPTER_UNSYNCED
    char TSTAMP_PRECISION_MICRO
    char TSTAMP_PRECISION_NANO
    char ETH_NULL
    char ETH_EN10MB
    char ETH_IEEE802
    char ETH_ARCNET
    char ETH_SLIP
    char ETH_PPP
    char ETH_FDDI
    char ETH_ATM_RFC1483
    char ETH_RAW
    char ETH_PPP_SERIAL
    char ETH_PPP_ETHER
    char ETH_C_HDLC
    char ETH_IEEE802_11
    char ETH_LOOP
    char ETH_LINUX_SLL
    char ETH_LTALK
    uint32_t PCAP_NETMASK_UNKNOWN

cdef class PCAP_CONST:
    cdef:
        readonly char VERSION_MAJOR
        readonly char VERSION_MINOR
        uint16_t ERRBUF_SIZE
        readonly char ERROR
        readonly char ERROR_BREAK
        readonly char ERROR_NOT_ACTIVATED
        readonly char ERROR_ACTIVATED
        readonly char ERROR_NO_SUCH_DEVICE
        readonly char ERROR_RFMON_NOTSUP
        readonly char ERROR_NOT_RFMON
        readonly char ERROR_PERM_DENIED
        readonly char ERROR_IFACE_NOT_UP
        readonly char ERROR_CANTSET_TSTAMP_TYPE
        readonly char ERROR_PROMISC_PERM_DENIED
        readonly char ERROR_TSTAMP_PRECISION_NOTSUP
        readonly char WARNING
        readonly char WARNING_PROMISC_NOTSUP
        readonly char WARNING_TSTAMP_TYPE_NOTSUP
        uint32_t NETMASK_UNKNOWN
        readonly char TSTAMP_HOST
        readonly char TSTAMP_HOST_LOWPREC
        readonly char TSTAMP_HOST_HIPREC
        readonly char TSTAMP_ADAPTER
        readonly char TSTAMP_ADAPTER_UNSYNCED
        readonly char TSTAMP_PRECISION_MICRO
        readonly char TSTAMP_PRECISION_NANO
        readonly char ETH_NULL
        readonly char ETH_EN10MB
        readonly char ETH_IEEE802
        readonly char ETH_ARCNET
        readonly char ETH_SLIP
        readonly char ETH_PPP
        readonly char ETH_FDDI
        readonly char ETH_ATM_RFC1483
        readonly char ETH_RAW
        readonly char ETH_PPP_SERIAL
        readonly char ETH_PPP_ETHER
        readonly char ETH_C_HDLC
        readonly char ETH_IEEE802_11
        readonly char ETH_LOOP
        readonly char ETH_LINUX_SLL
        readonly char ETH_LTALK

# General Types used
ctypedef unsigned char __uint8_t
ctypedef short __int16_t
ctypedef unsigned short __uint16_t
ctypedef int __int32_t
ctypedef unsigned int __uint32_t
ctypedef long long __int64_t
ctypedef unsigned long long __uint64_t
ctypedef __uint8_t sa_family_t
ctypedef unsigned short u_short
ctypedef unsigned char u_char
ctypedef unsigned int bpf_u_int32
ctypedef int bpf_int32
ctypedef unsigned int u_int


cdef extern from "<sys/time.h>" nogil:
    struct timeval:
        time_t tv_sec
        time_t tv_usec

cdef extern from "<signal.h>" nogil:
    ctypedef int sig_atomic_t

cdef extern from "<sys/socket.h>" nogil:
    struct sockaddr:
        __uint8_t sa_len
        sa_family_t sa_family
        char sa_data[14]


cdef extern from "<pcap/bpf.h>" nogil:
    struct bpf_insn:
        u_short code
        u_char jt
        u_char jf
        bpf_u_int32 k

    struct bpf_program:
        u_int bf_len
        bpf_insn *bf_insns

cdef extern from "<pcap.h>" nogil:

    ctypedef pcap pcap_t
    ctypedef pcap_dumper pcap_dumper_t
    ctypedef pcap_if pcap_if_t
    ctypedef pcap_addr pcap_addr_t

    char *pcap_lookupdev(char *)
    int pcap_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *, char *)
    pcap_t *pcap_create(const char *, char *)

    int pcap_set_snaplen(pcap_t *, int)
    int pcap_set_promisc(pcap_t *, int)
    int pcap_can_set_rfmon(pcap_t *)
    int pcap_set_rfmon(pcap_t *, int)
    int pcap_set_timeout(pcap_t *, int)
    int pcap_set_tstamp_type(pcap_t *, int)
    int pcap_set_immediate_mode(pcap_t *, int)
    int pcap_set_buffer_size(pcap_t *, int)
    int pcap_set_tstamp_precision(pcap_t *, int)
    int pcap_get_tstamp_precision(pcap_t *)
    int pcap_activate(pcap_t *)
    pcap_t *pcap_open_live(const char *, int, int, int, char *)
    pcap_t *pcap_open_offline(const char *, char *)
    pcap_t *pcap_open_dead(int, int)
    void pcap_close(pcap_t *)
    int pcap_loop(pcap_t *, int, pcap_handler, u_char *)
    int pcap_dispatch(pcap_t *, int, pcap_handler, u_char *)
    const u_char* pcap_next(pcap_t *, pcap_pkthdr *)
    int pcap_next_ex(pcap_t *, pcap_pkthdr **, const u_char **)
    void pcap_breakloop(pcap_t *)
    int pcap_stats(pcap_t *, pcap_stat *)
    int pcap_setfilter(pcap_t *, bpf_program *)
    int pcap_setdirection(pcap_t *, pcap_direction_t)
    int pcap_getnonblock(pcap_t *, char *)
    int pcap_setnonblock(pcap_t *, int, char *)
    int pcap_sendpacket(pcap_t *, const u_char *, int)
    int pcap_compile(pcap_t *, bpf_program *,
                     const char *, int,
                     bpf_u_int32)
    int pcap_compile_nopcap(int, int, bpf_program *,
                            const char *, int,
                            bpf_u_int32)
    void pcap_freecode(bpf_program *);
    int pcap_offline_filter(const bpf_program *,
                            const pcap_pkthdr *,
                            const u_char *)
    int pcap_snapshot(pcap_t *)
    int pcap_is_swapped(pcap_t *)
    int pcap_major_version(pcap_t *)
    int pcap_minor_version(pcap_t *)

    FILE *pcap_file(pcap_t *)
    int pcap_fileno(pcap_t *)

    pcap_dumper_t *pcap_dump_open(pcap_t *, const char *)
    pcap_dumper_t *pcap_dump_fopen(pcap_t *, FILE *fp)
    FILE *pcap_dump_file(pcap_dumper_t *)
    long pcap_dump_ftell(pcap_dumper_t *)
    int pcap_dump_flush(pcap_dumper_t *)
    void pcap_dump_close(pcap_dumper_t *)
    void pcap_dump(u_char *, const pcap_pkthdr *, const u_char *)

    int pcap_findalldevs(pcap_if_t **, char *)
    void pcap_freealldevs(pcap_if_t *)
    const char *pcap_lib_version()

    # Only doing Linux and MACOS so we will declare bpf_filter
    uint32_t bpf_filter(const bpf_insn *, const u_char *, u_int, u_int)
    int bpf_validate(const bpf_insn *f, int len)
    char *bpf_image(const bpf_insn *, int)
    void bpf_dump(const bpf_program *, int)

    pcap_dumper_t *pcap_dump_open(pcap_t *, const char *)
    int	pcap_dump_flush(pcap_dumper_t *);
    void pcap_dump_close(pcap_dumper_t *);
    void pcap_dump(u_char *, const pcap_pkthdr *, const u_char *);

    ctypedef int (*activate_op_t)(pcap_t *)
    ctypedef int (*can_set_rfmon_op_t)(pcap_t *)
    ctypedef int (*read_op_t)(pcap_t *, int cnt, pcap_handler, u_char *)
    ctypedef int (*next_packet_op_t)(pcap_t *, pcap_pkthdr *, u_char **)
    ctypedef int (*inject_op_t)(pcap_t *, const void *, int)
    ctypedef void (*save_current_filter_op_t)(pcap_t *, const char *)
    ctypedef int (*setfilter_op_t)(pcap_t *, bpf_program *)
    ctypedef int (*setdirection_op_t)(pcap_t *, pcap_direction_t)
    ctypedef int (*set_datalink_op_t)(pcap_t *, int)
    ctypedef int (*getnonblock_op_t)(pcap_t *)
    ctypedef int (*setnonblock_op_t)(pcap_t *, int)
    ctypedef int (*stats_op_t)(pcap_t *, pcap_stat *)
    ctypedef void (*breakloop_op_t)(pcap_t *)
    ctypedef void (*pcap_handler)(u_char *,
                                  const pcap_pkthdr *,
                                  const u_char *)
    ctypedef void (*cleanup_op_t)(pcap_t *)

    IF UNAME_SYSNAME == "Linux":
        struct pcap_opt:
            char *device
            int timeout
            u_int buffer_size;
            int promisc
            int rfmon
            int immediate
            int nonblock
            int tstamp_type
            int tstamp_precision
            int protocol
    ELIF UNAME_SYSNAME == "Darwin":
        struct pcap_opt:
            char *device
            int timeout
            u_int buffer_size;
            int promisc
            int rfmon
            int immediate
            int nonblock
            int tstamp_type
            int tstamp_precision

    struct pcap_dumper

    struct pcap_pkthdr:
        timeval ts
        bpf_u_int32 caplen
        bpf_u_int32 len

    struct pcap:
        read_op_t read_op
        next_packet_op_t next_packet_op
        int fd
        u_int bufsize
        void *buffer
        u_char *bp
        int cc
        sig_atomic_t break_loop
        # Not doing pcap_samp rmt_samp
        int swapped
        FILE *rfile
        u_int fddipad
        pcap *next
        int version_major
        int version_minor
        int snapshot
        int linktype
        int linktype_ext
        int offset
        int activated
        int oldstyle
        pcap_opt opt
        u_char *pkt
        pcap_direction_t direction
        int bpf_codegen_flags
        int selectable_fd
        timeval *required_select_timeout
        bpf_program fcode
        char errbuf[BUFFSIZE + 1]
        int dlt_count
        u_int *dlt_list
        int tstamp_type_count
        u_int *tstamp_type_list
        int tstamp_precision_count
        u_int *tstamp_precision_list
        pcap_pkthdr pcap_header
        #More methods.
        activate_op_t activate_op
        can_set_rfmon_op_t can_set_rfmon_op
        inject_op_t inject_op
        save_current_filter_op_t save_current_filter_op;
        setfilter_op_t setfilter_op;
        setdirection_op_t setdirection_op;
        set_datalink_op_t set_datalink_op;
        getnonblock_op_t getnonblock_op;
        setnonblock_op_t setnonblock_op;
        stats_op_t stats_op;
        breakloop_op_t breakloop_op;
        # Routine to use as callback for pcap_next()/pcap_next_ex().
        pcap_handler oneshot_callback
        cleanup_op_t cleanup_op

    struct pcap_file_header:
        bpf_u_int32 magic
        u_short version_major
        u_short version_minor
        bpf_int32 thiszone
        bpf_u_int32 sigfigs
        bpf_u_int32 snaplen
        bpf_u_int32 linktype

    cdef enum pcap_direction_t:
       PCAP_D_INOUT = 0
       PCAP_D_IN = 1
       PCAP_D_OUT = 2

    struct pcap_stat:
        u_int ps_recv
        u_int ps_drop
        u_int ps_ifdrop

    struct pcap_if:
        pcap_if * next
        char * name
        char * description
        pcap_addr * addresses
        bpf_u_int32 flags

    struct pcap_addr:
        pcap_addr * next
        sockaddr * addr
        sockaddr * netmask
        sockaddr * broadaddr
        sockaddr * dstaddr

    struct pcap_timeval:
        bpf_int32 tv_sec
        bpf_int32 tv_usec

    struct pcap_sf_pkthdr:
        pcap_timeval ts
        bpf_u_int32 caplen
        bpf_u_int32 len

    struct pcap_sf_patched_pkthdr:
        pcap_timeval ts
        bpf_u_int32 caplen
        bpf_u_int32 len
        int index
        unsigned short protocol
        unsigned char pkt_type

    struct oneshot_userdata:
        pcap_pkthdr *hdr
        const u_char **pkt
        pcap_t *pd

cdef struct pcapdumper:
    pcap_dumper_t * dumper

ctypedef pcap_pkthdr pcap_pkthdr_t

cpdef uint32_t ip2int(str addr)
cpdef str int2ip(uint32_t addr)

cpdef char *lookupdev(char *errtext)
cpdef int findalldevs(list devices, char *errtext)
cdef int lookupnet(const char *device,
                   bpf_u_int32 *net,
                   bpf_u_int32 *mask,
                   char *errtext)
cdef pcap_t *open_live(const char * device,
                       int snaplen,
                       int promisc,
                       int to_ms,
                       char *errtext)
cdef pcap_t *open_offline(const char * filename,
                          char *errtext)
cdef pcap_t *open_dead(int linktype,
                       int snaplen)


cdef class PCAPBase:
    cdef:
        pcap_dumper_t * dumper
        bint have_dumper
        double start_ts, end_ts

    cdef int _open_pcap_dumper(self, str file_name, pcap_t * sock)
    cpdef void close_pcap_dumper(self)
    cpdef void dump_hdr_pkt(self,
                            pcap_pkthdr_t hdr,
                            bytes data,
                            uint32_t tv_sec=*,
                            uint32_t tv_usec=*)
    cpdef void dump_pkt(self,
                        bytes data,
                        uint32_t tv_sec=*,
                        uint32_t tv_usec=*)
    cdef int _add_bpf_filter(self,
                             str bpf_filter,
                             pcap_t * sock,
                             bpf_u_int32 mask)
    cpdef int add_bpf_filter(self, str bpf_filter)


cdef class PCAPSocket(PCAPBase):
    cdef:
        public object stop_event
        const char * devicename
        pcap_t * sock
        bpf_u_int32 net
        bpf_u_int32 mask

    cpdef int set_snaplen(self, int snaplen)
    cpdef int set_promisc(self, int promisc)
    cpdef int set_timeout(self, int timeout)
    cpdef int getnonblock(self)
    cpdef int setnonblock(self, int nonblock)
    cpdef int sendpacket(self, bytes pktdata)
    cpdef int add_bpf_filter(self, str bpf_filter)
    cpdef int open_pcap_dumper(self, str file_name)
    cpdef void close(self)


cdef class PCAPReader(PCAPBase):
    cdef:
        const char * filename
        pcap_t * reader


    cpdef list pkts(self)
    cpdef void close(self)
    cpdef int open_pcap_dumper(self, str file_name)
    cpdef int add_bpf_filter(self, str bpf_filter)


cdef class PCAPWriter(PCAPBase):
    cdef:
        pcap_t * pcap_dead
        uint16_t snaplen


    cpdef void close(self)
    cpdef int open_pcap_dumper(self, str file_name)


cpdef pcap_pkthdr_t get_pkts_header(double ts, bytes data)

cpdef dict pcap_info(str filename)

cpdef int netflow_replay_raw_sock(str device,
                                  str pcap_file,
                                  uint16_t pcap_dst_port,
                                  str dest_ip,
                                  str dest_mac,
                                  uint16_t dest_port,
                                  str src_ip=*,
                                  str src_mac=*,
                                  unsigned char blast_mode=*)

cpdef int netflow_replay_system_sock(str pcap_file,
                                     uint16_t pcap_dst_port,
                                     str dest_ip,
                                     uint16_t dest_port,
                                     unsigned char blast_mode=*)
