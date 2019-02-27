import pcapy


class PktSource(object):
    def __init__(self, *args, **kwargs):
        self.source_type = kwargs.get('source_type', 'socket')
        self.source_name = kwargs.get('source_name')
        self.bpf_filter = kwargs.get('bpf_filter')
        self.snap_len = kwargs.get('snap_len', 0)
        self.promisc = kwargs.get('promisc', 0)
        self.read_timeout = kwargs.get('read_timeout', 0)
        if self.source_type == 'file':
            self.rdr = pcapy.open_offline(self.source_name)
        elif self.source_type == 'socket':
            self.rdr = pcapy.open_live(self.source_name,
                                       self.snap_len,
                                       self.promisc,
                                       self.read_timeout)
        else:
            raise ValueError('PktSource.source_type not in {}'
                             ''.format(['file', 'socket']))
        if self.bpf_filter:
            self.rdr.setfilter(self.bpf_filter)

    def __iter__(self):
        if self.rdr:
            rdr = self.rdr
            hdr = 1
            while hdr:
                hdr, pkt = rdr.next()
                if (hdr and
                        (pkt[12:14] == b'\x08\x06' or
                         (pkt[12:14] == b'\x08\x00' and pkt[23] == 1))):
                    yield hdr, pkt
            return
