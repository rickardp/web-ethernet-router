import struct
import time

def open_pcap(filename):
    fh = open(filename, "wb")
    fh.write(struct.pack('>I', 0xa1b2c3d4)) # magic
    fh.write(struct.pack('>HH', 2, 4)) # version
    fh.write(struct.pack('>I', 0)) # thiszone
    fh.write(struct.pack('>I', 0)) # sigfigs
    fh.write(struct.pack('>I', 0xffff)) # snaplen
    fh.write(struct.pack('>I', 1)) # network
    return fh

def write_pcap(fh, data):
    try:
        ts = time.time()
        fh.write(struct.pack('>I', int(ts))) # timestamp seconds
        fh.write(struct.pack('>I', int(ts * 1e6) % 1000000)) # timestamp microseconds
        fh.write(struct.pack('>I', len(data))) # incl_len
        fh.write(struct.pack('>I', len(data))) # orig_len
        fh.write(data)
        fh.flush()
    except ValueError: #fh was closed
        pass
