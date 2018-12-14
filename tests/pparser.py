import dpkt
import datetime
import sys

def saddr(addr):
    return "{}.{}.{}.{}".format(ord(addr[0]), ord(addr[1]), ord(addr[2]), 
                                ord(addr[3]))

def addr2int(addr):
    value = 0
    for f in addr:
        value = value << 8
        value += ord(f)
    return value


counter     = 0
ipcounter   = 0
tcpcounter  = 0
udpcounter  = 0
icmpcounter = 0
ipv6counter = 0
grecounter  = 0
espcounter  = 0

if len(sys.argv) < 2:
    print("Missing pcap file.")
    exit(1)

if len(sys.argv) < 3:
    print("Missing output file.")
    exit(1)

filename = sys.argv[1]
if not filename.endswith(".pcap"):
    print("File must be pcap.")
    exit(1)

outfname = sys.argv[2]
outfile = open(outfname, "w")
print("Reading " + filename)
for ts, pkt in dpkt.pcap.Reader(open(filename, "r")):

    counter += 1
    eth = dpkt.ethernet.Ethernet(pkt) 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
       continue
    
    dt = datetime.datetime.utcfromtimestamp(ts)
    # ptime = dt.hour
    # ptime = (ptime * 60) + dt.minute
    # ptime = (ptime * 60) + dt.second
    # ptime = (ptime * (10**6)) + dt.microsecond
    etime = (dt - datetime.datetime(1970, 1, 1))
    ptime = etime.total_seconds()
    
    ip = eth.data
    ipcounter += 1

    src = addr2int(ip.src)
    dst = addr2int(ip.dst)
    addr1 = src
    addr2 = dst
    if src > dst:
        addr1 = dst
        addr2 = src

    outfile.write(str(addr1))
    outfile.write(",")
    outfile.write(str(addr2))
    outfile.write(",")
    outfile.write(str(len(eth)))
    outfile.write(",")
    outfile.write(str(ptime))
    outfile.write("\n")

    # print("src: " + saddr(ip.src) + "(" + str(src) + ") dst: " + \
    #       saddr(ip.dst) + "(" + str(dst) + ") len: " + str(len(eth)))
    
    if ip.p == dpkt.ip.IP_PROTO_TCP: 
       tcpcounter += 1
    elif ip.p == dpkt.ip.IP_PROTO_UDP:
       udpcounter += 1
    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
        icmpcounter += 1
    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
        icmpcounter += 1
    elif ip.p == dpkt.ip.IP_PROTO_IP6:
        ipv6counter += 1
    elif ip.p == dpkt.ip.IP_PROTO_GRE:
        grecounter += 1
    elif ip.p == dpkt.ip.IP_PROTO_ESP:
        espcounter += 1

print("Total number of packets in the pcap file: {}".format(counter))
print("Total number of ip packets: {}".format(ipcounter))
print("Total number of tcp packets: {}".format(tcpcounter))
print("Total number of udp packets: {}".format(udpcounter))
print("Total number of icmp packets: {}".format(icmpcounter))
print("Total number of ipv6 packets: {}".format(ipv6counter))
print("Total number of gre packets: {}".format(grecounter))
print("Total number of esp packets: {}".format(espcounter))