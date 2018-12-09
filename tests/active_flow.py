import sys

Inf = float("inf")

class Entry:
    def __init__(self, addr1, addr2, plen):
        self.addr1 = addr1
        self.addr2 = addr2
        self.len   = plen

inname    = None    # input file name
outname   = None    # output file name
maxtime   = 0       # max estimation time (in seconds)
tactive   = Inf     # threshold for active flows (in seconds)
lspeed    = 0       # link speed (in bps)
cinterval = 1       # checking interval (in seconds)

i = 1
while i < len(sys.argv):
    if sys.argv[i] == "-i":
        i += 1
        inname = sys.argv[i]
    elif sys.argv[i] == "-o":
        i += 1
        outname = sys.argv[i]
    elif sys.argv[i] == "-t":
        i += 1
        maxtime = float(sys.argv[i])
    elif sys.argv[i] == "-a":
        i += 1
        tactive = float(sys.argv[i])
    elif sys.argv[i] == "-s":
        i += 1
        lspeed = float(sys.argv[i]) * 10**6 # from Mbps to bps
    elif sys.argv[i] == "-c":
        i += 1
        cinterval = float(sys.argv[i])
    i += 1

if inname == None:
    print("Missing input file \"-i\"")
    exit(0)
if outname == None:
    print("Missing output file \"-o\"")
    exit(0)
if maxtime == 0:
    print("time = 0")
    exit(0)
else:
    print("Max time\t\t= {} s".format(maxtime))
if lspeed == 0:
    print("Missing link speed (in Mbps)\"-s\"")
    exit(0)
else:
    print("Link speed\t\t= {} bps".format(lspeed))
if tactive == 0:
    print("Missing active threshold\"-a\"")
    exit(0)
else:
    print("Active threshold\t\t= {}".format(tactive))
if cinterval == 0:
    print("Missing checking interval (in s)\"-c\"")
    exit(0)
else:
    print("Checking interval\t= {} s".format(cinterval))

# reading file with packets information: addr,addr,length
fin = open(inname, "r")
pckts = []
print("Reading input from " + inname)
for line in fin:
    val = [int(x) for x in line.split(";")]
    # storing length in bits for speed
    # pckts.append(Entry(val[0], val[1], val[2] * 8))
    pckts.append([val[0], val[1], val[2] * 8])
pckts.reverse()

# estimation of arriving time
currTime = 0
pcktsTime = []
for i in range(len(pckts)):
    # currTime += pckts[i].len / lspeed
    currTime += pckts[i][2] / lspeed
    pcktsTime.append(currTime)
pcktsTime.reverse()

# starting estimation of active flows
activeFlows = {}
currTime    = 0
nextCheck   = 0
nextPTime   = pcktsTime.pop()
history     = [] # (time, number of active flows)
print("Estimating number of active flows", end=" ")
print("and writing active flows history in " + outname)
fout = open(outname, "w")
print("{} packets".format(len(pckts)))
while currTime < maxtime:
    # nextPTime = Inf
    # if len(pcktsTime) > 0:
    #     nextPTime = pcktsTime[-1]
    if nextPTime <= nextCheck:
        currTime  = nextPTime#pcktsTime.pop()
        if len(pcktsTime) > 0:
            nextPTime = pcktsTime.pop()
        else:
            nextPTime = Inf
        pckt = pckts.pop()
        activeFlows[(pckt[0], pckt[1])] = currTime
    else:
        currTime   = nextCheck
        # print("curr time = {}".format(currTime))
        nextCheck += cinterval
        toDel = []
        for addrPair, aTime in activeFlows.items():
            if (aTime + tactive) < currTime:
                toDel.append(addrPair)
        for addrPair in toDel:
            del activeFlows[addrPair]
        fout.write("{0:.9f}".format(currTime))
        fout.write(",")
        fout.write(str(len(activeFlows)))
        fout.write("\n")
        if len(pckts) == 0 and len(activeFlows) == 0:
            # nothing will chage from now on so it can stop
            break

# writing active flow history
fin.close()
fout.close()
print("Finished.")