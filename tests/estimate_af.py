import sys
import random

Inf = float("inf")

class Entry:
    def __init__(self, addr1, addr2, plen):
        self.addr1 = addr1
        self.addr2 = addr2
        self.len   = plen

inname    = None    # input file name
refname   = None    # reference file name
outname   = None    # output file name
maxtime   = 0       # max estimation time (in seconds)
tactive   = Inf     # threshold for active flows (in seconds)

i = 1
while i < len(sys.argv):
    if sys.argv[i] == "-i":
        i += 1
        inname = sys.argv[i]
    if sys.argv[i] == "-r":
        i += 1
        refname = sys.argv[i]
    elif sys.argv[i] == "-o":
        i += 1
        outname = sys.argv[i]
    elif sys.argv[i] == "-t":
        i += 1
        duration = float(sys.argv[i])# * (10**6) # from s to us
    elif sys.argv[i] == "-a":
        i += 1
        tactive = float(sys.argv[i])# * (10**6) # from s to us
    i += 1

if inname == None:
    print("Missing input file \"-i\"")
    exit(0)
if refname == None:
    print("Missing reference file \"-r\"")
    exit(0)
if outname == None:
    print("Missing output file \"-o\"")
    exit(0)
if duration == 0:
    print("time = 0")
    exit(0)
else:
    print("Duration\t\t= {} us".format(duration))
if tactive == 0:
    print("Missing active threshold\"-a\"")
    exit(0)
else:
    print("Active threshold\t= {}".format(tactive))

# reading file with packets information: addr,addr,length,timeOfArrival
fin = open(inname, "r")
pckts  = []
print("Reading input from " + inname)
for line in fin:
    val = [float(x) for x in line.split(";")]
    # storing length in bits for speed
    # pckts.append(Entry(val[0], val[1], val[2] * 8))
    pckts.append([val[0], val[1], val[2] * 8, val[3]])
pckts.reverse()

# reading file for check reference: checkTime,numActiveFlows,appTime
fref = open(refname, "r")
cTimes = []
checks = []
print("Reading reference from " + refname)
for line in fref:
    val = [float(x) for x in line.split(",")]
    cTimes.append(val[0])
    checks.append(val[2])
cTimes.reverse()
checks.reverse()

# estimation of arriving time
# currTime = 0
# pcktsTime = []
# for i in range(len(pckts)):
    # currTime += pckts[i][2] / lspeed
    # pcktsTime.append(currTime)
# pcktsTime.reverse()
# starting estimation of active flows
activeFlows = {}
nextCheck   = checks.pop()
initTime    = min(pckts[-1][3], nextCheck)
print(initTime)
currTime    = initTime
maxtime     = currTime + duration
# nextPTime   = pcktsTime.pop()
nextPTime   = pckts[-1][3]
print("Estimating number of active flows", end=" ")
print("and writing active flows history in " + outname)
fout = open(outname, "w")
print("{} packets".format(len(pckts)))
while currTime < maxtime and nextCheck != Inf:
    # nextPTime = Inf
    # if len(pcktsTime) > 0:
    #     nextPTime = pcktsTime[-1]
    if nextPTime <= nextCheck:
        currTime  = nextPTime # pcktsTime.pop()
        pckt = pckts.pop()
        activeFlows[(pckt[0], pckt[1])] = currTime
        if len(pckts) > 0:
            nextPTime = pckts[-1][3] # pcktsTime.pop()
        else:
            nextPTime = Inf
    else:
        currTime = nextCheck
        # print("curr time = {}".format(currTime))
        if len(checks) != 0:
            nextCheck = checks.pop()
        else:
            nextCheck = Inf
        toDel = []
        for addrPair, aTime in activeFlows.items():
            if (aTime + tactive) < currTime:
                toDel.append(addrPair)
        for addrPair in toDel:
            del activeFlows[addrPair]
        # fout.write("{0:.9f}".format((currTime - initTime)/(10**6)))
        fout.write("{0:.9f}".format(cTimes.pop()))
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