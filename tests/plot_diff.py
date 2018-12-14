#!/usr/bin/env python
# -*- coding: utf-8 -*-

import matplotlib
from matplotlib import pyplot as plt
import sys
# reload(sys)
# sys.setdefaultencoding('utf-8')

fsize = 36

if len(sys.argv) < 5:
    print("[input_ref] [input] [time] [output]")
    exit()

fref = open(sys.argv[1])
fin  = open(sys.argv[2])
time = float(sys.argv[3])
fout = sys.argv[4]

ref = [[], []]
# just for alignment
# ref[0].append(0.50)
# ref[1].append(0)
# ref[0].append(1.00)
# ref[1].append(0)
# ref[0].append(1.50)
# ref[1].append(0)
# ref[0].append(2.00)
# ref[1].append(0)
# ref[0].append(2.50)
# ref[1].append(0)
# ref[0].append(3.00)
# ref[1].append(0)

for line in fref:
    values = line.split(",")
#     ref[0].append(float(values[0]) + 3.5)
    ref[0].append(float(values[0]))
    ref[1].append(float(values[1]))
    if ref[0][-1] >= time:
        break

data = [[], []]
for line in fin:
    values = line.split(",")
    data[0].append(float(values[0]))
    data[1].append(float(values[1]))
    if data[0][-1] >= time:
        break

# just to finish in zero
# diff = data[0][1] - data[0][0]
# data[0].append(data[0][-1] + diff)
# data[1].append(0)

for i in range(len(ref[0])):
    if ref[0][i] > data[0][i]:
        print("not always greater")
        break

ref[0]  = [x/60 for x in ref[0]]
data[0] = [x/60 for x in data[0]]

diffv = []
for i in range(len(ref[1])):
    if ref[1][i] == 0:
        diffv.append(0)
    else:
        diffv.append(100*(data[1][i] - ref[1][i])/ref[1][i])

print("min: {} med: {} max: {}".format(min(diffv), sum(diffv)/len(diffv), max(diffv)))
# plt.plot(data[0], diffv, linestyle="-", label="Medido", color="k")
# axes = plt.gca()
# # plt.ylim(bottom=-10, top=10)
# for label in (axes.get_xticklabels() + axes.get_yticklabels()):
#     label.set_fontsize(fsize)

# plt.ylabel("Erro (%)", fontsize=fsize)
# plt.xlabel("Tempo (min)", fontsize=fsize)

# fig = plt.gcf()
# fig.set_size_inches(15, 8)

# plt.tight_layout()
# plt.savefig(fout, facecolor="w", transparent=True)
# plt.close()
