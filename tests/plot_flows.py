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
ref[0].append(0.50)
ref[1].append(0)
ref[0].append(1.00)
ref[1].append(0)
ref[0].append(1.50)
ref[1].append(0)
ref[0].append(2.00)
ref[1].append(0)
ref[0].append(2.50)
ref[1].append(0)
ref[0].append(3.00)
ref[1].append(0)

for line in fref:
    values = line.split(",")
    ref[0].append(float(values[0]) + 3.5)
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

ref[0]  = [x/60 for x in ref[0]]
data[0] = [x/60 for x in data[0]]

plt.plot(ref[0], ref[1], linestyle=":", label="Estimativa", color="r")
plt.plot(data[0], data[1], linestyle="-", label="Medido", color="b")
plt.legend(["Estimado", "Medido"], ncol=2, fontsize=fsize)
axes = plt.gca()
plt.ylim(top=700)
for label in (axes.get_xticklabels() + axes.get_yticklabels()):
    label.set_fontsize(fsize)

# plt.ylabel("Number of Active Flows")
# plt.xlabel("Time (s)")

plt.ylabel("Número de Fluxos Ativos", fontsize=fsize)
plt.xlabel("Tempo (min)", fontsize=fsize)

fig = plt.gcf()
fig.set_size_inches(15, 8)

plt.tight_layout()
plt.savefig(fout, facecolor="w", transparent=True)
plt.close()
