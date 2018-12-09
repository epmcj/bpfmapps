#!/usr/bin/env python
# -*- coding: utf-8 -*-

import matplotlib
from matplotlib import pyplot as plt
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

def autolabel(ax, rects, vals, fsize):
    """
    Attach a text label above each bar displaying its height
    """
    for i in range(len(rects)):
        rect = rects[i]
        val  = vals[i]
#    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width()/2., 0.99*height,
                '%d' % int(val), fontsize=fsize,
                ha='center', va='bottom')

def plot_bar_chart(x, xlabels, data, xlabel, ylabel, title, fname="", fsize=30):    
    
    rects = plt.bar(x, data, align='center')
    
    plt.title(title)
    plt.ylabel(ylabel, fontsize=fsize)
    plt.xlabel(xlabel, fontsize=fsize)    
    
    ax = plt.gca()
    
    autolabel(ax, rects, data, fsize)
    plt.xticks(x, xlabels, rotation=70)
    
    for label in (ax.get_xticklabels() + ax.get_yticklabels()):
        label.set_fontsize(fsize)
    
    fig = plt.gcf()
    fig.set_size_inches(15, 12)
    
    plt.tight_layout()
    if fname is not "":
        plt.savefig(sys.argv[2], facecolor="w", transparent=True)
        

if len(sys.argv) < 3:
    print("[INPUT] [OUTPUT]")
    exit()
infile  = sys.argv[1]
outfile = sys.argv[2]
print("in  = " + infile)
print("out = " + outfile)

data = [[], []]

for line in open(infile):
    values = line.split(",")
    data[0].append(values[0])
    data[1].append(int(values[1])/1000)
    
ylabel = "Número de Pacotes (em milhares)"
xlabel = "Protocolo"
title  = ""

x = range(len(data[0]))

plot_bar_chart(x, data[0], data[1], xlabel, ylabel, title, outfile, 42)
print("done")


