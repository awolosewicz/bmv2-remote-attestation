#!/usr/bin/python3

import csv
import argparse
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
import math

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--ra_file", type=str)
parser.add_argument("-b", "--base_file", type=str)

args = parser.parse_args()
filename = args.ra_file
filename2 = args.base_file

'''
    Calculate throughput as base10 log and plot it
'''
ra_experiment = []
base_experiment = []
with open(filename, 'r') as f:
    reader = csv.reader(f, delimiter=',')
    for row in reader:
        for elem in row:
            if elem != '':
                ra_experiment.append(math.log10(float(elem)))

with open(filename2, 'r') as f:
    reader = csv.reader(f, delimiter=',')
    for row in reader:
        for elem in row:
            if elem != '':
                base_experiment.append(math.log10(float(elem)))

print(ra_experiment)
print(base_experiment)

i = np.arange(1,9)
fig,ax = plt.subplots()
ax.plot(i, ra_experiment, label='BMv2-RA')
ax.plot(i, base_experiment, label='BMv2-base')
ax.set_ylim([0,4])
ax.set_xlabel('Test runs')
ax.set_ylabel('Througput(Mbps)')
ax.legend()

fig.savefig('plot_log.png')

