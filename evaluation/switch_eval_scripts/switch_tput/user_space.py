#!/usr/bin/python3

from bcc import BPF
import ctypes as ct
import math as m
import argparse
import csv

filename = "base.txt"
switch = "base"

parser = argparse.ArgumentParser()
parser.add_argument("-o", "--output_file", type=str)
parser.add_argument("-s", "--switch", type=str)
args = parser.parse_args()
filename = args.output_file
switch = args.switch


'''
    Open a BPF pinned map
'''
b = BPF(text = r'BPF_TABLE_PINNED("ringbuf", u64, u64, ringbuf_in, 4096, "/sys/fs/bpf/tc/globals/ringbuf_eg");');

class Data(ct.Structure):
    _fields_ = [("total_time", ct.c_ulonglong),
                ("tot_bytes", ct.c_ulonglong)]

counter = 0
tput_sum = 0
tot_bytes = []
time_ns = []
tput_list = []


'''
    Callback function for ringbuf event
'''
def print_event(cpu, data, size):
    #data = b["ringbuf_in"].event(data)
    global counter
    event = ct.cast(data, ct.POINTER(Data)).contents
    time_ns.append(event.total_time)
    tot_bytes.append(event.tot_bytes)
    counter = counter + 1

b["ringbuf_in"].open_ring_buffer(print_event)
'''
    Poll for event
'''
while counter < 6:
    b.ring_buffer_poll()

'''
    Append throughput in Mbps to a list
'''
for i in range(0, len(time_ns)):
   tput = (tot_bytes[i] * 8 * 1000 * 1000 * 1000) / time_ns[i]
   tput /= (1024 *  1024)
   tput_list.append(tput)

for tput in tput_list:
    print(f"tput : {tput}")
    tput_sum = tput_sum + tput

''' 
    Sequence of steps to calculate standard deviation
'''
tput_avg = tput_sum / len(tput_list)
print(f'tput_avg: {tput_avg}')

variance = []

for tput in tput_list:
    variance.append(tput-tput_avg)

sq_variance = []

for var in variance:
    sq_variance.append(var * var)

sum_sq = 0
for elem in sq_variance:
    sum_sq = sum_sq + elem
print(f'sum_sq = {sum_sq}')

std_deviation = m.sqrt(sum_sq/(len(sq_variance) - 1)) 
print(std_deviation)

'''
    Remove elements which are 2 deviations away from the mean
'''
real_tput = 0
real_count = 0
for tput in tput_list:
    if tput < tput_avg:
        if tput_avg - (2 * std_deviation) > tput:
            continue
    else:
        if tput_avg + (2 * std_deviation) < tput:
            continue
    real_tput = real_tput + tput
    real_count = real_count + 1

'''
    Calculate new average
'''
if args.switch == "base":
    avg_tput = real_tput/real_count
elif args.switch == "ra":
    avg_tput = real_tput * (1466 - 104)/(real_count * 1466)

print(f'avg_tput at switch: ', avg_tput)    

'''
    Write tput to provided file
'''
with open(filename, 'a') as f:   #with takes care of file closing
    f.write(f'{avg_tput},')
