#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage: ./add_tc_egress.sh <interface>"
    exit 0
fi

IFACE=$1
tc qdisc add dev $IFACE clsact

success=$(tc qdisc show dev $IFACE | grep clsact | wc -l)
if [ $success == 1 ]; then
	echo "clsact qdisc was successfully created"
else
	echo "clsact creation failed"
	exit 0
fi
	
tc filter add dev $IFACE egress bpf direct-action obj ../switch_tput/switch_tput.bpf.o section egress

