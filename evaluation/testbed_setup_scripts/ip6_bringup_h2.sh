#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: ./ip6_bringup_h2.sh [interface] [nexthop_mac]"
    exit 0
fi

IFACE=$1
NHOP_MAC=$2

echo "Bringing up interface"
sudo ifconfig $IFACE del fec0:db8:0:f001::100/64  
sudo ifconfig $IFACE add fec0:db8:0:f001::100/64 up

echo "Adding route"
sudo ip -6 route del fec0:db8:0:f000::/64
sudo ip -6 route add fec0:db8:0:f000::/64 dev $IFACE

echo "Adding neighbour details"
sudo ip -6 neigh del fec0:db8:0:f000::10 dev $IFACE
sudo ip -6 neigh add fec0:db8:0:f000::10 lladdr $NHOP_MAC dev $IFACE


