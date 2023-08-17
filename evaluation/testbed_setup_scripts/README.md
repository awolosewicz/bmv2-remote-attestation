ip6\_bringup\_h1.sh is executed on host 1. The egress interface and next hop MAC address are passed in as arguments. The script sets up the interface IPv6 address, routing table entry and neighbour table entries on host1.

ip6\_bringup\_h2.sh is executed on host 2. The egress interface and next hop MAC address are passed in as arguments. The script sets up the interface IPv6 address, routing table entry and neighbour table entries on host2.

After executing the scripts, on host2 run:
$ sudo iperf3 -s

On host1 run:
$ sudo iperf3 -V -c fec0:db8:0:f001::100 -u -l 1300 -b 100M   # Send UDP packets of 1300byte payload at rate of 100Mbps. 
