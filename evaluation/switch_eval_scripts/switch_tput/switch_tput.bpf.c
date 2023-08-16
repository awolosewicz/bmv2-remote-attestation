//#include "vmlinux.h"
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <iproute2/bpf_elf.h>

struct ingress_t {
	__u64 initial_time;
	__u64 counter ;
}ingress;

struct egress_t {
	__u64 initial_time ;
	__u64 counter ;
}egress;

struct ingress_map {
	__u64 total_time;
	__u64 tot_bytes;
}imap;

struct egress_map {
	__u64 total_time;
	__u64 tot_bytes;
}emap;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 * 4096);
	__uint(pinning, PIN_OBJECT_NS);
}ringbuf_eg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 * 4096);
	__uint(pinning, PIN_OBJECT_NS);
}ringbuf_in SEC(".maps");




SEC("cls_ingress")
int icmp_ingress_dropper(struct __sk_buff *skb)
{
	char *data = (char *)skb->data;
	char *data_end = (char *)skb->data_end;
	__u64 time_ns = 0;
	int proto;
	struct ethhdr *eth = (struct ethhdr *)data;
	if(data + sizeof(struct ethhdr) > data_end)
		return -1;
	proto = bpf_ntohs(eth->h_proto);
	if (proto != ETH_P_IPV6)
		return TC_ACT_OK;

	if (proto == ETH_P_IP) {	
		struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
			return -1;
	} else {
		//ipv6 case
		struct ipv6hdr *ip6 = (struct ipv6hdr *)(data + sizeof(struct ethhdr));
		if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
			return -1;
	}
	char imsg[] = "Time for %d packets is %lu\n";
	char tput_msg[] = "Ingress Tput is %llu bps\n";
	time_ns = bpf_ktime_get_ns();
	ingress.counter++;
	imap.tot_bytes += skb->len;

	if (ingress.counter == 1) {
		ingress.initial_time = time_ns;
	}
	if (ingress.counter == 10000) {
		imap.total_time = time_ns - ingress.initial_time;
		//bpf_trace_printk(imsg, sizeof(imsg), counter, imap.total_time);
		//__u64 tput = (imap.tot_bytes * 8 * 1000 * 1000) / (imap.total_time / 1000);
		//bpf_trace_printk(tput_msg, sizeof(tput_msg), tput);
		bpf_ringbuf_output(&ringbuf_in, &imap, sizeof(imap), 0);
		imap.tot_bytes = 0;
		ingress.counter = 0;
	}

	return TC_ACT_OK;
}

SEC("cls_egress")
int icmp_egress_dropper(struct __sk_buff *skb)
{
	char *data = (char *)skb->data;
	char *data_end = (char *)skb->data_end;
	__u64 time_ns = 0;
	int proto;
	struct ethhdr *eth = (struct ethhdr *)data;
	if(data + sizeof(struct ethhdr) > data_end)
		return -1;
	proto = bpf_ntohs(eth->h_proto);
	if (proto != ETH_P_IPV6)
		return TC_ACT_OK;
	if (proto == ETH_P_IP) {	
		struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
			return -1;
	} else {
		//ipv6 case
		struct ipv6hdr *ip6 = (struct ipv6hdr *)(data + sizeof(struct ethhdr));
		if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
			return -1;
	}

	char imsg[] = "Time for %d packets is %lu\n";
	char tput_msg[] = "Egress Tput is %llu bps\n";
	time_ns = bpf_ktime_get_ns();
	egress.counter++;
	emap.tot_bytes += skb->len;

	if (egress.counter == 1) {
		egress.initial_time = time_ns;
	}
	if (egress.counter == 10000) {
		emap.total_time = time_ns - egress.initial_time;
		//bpf_trace_printk(imsg, sizeof(imsg), counter, emap.total_time);
		//__u64 tput = (emap.tot_bytes * 8 * 1000 * 1000) / (emap.total_time / 1000);
		//bpf_trace_printk(tput_msg, sizeof(tput_msg), tput);
		bpf_ringbuf_output(&ringbuf_eg, &emap, sizeof(emap), 0);
		emap.tot_bytes = 0;
		egress.counter = 0;
	}

	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
