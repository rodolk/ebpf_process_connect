// SPDX-License-Identifier: GPL-2.0
#define KBUILD_MODNAME "foo"

#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define COMM_SIZE 32
#define MAX_TCP_CONN_ENTRIES 256

struct tcpconn_data {
    s32 tgid;
    s32 pid;
    s32 ppid;
    u32 uid;
    u16 lport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    char comm[COMM_SIZE];
};
/*    char comm[COMM_SIZE + 1]; */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct tcpconn_data);
	__uint(max_entries, MAX_TCP_CONN_ENTRIES);
} tcpconn_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, 1);
} my_map_index SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, s32);
        __type(value, struct sock *);
        __uint(max_entries, 1000);
} currsock SEC(".maps");


SEC("kprobe/tcp_v4_connect")
int tcpconn_entry(struct pt_regs *ctx) { 
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx); 
    s32 pid;

    pid = bpf_get_current_pid_tgid();
    
    bpf_map_update_elem(&currsock, &pid, &sk, BPF_ANY);

    return 0;
};



SEC("kretprobe/tcp_v4_connect")
int tcpconn_return(struct pt_regs *ctx) { 
    long ret = PT_REGS_RC(ctx);
    u8 *idxvaluePtr;
    u8 idxvalue;
    u32 idxvalue32;
    u32 index = 0;
    struct task_struct *task;
    struct tcpconn_data tcpconn = {0};
    struct task_struct *real_parent;
	struct sock **skpp;
    //char strfmt1[] = "TRACE-1 tcp_v4_connect, TGID: %d, PID: %d\n";
    //char strfmt2[] = "TRACE-2 tcp_v4_connect, TGID: %d, PPID: %d\n";
    //char strfmt3[] = "TRACE-3 tcp_v4_connect, COMM: %s\n";

    task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 1;

    tcpconn.pid = bpf_get_current_pid_tgid();

    skpp = bpf_map_lookup_elem(&currsock, &tcpconn.pid);
	if (skpp == 0) {
		return 0; //sock not found
	}
	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		bpf_map_delete_elem(&currsock, &tcpconn.pid);
		return 0;
	}

    tcpconn.tgid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read(&real_parent, sizeof(struct task_struct *), (void *)&task->real_parent);
    //In ubuntu real_parent->pid is 0
    bpf_probe_read(&tcpconn.ppid, sizeof(tcpconn.ppid), (void *)&real_parent->pid);

    tcpconn.uid  = bpf_get_current_uid_gid();

	struct sock *skp = *skpp;
	
	bpf_probe_read(&tcpconn.saddr, sizeof(u32), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&tcpconn.daddr, sizeof(u32), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&tcpconn.dport, sizeof(u16), &skp->__sk_common.skc_dport);
	bpf_probe_read(&tcpconn.lport, sizeof(u16), &skp->__sk_common.skc_num);
	
    bpf_map_delete_elem(&currsock, &tcpconn.pid);
    
    ret = bpf_get_current_comm(tcpconn.comm, COMM_SIZE);
    if (ret < 0) return 1;

    //bpf_trace_printk(strfmt1, sizeof(strfmt1), tcpconn.tgid, tcpconn.pid);
    //bpf_trace_printk(strfmt2, sizeof(strfmt2), tcpconn.tgid, tcpconn.ppid);
    //bpf_trace_printk(strfmt3, sizeof(strfmt3), tcpconn.comm);

    idxvaluePtr = bpf_map_lookup_elem(&my_map_index, &index);
    if (idxvaluePtr) {
        idxvalue = (*idxvaluePtr);
        idxvalue++;
        idxvalue32 = idxvalue;
        bpf_map_update_elem(&tcpconn_map, &idxvalue32, &tcpconn, BPF_ANY);
        bpf_map_update_elem(&my_map_index, &index, &idxvalue, BPF_EXIST);
    }
    
    return 0;
};




char _license[] SEC("license") = "GPL";
