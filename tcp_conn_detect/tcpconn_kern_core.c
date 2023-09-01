// SPDX-License-Identifier: GPL-2.0
#define KBUILD_MODNAME "foo"

#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define COMM_SIZE 32
#define MAX_TCP_CONN_ENTRIES 256

struct tcpconn_data {
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
        __type(key, u32);
        __type(value, struct sock *);
        __uint(max_entries, 1000);
} currsock SEC(".maps");


SEC("kprobe/tcp_v4_connect")
/* int tcpconn_entry(struct pt_regs *ctx) { */
/* int kprobe__tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) { */
int tcpconn_entry(struct pt_regs *ctx) { 
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx); 
    struct sockaddr_in *usin = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    char fmt[] = "Called tcp_v4_connect: %x - %d\\n";
    char fmt1[] = "PID: %d - PID: %d \\n";
    u16 dport;
    u32 daddr;
    u32 pid1;
	u32 pid2;
    struct task_struct *task;

    bpf_probe_read_kernel(&dport, sizeof(u16), &(usin->sin_port));
    bpf_probe_read_kernel(&daddr, sizeof(u32), &(usin->sin_addr));
    bpf_trace_printk(fmt, sizeof(fmt), daddr, ntohs(dport), 0);

    task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 1;

    bpf_probe_read(&pid1, sizeof(int), (void *)&task->pid);
    pid2 = bpf_get_current_pid_tgid();
    bpf_trace_printk(fmt1, sizeof(fmt1), pid1, pid2, 0);
    
    bpf_map_update_elem(&currsock, &pid1, &sk, BPF_ANY);

    return 0;
};



SEC("kretprobe/tcp_v4_connect")
int tcpconn_return(struct pt_regs *ctx) { 
    long ret = PT_REGS_RC(ctx);
    char fmt[] = "Index: %d\n";
    char fmt1[] = "trace_tcp4connect %x %d\\n";
    char fmt2[] = "trace_tcp4connect -> %x %d\\n";
    char fmt3[] = "PID: %d - COMM: %s\\n";
//    char mycomm[COMM_SIZE] ;
    u8 *idxvalue;
    u8 idxvalue2;
    u32 idxvalue3;
    u32 index = 0;
    struct task_struct *task;
    struct tcpconn_data tcpconn = {0};
    struct tcpconn_data *tcnPtr = NULL;
    struct task_struct *real_parent;
    struct sock_common l_sk_common;
	struct sock **skpp;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 1;

    bpf_core_read(&tcpconn.pid, sizeof(int), (void *)&task->pid);
    bpf_core_read(&real_parent, sizeof(struct task_struct *), (void *)&task->real_parent);
    bpf_core_read(&tcpconn.ppid, sizeof(tcpconn.ppid), (void *)&real_parent->pid);
    tcpconn.uid  = bpf_get_current_uid_gid();

	skpp = bpf_map_lookup_elem(&currsock, &tcpconn.pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}
	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		bpf_map_delete_elem(&currsock, &tcpconn.pid);
		return 0;
	}
	// pull in details
	struct sock *skp = *skpp;
	
	bpf_probe_read(&tcpconn.saddr, sizeof(u32), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&tcpconn.daddr, sizeof(u32), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&tcpconn.dport, sizeof(u16), &skp->__sk_common.skc_dport);
	bpf_probe_read(&tcpconn.lport, sizeof(u16), &skp->__sk_common.skc_num);
	// output
	bpf_trace_printk(fmt1, sizeof(fmt1), tcpconn.saddr, tcpconn.lport);
	bpf_trace_printk(fmt2, sizeof(fmt2), tcpconn.daddr, ntohs(tcpconn.dport));
	
    bpf_map_delete_elem(&currsock, &tcpconn.pid);
    
    ret = bpf_get_current_comm(tcpconn.comm, COMM_SIZE);
    if (ret < 0) return 1;

	bpf_trace_printk(fmt3, sizeof(fmt3), tcpconn.pid, tcpconn.comm);
 
    idxvalue = bpf_map_lookup_elem(&my_map_index, &index);
    if (idxvalue) {
        idxvalue2 = (*idxvalue);
        idxvalue2++;
        idxvalue3 = idxvalue2;
        bpf_trace_printk(fmt, sizeof(fmt), idxvalue3, 0, 0);
        bpf_map_update_elem(&tcpconn_map, &idxvalue3, &tcpconn, BPF_ANY);
        bpf_map_update_elem(&my_map_index, &index, &idxvalue2, BPF_EXIST);
        bpf_trace_printk(fmt, sizeof(fmt), idxvalue2, 0, 0);
        tcnPtr = bpf_map_lookup_elem(&tcpconn_map, &idxvalue3);
        if (tcnPtr) {
            bpf_trace_printk(fmt1, sizeof(fmt1), tcnPtr->saddr, tcnPtr->lport);
            bpf_trace_printk(fmt2, sizeof(fmt2), tcnPtr->daddr, ntohs(tcnPtr->dport));
	        bpf_trace_printk(fmt3, sizeof(fmt3), tcnPtr->pid, tcnPtr->comm);
        }
    }
    
    return 0;
};




char _license[] SEC("license") = "GPL";
