// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <signal.h>
#include <arpa/inet.h>

#define COMM_SIZE 32
#define MAX_TCP_CONN_ENTRIES 256
#define K_OBJECT_NAME "processConnEBPF_kern.o"

struct tcpconn_data {
    int32_t tgid;
    int32_t pid;
    int32_t ppid;
    uint32_t uid;
    uint16_t lport;
    uint16_t dport;
    uint32_t saddr;
    uint32_t daddr;
    char comm[COMM_SIZE];
};


struct bpf_object *obj;

static void int_exit(int sig) {
    printf("CTRL-C Signal received\n");
    bpf_object__close(obj);
    exit(0);
}

int main(int ac, char **argv)
{
    struct bpf_program *prog1;
    struct bpf_program *prog2;
    struct bpf_link *link1;
    struct bpf_link *link2;
    char *filename = K_OBJECT_NAME;
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    int map_fd1;
    int map_fd2;
    struct tcpconn_data tcpconn;
    uint32_t keyindex = 0;
    uint8_t idxvalue = 0;
    uint8_t prev_idxvalue = 0;
    uint32_t prev_idxvalue2 = 0;
    uint32_t counter = 0;

    setrlimit(RLIMIT_MEMLOCK, &lim);
    
    obj = bpf_object__open(filename);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 0;
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    prog1 = bpf_object__find_program_by_title(obj, "kprobe/tcp_v4_connect");     
    if (!prog1) {
        printf("ERROR: finding a prog1 in obj file failed\n");
        goto err;
    }
    bpf_program__set_type(prog1, BPF_PROG_TYPE_KPROBE);
    
    prog2 = bpf_object__find_program_by_title(obj, "kretprobe/tcp_v4_connect");     
    if (!prog2) {
        printf("ERROR: finding a prog2 in obj file failed\n");
        goto err;
    }
    bpf_program__set_type(prog2, BPF_PROG_TYPE_KPROBE);
    
    /* load BPF program */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto err;
    }

    link1 = bpf_program__attach_kprobe(prog1, false, "tcp_v4_connect");
    if (libbpf_get_error(link1)) {
        fprintf(stderr, "ERROR: attaching BPF program to kprobe/tcp_v4_connect\n");
        goto err;
    }

    link2 = bpf_program__attach_kprobe(prog2, true, "tcp_v4_connect");
    if (libbpf_get_error(link2)) {
        fprintf(stderr, "ERROR: attaching BPF program, link2, to kretprobe/tcp_v4_connect\n");
        goto err1;
    }

	map_fd1 = bpf_object__find_map_fd_by_name(obj, "my_map_index");
    if (map_fd1 < 0) {
        printf("Error-1, get map fd from bpf obj failed\n");
        goto err2;
    }

	map_fd2 = bpf_object__find_map_fd_by_name(obj, "tcpconn_map");
    if (map_fd2 < 0) {
        printf("Error-2, get map fd from bpf obj failed\n");
        goto err2;
    }

   
    while(counter++ < 300) {
        assert(bpf_map_lookup_elem(map_fd1, &keyindex, &idxvalue) == 0);
        printf("READ IDXVALUE: %u\n", idxvalue);
        printf("PREVIOUS IDXVALUE: %u\n", prev_idxvalue);
        if (idxvalue != prev_idxvalue) {
            prev_idxvalue++;
            prev_idxvalue2 = prev_idxvalue;
            assert(bpf_map_lookup_elem(map_fd2, &prev_idxvalue2, &tcpconn) == 0);
            printf("NEW CONNECTION:\n");
            printf("TGID: %d, PID: %d, COMM: %s, PPID: %d, UID: %u\n", tcpconn.tgid, tcpconn.pid, tcpconn.comm, tcpconn.ppid, tcpconn.uid);
            uint8_t *ipfrom = (uint8_t *)&tcpconn.saddr;
            uint8_t *ipto = (uint8_t *)&tcpconn.daddr;
            printf("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n", ipfrom[3], ipfrom[2], ipfrom[1], ipfrom[0], tcpconn.lport, ipto[3], ipto[2], ipto[1], ipto[0], ntohs(tcpconn.dport));
        }
        sleep(1);
    }
    
    printf("FINISHING\n");

    
    bpf_link__destroy(link2);
    bpf_link__destroy(link1);
    bpf_object__close(obj);
    return 0;

err2:
    bpf_link__destroy(link2);
err1:
    bpf_link__destroy(link1);
err:
    bpf_object__close(obj);
    return 1;
}





