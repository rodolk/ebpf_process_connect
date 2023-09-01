
FOCAL_DIR = /usr/src/focal
COMMON_DIR = ../common

CLANG_INCLUDE = -I$(FOCAL_DIR)/arch/x86/include -I$(FOCAL_DIR)/arch/x86/include/generated -I$(FOCAL_DIR)/include \
-I$(FOCAL_DIR)/arch/x86/include/uapi -I$(FOCAL_DIR)/arch/x86/include/generated/uapi -I$(FOCAL_DIR)/include/uapi \
-I$(FOCAL_DIR)/include/generated/uapi -include $(FOCAL_DIR)/include/linux/kconfig.h -I$(FOCAL_DIR)/ubuntu/include \
-I$(FOCAL_DIR)/tools/testing/selftests/bpf -I$(FOCAL_DIR)/tools/lib -include $(COMMON_DIR)/asm_goto_workaround.h

GCC_INCLUDE = -I$(FOCAL_DIR)/usr/include -I$(FOCAL_DIR)/tools/testing/selftests/bpf/ -I$(FOCAL_DIR)/tools/lib/ \
-I$(FOCAL_DIR)/tools/include -I$(FOCAL_DIR)/tools/perf 

.PHONY: all clean

all: tcpconn processConnEBPF_kern.o



processConnEBPF_kern.o:
	clang -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include $(CLANG_INCLUDE) -fno-stack-protector \
	-g  -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
	-D__TARGET_ARCH_x86 -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member \
	-Wno-tautological-compare -Wno-unknown-warning-option -O2 -emit-llvm -Xclang -disable-llvm-passes \
	-c tcpconn_kern.c -o - | opt -O2 -mtriple=bpf-pc-linux | llvm-dis | llc -march=bpf  -filetype=obj -o processConnEBPF_kern.o

tcpconn:
	gcc -Wp,-MD,.tcpconn_user.o.d -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes $(GCC_INCLUDE) -DHAVE_ATTR_TEST=0  -c -o tcpconn_user.o tcpconn_user.c
	gcc -Wp,-MD,.tcpconn.d -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -DHAVE_ATTR_TEST=0   -o tcpconn tcpconn_user.o $(FOCAL_DIR)/tools/lib/bpf/libbpf.a -lelf -lz


clean:
	rm -f *.o
	rm -f tcpconn

#	gcc -Wp,-MD,.tcpconn.d -Wall -O2 -Wmissing-prototypes -Wstrict-prototypes -I$(FOCAL_DIR)/usr/include -I$(FOCAL_DIR)/tools/testing/selftests/bpf/ -I$(FOCAL_DIR)/tools/lib/ -I$(FOCAL_DIR)/tools/include -I$(FOCAL_DIR)/tools/perf -DHAVE_ATTR_TEST=0   -o tcpconn tcpconn_user.o $(FOCAL_DIR)/tools/lib/bpf/libbpf.a -lelf -lz
