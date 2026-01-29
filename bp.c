/* Copyright 2026 edcsnt. All rights reserved. */
/* ssltrace-ebpf - eBPF uprobe tracer with unlimited data capture (C89) */
/*
 * Classic BPF constants from <linux/bpf_common.h> (C89 compliant, no deps).
 * eBPF extensions and structures defined locally to avoid <linux/bpf.h>
 * which includes <linux/types.h> -> <asm/swab.h> with inline assembly.
 */
#define _POSIX_C_SOURCE 199309L
#include <linux/bpf_common.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

long syscall(long n, ...);

/*
 * eBPF extensions - linux/bpf.h (not in bpf_common.h)
 */
#define BPF_ALU64 0x07U
#define BPF_DW    0x18U
#define BPF_MOV   0xb0U
#define BPF_JLT   0xa0U
#define BPF_JLE   0xb0U
#define BPF_CALL  0x80U
#define BPF_EXIT  0x90U

/* BPF src_reg value for LD_IMM64 to indicate map fd */
#define BPF_PSEUDO_MAP_FD 1U

/*
 * BPF commands - linux/bpf.h
 */
#define BPF_MAP_CREATE       0
#define BPF_MAP_UPDATE_ELEM  2
#define BPF_PROG_LOAD        5

/*
 * BPF map types - linux/bpf.h
 */
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4U
#define BPF_MAP_TYPE_PERCPU_ARRAY     6U

/*
 * BPF program types - linux/bpf.h
 */
#define BPF_PROG_TYPE_KPROBE 2U

/*
 * BPF helper function IDs - linux/bpf.h
 */
#define BPF_FUNC_map_lookup_elem     1
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_perf_event_output   25
#define BPF_FUNC_probe_read_user     112

/*
 * BPF instruction structure - linux/bpf.h
 * Uses unsigned int for bitfields (C89 compliant).
 * dst_reg is lower 4 bits, src_reg is upper 4 bits on little-endian.
 */
struct bpf_insn {
	unsigned char code;
	unsigned int dst_reg:4;
	unsigned int src_reg:4;
	short off;
	int imm;
};

/*
 * BPF syscall attribute union - linux/bpf.h
 * Only fields we use are defined; padded to correct offsets.
 */
union bpf_attr {
	/* BPF_MAP_CREATE */
	struct bpf_attr_map {
		unsigned int map_type;
		unsigned int key_size;
		unsigned int value_size;
		unsigned int max_entries;
	} map;
	/* BPF_PROG_LOAD */
	struct bpf_attr_prog {
		unsigned int prog_type;
		unsigned int insn_cnt;
		unsigned long insns;
		unsigned long license;
		unsigned int log_level;
		unsigned int log_size;
		unsigned long log_buf;
	} prog;
	/* BPF_MAP_UPDATE_ELEM */
	struct bpf_attr_map_update {
		unsigned int map_fd;
		unsigned long key;
		unsigned long value;
	} map_update;
};

/*
 * Perf event constants - linux/perf_event.h
 */
#define PERF_TYPE_SOFTWARE       1U
#define PERF_COUNT_SW_BPF_OUTPUT 10UL
#define PERF_SAMPLE_RAW          (1U << 10)
#define PERF_RECORD_SAMPLE       9U
#define PERF_FLAG_FD_CLOEXEC     (1UL << 3)

/* Perf ioctl commands - computed from _IO/_IOW macros */
#define PERF_EVENT_IOC_ENABLE   0x2400U
#define PERF_EVENT_IOC_SET_BPF  0x40042408U

/*
 * Perf event attribute structure - linux/perf_event.h
 */
struct perf_event_attr {
	unsigned int type;
	unsigned int size;
	unsigned long config;
	unsigned long sample_period;
	unsigned long sample_type;
	unsigned long read_format;
	unsigned long flags;
	unsigned int wakeup_events;
	unsigned int bp_type;
	unsigned long config1;
	unsigned long config2;
	unsigned long branch_sample_type;
	unsigned long sample_regs_user;
	unsigned int sample_stack_user;
	int clockid;
	unsigned long sample_regs_intr;
	unsigned int aux_watermark;
	unsigned short sample_max_stack;
	unsigned short reserved_2;
	unsigned int aux_sample_size;
	unsigned int reserved_3;
	unsigned long sig_data;
	unsigned long config3;
};

/*
 * Perf mmap page header - linux/perf_event.h
 * Simplified: only fields we need, with padding to correct offsets.
 * data_head is at offset 0x68 (104 bytes) from start.
 */
struct perf_event_mmap_page {
	unsigned char reserved1[104U];
	unsigned long data_head;
	unsigned long data_tail;
};

/*
 * Perf event header - linux/perf_event.h
 */
struct perf_event_header {
	unsigned int type;
	unsigned short misc;
	unsigned short size;
};

/*
 * Application constants
 */
#define MAX_CPUS 1024U

/* linux/bpf.h:2149 - maximum iterations for bounded loops (not exported) */
#define BPF_MAX_LOOPS (8U * 1024U * 1024U)

/* linux/percpu.h:24 - PCPU_MIN_UNIT_SIZE, max per-CPU map value */
#define CHUNK_SIZE 32768U

/*
 * BPF instruction macros - C89 compatible (kernel uses C99 designated init)
 */
#define I(c,d,s,o,i) {(c),(d),(s),(o),(i)}
#define ALU_I(op,d,i)  I(BPF_ALU64|(op)|BPF_K, (d), 0, 0, (i))
#define ALU_R(op,d,s)  I(BPF_ALU64|(op)|BPF_X, (d), (s), 0, 0)
#define MOV_R(d,s)     I(BPF_ALU64|BPF_MOV|BPF_X, (d), (s), 0, 0)
#define MOV_I(d,i)     I(BPF_ALU64|BPF_MOV|BPF_K, (d), 0, 0, (i))
#define LDX(sz,d,s,o)  I(BPF_LDX|(sz)|BPF_MEM, (d), (s), (o), 0)
#define STX(sz,d,s,o)  I(BPF_STX|(sz)|BPF_MEM, (d), (s), (o), 0)
#define ST(sz,d,o,i)   I(BPF_ST|(sz)|BPF_MEM, (d), 0, (o), (i))
#define JMP(op,d,i,o)  I(BPF_JMP|(op)|BPF_K, (d), 0, (o), (i))
#define CALL(id)       I(BPF_JMP|BPF_CALL, 0, 0, 0, (id))
#define EXIT           I(BPF_JMP|BPF_EXIT, 0, 0, 0, 0)
#define LD_IMM64(d,s,i) I(BPF_LD|BPF_DW|BPF_IMM, (d), (s), 0, (i)), I(0, 0, 0, 0, 0)
#define LD_MAP(d,fd)   LD_IMM64((d), BPF_PSEUDO_MAP_FD, (fd))

/*
 * Architecture-specific pt_regs offsets for function arguments.
 * arg2 = 2nd parameter (buffer pointer), arg3 = 3rd parameter (length).
 * Offsets derived from arch/{ARCH}/include/asm/ptrace.h in Linux kernel.
 */
#if defined(__x86_64__)
#define PT_ARG2_OFF 104
#define PT_ARG3_OFF 96
#define PT_ARG_SIZE BPF_DW
#elif defined(__aarch64__)
#define PT_ARG2_OFF 8
#define PT_ARG3_OFF 16
#define PT_ARG_SIZE BPF_DW
#elif defined(__riscv) && __riscv_xlen == 64
#define PT_ARG2_OFF 88
#define PT_ARG3_OFF 96
#define PT_ARG_SIZE BPF_DW
#elif defined(__mips__) && _MIPS_SIM == _ABI64
#define PT_ARG2_OFF 40
#define PT_ARG3_OFF 48
#define PT_ARG_SIZE BPF_DW
#elif defined(__powerpc64__)
#define PT_ARG2_OFF 32
#define PT_ARG3_OFF 40
#define PT_ARG_SIZE BPF_DW
#elif defined(__s390x__)
#define PT_ARG2_OFF 48
#define PT_ARG3_OFF 56
#define PT_ARG_SIZE BPF_DW
#elif defined(__arm__)
#define PT_ARG2_OFF 4
#define PT_ARG3_OFF 8
#define PT_ARG_SIZE BPF_W
#elif defined(__i386__)
#define PT_ARG2_OFF 4
#define PT_ARG3_OFF 8
#define PT_ARG_SIZE BPF_W
#elif defined(__riscv) && __riscv_xlen == 32
#define PT_ARG2_OFF 44
#define PT_ARG3_OFF 48
#define PT_ARG_SIZE BPF_W
#elif defined(__mips__) && _MIPS_SIM == _ABIO32
#define PT_ARG2_OFF 52
#define PT_ARG3_OFF 56
#define PT_ARG_SIZE BPF_W
#elif defined(__powerpc__) && !defined(__powerpc64__)
#define PT_ARG2_OFF 16
#define PT_ARG3_OFF 20
#define PT_ARG_SIZE BPF_W
#else
#error "Unsupported architecture"
#endif

/* Event structure size: pid(4) + len(4) + data */
#define EVENT_SIZE (8U + CHUNK_SIZE)

static int map_fd = -1, data_map_fd = -1, prog_fd = -1, perf_fd = -1;
static struct perf_event_mmap_page *pbuf[MAX_CPUS];
static unsigned char wrap_buf[sizeof(struct perf_event_header) +
                              sizeof(unsigned int) + EVENT_SIZE];
static long page_sz;
static unsigned int ncpus;

/*
 * I/O helper functions - suckless style
 * Uses POSIX write() instead of stdio (MISRA C:2012 Rule 21.6).
 * If msg ends with ':', errno string is appended.
 */
static void
write_str(const char *s)
{
	(void)write(STDERR_FILENO, s, strlen(s));
}

static void
die(const char *msg)
{
	size_t n = strlen(msg);
	int e = errno;
	write_str("ssltrace: ");
	write_str(msg);
	if (n > 0U && msg[n - 1U] == ':') {
		write_str(" ");
		write_str(strerror(e));
	}
	write_str("\n");
}

static void
ring_copy(void *dst, const char *base, size_t off, size_t len, size_t sz)
{
	size_t first = sz - off;
	if (off + len > sz) {
		(void)memcpy(dst, base + off, first);
		(void)memcpy((char *)dst + first, base, len - first);
	} else {
		(void)memcpy(dst, base + off, len);
	}
}

static long
sys_bpf(int cmd, union bpf_attr *a, unsigned int sz)
{
	return syscall(__NR_bpf, cmd, a, sz);
}

static long
sys_perf(struct perf_event_attr *a, int pid, int cpu, int grp, unsigned long fl)
{
	return syscall(__NR_perf_event_open, a, pid, cpu, grp, fl);
}

static int
create_map(unsigned int type, unsigned int val_sz, unsigned int max_ent)
{
	union bpf_attr a;
	(void)memset(&a, 0, sizeof(a));
	a.map.map_type = type;
	a.map.key_size = 4U;
	a.map.value_size = val_sz;
	a.map.max_entries = max_ent;
	return (int)sys_bpf(BPF_MAP_CREATE, &a, sizeof(a));
}

static int
load_prog(int perf_mfd, int data_mfd)
{
	union bpf_attr a;
	static char log[8192U];

	/*
	 * BPF program with bounded loop for unlimited data capture.
	 *
	 * Register allocation:
	 *   R6 = ctx (pt_regs pointer, preserved)
	 *   R7 = total_len (remaining bytes to read)
	 *   R8 = user_ptr (current read position)
	 *   R9 = data buffer pointer (from map lookup)
	 *
	 * Stack layout:
	 *   [R10-4]  = map key (always 0)
	 *   [R10-8]  = PID
	 *   [R10-16] = loop counter
	 */
	struct bpf_insn prog[] = {
		/* r6=ctx, get pid, r7=len, r8=buf */
		MOV_R(6, 1),
		CALL(BPF_FUNC_get_current_pid_tgid),
		ALU_I(BPF_RSH, 0, 32),
		STX(BPF_W, 10, 0, -8),
		LDX(PT_ARG_SIZE, 7, 6, PT_ARG3_OFF),
		LDX(PT_ARG_SIZE, 8, 6, PT_ARG2_OFF),
		/* r9 = map_lookup_elem(data_map, &0) */
		ST(BPF_W, 10, -4, 0),
		LD_MAP(1, 0),
		MOV_R(2, 10),
		ALU_I(BPF_ADD, 2, -4),
		CALL(BPF_FUNC_map_lookup_elem),
		JMP(BPF_JEQ, 0, 0, 31),
		MOV_R(9, 0),
		/* event->pid = pid */
		LDX(BPF_W, 0, 10, -8),
		STX(BPF_W, 9, 0, 0),
		ST(BPF_DW, 10, -16, 0),
		/* LOOP: if (r7 <= 0) exit */
		JMP(BPF_JLE, 7, 0, 26),
		/* r1 = min(r7, CHUNK_SIZE) */
		MOV_R(1, 7),
		JMP(BPF_JLE, 1, CHUNK_SIZE, 1),
		MOV_I(1, CHUNK_SIZE),
		STX(BPF_W, 9, 1, 4),
		STX(BPF_DW, 10, 1, -24),
		/* probe_read_user(event->data, chunk_len, user_ptr) */
		MOV_R(1, 9),
		ALU_I(BPF_ADD, 1, 8),
		LDX(BPF_DW, 2, 10, -24),
		MOV_R(3, 8),
		CALL(BPF_FUNC_probe_read_user),
		/* perf_event_output(ctx, map, -1, event, 8+len) */
		MOV_R(1, 6),
		LD_MAP(2, 0),
		I(BPF_LD|BPF_DW|BPF_IMM, 3, 0, 0, -1), I(0, 0, 0, 0, -1),
		MOV_R(4, 9),
		LDX(BPF_DW, 5, 10, -24),
		ALU_I(BPF_ADD, 5, 8),
		CALL(BPF_FUNC_perf_event_output),
		/* r8 += chunk, r7 -= chunk */
		LDX(BPF_DW, 0, 10, -24),
		ALU_R(BPF_ADD, 8, 0),
		ALU_R(BPF_SUB, 7, 0),
		/* loop counter++, continue if < max */
		LDX(BPF_DW, 0, 10, -16),
		ALU_I(BPF_ADD, 0, 1),
		STX(BPF_DW, 10, 0, -16),
		JMP(BPF_JLT, 0, BPF_MAX_LOOPS, -27),
		/* exit */
		MOV_I(0, 0),
		EXIT
	};

	/* Patch map file descriptors */
	prog[7].imm = data_mfd;
	prog[29].imm = perf_mfd;

	(void)memset(&a, 0, sizeof(a));
	a.prog.prog_type = BPF_PROG_TYPE_KPROBE;
	a.prog.insns = (unsigned long)prog;
	a.prog.insn_cnt = (unsigned int)(sizeof(prog) / sizeof(prog[0]));
	a.prog.license = (unsigned long)"GPL";
	a.prog.log_buf = (unsigned long)log;
	a.prog.log_size = (unsigned int)sizeof(log);
	a.prog.log_level = 1U;

	prog_fd = (int)sys_bpf(BPF_PROG_LOAD, &a, sizeof(a));
	if (prog_fd < 0) {
		write_str("ssltrace: bpf:\n");
		write_str(log);
		write_str("\n");
	}
	return prog_fd;
}

static int
attach(const char *path, unsigned long off, int pfd, int target_pid)
{
	struct perf_event_attr a;
	int fd, type, perf_pid, perf_cpu;
	long n, val;
	char *endp;
	char buf[32U];

	fd = open("/sys/bus/event_source/devices/uprobe/type", O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	n = read(fd, buf, sizeof(buf) - 1U);
	if (close(fd) < 0) {
		return -1;
	}
	if (n <= 0L) {
		return -1;
	}
	buf[(size_t)n] = '\0';
	val = strtol(buf, &endp, 10);
	if ((endp == buf) || (val < 0L) || (val > 2147483647L)) {
		return -1;
	}
	type = (int)val;

	if (target_pid < 0) {
		perf_pid = -1;
		perf_cpu = 0;
	} else {
		perf_pid = target_pid;
		perf_cpu = -1;
	}
	(void)memset(&a, 0, sizeof(a));
	a.type = (unsigned int)type;
	a.size = (unsigned int)sizeof(a);
	a.config1 = (unsigned long)path;
	a.config2 = off;
	a.sample_period = 1UL;
	a.wakeup_events = 1U;
	fd = (int)sys_perf(&a, perf_pid, perf_cpu, -1, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	if (ioctl(fd, (int)PERF_EVENT_IOC_SET_BPF, pfd) < 0) {
		return -1;
	}
	if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		return -1;
	}
	return fd;
}

static int
setup_pbuf(int mfd, int cpu)
{
	struct perf_event_attr a;
	union bpf_attr ba;
	int fd;
	(void)memset(&a, 0, sizeof(a));
	a.type = PERF_TYPE_SOFTWARE;
	a.size = (unsigned int)sizeof(a);
	a.config = PERF_COUNT_SW_BPF_OUTPUT;
	a.sample_period = 1UL;
	a.sample_type = PERF_SAMPLE_RAW;
	a.wakeup_events = 1U;
	fd = (int)sys_perf(&a, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	pbuf[cpu] = mmap(NULL, (size_t)page_sz * 9U, PROT_READ | PROT_WRITE, MAP_SHARED,
	                 fd, 0);
	if (pbuf[cpu] == MAP_FAILED) {
		return -1;
	}
	(void)memset(&ba, 0, sizeof(ba));
	ba.map_update.map_fd = (unsigned int)mfd;
	ba.map_update.key = (unsigned long)&cpu;
	ba.map_update.value = (unsigned long)&fd;
	if (sys_bpf(BPF_MAP_UPDATE_ELEM, &ba, sizeof(ba)) < 0) {
		return -1;
	}
	if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		return -1;
	}
	return fd;
}

static void
poll_cpu(int cpu)
{
	struct perf_event_mmap_page *hdr;
	char *base;
	unsigned long head, tail;
	size_t buf_sz, off, data_off;
	struct perf_event_header ev_hdr;
	unsigned int len;

	if (pbuf[cpu] == NULL) {
		return;
	}
	hdr = pbuf[cpu];
	base = (char *)hdr + page_sz;
	buf_sz = (size_t)page_sz * 8U;

	head = *(volatile unsigned long *)&hdr->data_head;
	tail = hdr->data_tail;

	while (tail != head) {
		off = tail & (buf_sz - 1U);
		ring_copy(&ev_hdr, base, off, sizeof(ev_hdr), buf_sz);
		ring_copy(wrap_buf, base, off, (size_t)ev_hdr.size, buf_sz);

		if (ev_hdr.type == PERF_RECORD_SAMPLE) {
			/* Offset to len: header + raw_size(u32) + pid(u32) */
			data_off = sizeof(ev_hdr) + 2U * sizeof(unsigned int);
			(void)memcpy(&len, wrap_buf + data_off, sizeof(len));
			if (len > CHUNK_SIZE) {
				len = CHUNK_SIZE;
			}
			if (len > 0U) {
				/* Data starts after len field */
				if (write(STDOUT_FILENO,
				          wrap_buf + data_off + sizeof(unsigned int),
				          len) < 0) {
					/* Output write failed, continue tracing */
				}
			}
		}
		tail += ev_hdr.size;
	}

	*(volatile unsigned long *)&hdr->data_tail = tail;
}

int
main(int argc, char **argv)
{
	const char *path;
	unsigned long off;
	unsigned int i;
	int target_pid;
	struct timespec ts;
	char *endp;

	target_pid = -1;

	/* Parse -p option */
	if (argc >= 2 && strcmp(argv[1], "-p") == 0) {
		long pid_val;
		if (argc < 3) {
			goto usage;
		}
		pid_val = strtol(argv[2], &endp, 10);
		if ((endp == argv[2]) || (*endp != '\0') || (pid_val < 0L) || (pid_val > 2147483647L)) {
			die("Invalid PID");
			return 1;
		}
		target_pid = (int)pid_val;
		argv += 2;
		argc -= 2;
	}

	if (argc != 3) {
usage:
		write_str("usage: ssltrace [-p pid] file offset\n");
		return 1;
	}
	path = argv[1];
	off = strtoul(argv[2], &endp, 0);
	if ((endp == argv[2]) || (*endp != '\0')) {
		die("Invalid offset");
		return 1;
	}

	page_sz = sysconf(_SC_PAGESIZE);
	if (page_sz < 4096) {
		page_sz = 4096;
	}

	{
		long nc = sysconf(_SC_NPROCESSORS_ONLN);
		if (nc < 1L) {
			nc = 1L;
		}
		if (nc > (long)MAX_CPUS) {
			nc = (long)MAX_CPUS;
		}
		ncpus = (unsigned int)nc;
	}

	map_fd = create_map(BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4U, ncpus);
	if (map_fd < 0) {
		die("create perf map:");
		return 1;
	}

	data_map_fd = create_map(BPF_MAP_TYPE_PERCPU_ARRAY, EVENT_SIZE, 1U);
	if (data_map_fd < 0) {
		die("create data map:");
		return 1;
	}

	prog_fd = load_prog(map_fd, data_map_fd);
	if (prog_fd < 0) {
		die("load bpf:");
		return 1;
	}

	perf_fd = attach(path, off, prog_fd, target_pid);
	if (perf_fd < 0) {
		int e = errno;
		write_str("ssltrace: attach ");
		write_str(path);
		write_str(": ");
		write_str(strerror(e));
		write_str("\n");
		return 1;
	}

	for (i = 0U; i < ncpus; i++) {
		(void)setup_pbuf(map_fd, (int)i);
	}

	ts.tv_sec = 0;
	ts.tv_nsec = 100000000L;
	for (;;) {
		(void)nanosleep(&ts, NULL);
		for (i = 0U; i < ncpus; i++) {
			poll_cpu((int)i);
		}
	}
	/* NOTREACHED - process terminated by signal, kernel cleans up */
}
