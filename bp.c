/* Copyright 2026 edcsnt. All rights reserved. */
/* ssltrace-ebpf - eBPF SSL capture with HTTP/2 decoding (C89) */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>

/* syscall is POSIX but needs explicit declaration for strict C89 */
long syscall(long, ...);

#define PAGE_SIZE 4096
#define BUFLEN 504
#define MAX_CPUS 8

#ifndef __NR_bpf
#define __NR_bpf 280
#endif
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif

/* === HTTP/2 HPACK decoder (RFC 7541) === */

/* Huffman table: 256 symbols, codes 5-30 bits (RFC 7541 Appendix B) */
static const unsigned char huff_len[257] = {
	13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,28,28,28,28,
	28,28,30,28,28,28,28,28,28,28,28,28,6,10,10,12,13,6,8,11,10,
	10,8,11,8,6,6,6,5,5,5,6,6,6,6,6,6,6,7,8,15,6,12,10,13,6,7,7,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,7,8,13,19,13,14,6,
	15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,6,7,6,5,5,6,7,7,7,7,7,15,11,
	14,13,28,20,22,20,20,22,22,22,23,22,23,23,23,23,23,24,23,24,
	24,22,23,24,23,23,23,23,21,22,23,22,23,23,24,22,21,20,22,22,
	23,23,21,23,22,22,24,21,22,23,23,21,21,22,21,23,22,23,23,20,
	22,22,22,23,22,22,23,26,26,20,19,22,23,23,23,23,22,23,26,23,
	23,23,23,23,23,26,27,27,27,27,27,26,27,27,26,26,26,27,27,27,
	27,27,28,27,27,27,27,27,26,27,27,27,27,27,27,27,27,27,27,27,
	27,27,27,27,27,27,28,30
};
static const unsigned long huff_code[257] = {
	0x1ff8,0x7fffd8,0xfffffe2,0xfffffe3,0xfffffe4,0xfffffe5,0xfffffe6,
	0xfffffe7,0xfffffe8,0xffffea,0x3ffffffc,0xfffffe9,0xfffffea,
	0x3ffffffd,0xfffffeb,0xfffffec,0xfffffed,0xfffffee,0xfffffef,
	0xffffff0,0xffffff1,0xffffff2,0x3ffffffe,0xffffff3,0xffffff4,
	0xffffff5,0xffffff6,0xffffff7,0xffffff8,0xffffff9,0xffffffa,
	0xffffffb,0x14,0x3f8,0x3f9,0xffa,0x1ff9,0x15,0xf8,0x7fa,0x3fa,
	0x3fb,0xf9,0x7fb,0xfa,0x16,0x17,0x18,0x0,0x1,0x2,0x19,0x1a,0x1b,
	0x1c,0x1d,0x1e,0x1f,0x5c,0xfb,0x7ffc,0x20,0xffb,0x3fc,0x1ffa,
	0x21,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,
	0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0xfc,
	0x73,0xfd,0x1ffb,0x7fff0,0x1ffc,0x3ffc,0x22,0x7ffd,0x3,0x23,
	0x4,0x24,0x5,0x25,0x26,0x27,0x6,0x74,0x75,0x28,0x29,0x2a,0x7,
	0x2b,0x76,0x2c,0x8,0x9,0x2d,0x77,0x78,0x79,0x7a,0x7b,0x7ffe,
	0x7fc,0x3ffd,0x1ffd,0xffffffc,0xfffe6,0x3fffd2,0xfffe7,0xfffe8,
	0x3fffd3,0x3fffd4,0x3fffd5,0x7fffd9,0x3fffd6,0x7fffda,0x7fffdb,
	0x7fffdc,0x7fffdd,0x7fffde,0xffffeb,0x7fffdf,0xffffec,0xffffed,
	0x3fffd7,0x7fffe0,0xffffee,0x7fffe1,0x7fffe2,0x7fffe3,0x7fffe4,
	0x1fffdc,0x3fffd8,0x7fffe5,0x3fffd9,0x7fffe6,0x7fffe7,0xffffef,
	0x3fffda,0x1fffdd,0xfffe9,0x3fffdb,0x3fffdc,0x7fffe8,0x7fffe9,
	0x1fffde,0x7fffea,0x3fffdd,0x3fffde,0xfffff0,0x1fffdf,0x3fffdf,
	0x7fffeb,0x7fffec,0x1fffe0,0x1fffe1,0x3fffe0,0x1fffe2,0x7fffed,
	0x3fffe1,0x7fffee,0x7fffef,0xfffea,0x3fffe2,0x3fffe3,0x3fffe4,
	0x7ffff0,0x3fffe5,0x3fffe6,0x7ffff1,0x3ffffe0,0x3ffffe1,0xfffeb,
	0x7fff1,0x3fffe7,0x7ffff2,0x3fffe8,0x1ffffec,0x3ffffe2,0x3ffffe3,
	0x3ffffe4,0x7ffffde,0x7ffffdf,0x3ffffe5,0xfffff1,0x1ffffed,0x7fff2,
	0x1fffe3,0x3ffffe6,0x7ffffe0,0x7ffffe1,0x3ffffe7,0x7ffffe2,
	0xfffff2,0x1fffe4,0x1fffe5,0x3ffffe8,0x3ffffe9,0xffffffd,
	0x7ffffe3,0x7ffffe4,0x7ffffe5,0xfffec,0xfffff3,0xfffed,0x1fffe6,
	0x3fffe9,0x1fffe7,0x1fffe8,0x7ffff3,0x3fffea,0x3fffeb,0x1ffffee,
	0x1ffffef,0xfffff4,0xfffff5,0x3ffffea,0x7ffff4,0x3ffffeb,0x7ffffe6,
	0x3ffffec,0x3ffffed,0x7ffffe7,0x7ffffe8,0x7ffffe9,0x7ffffea,
	0x7ffffeb,0xffffffe,0x7ffffec,0x7ffffed,0x7ffffee,0x7ffffef,
	0x7fffff0,0x3ffffee,0x3fffffff
};

static void huff_dec(const unsigned char *in, int n) {
	unsigned long bits = 0;
	int nb = 0, i, j;
	for (i = 0; i < n; i++) {
		bits = (bits << 8) | in[i];
		nb += 8;
		while (nb >= 5) {
			for (j = 0; j < 256; j++) {
				if (huff_len[j] <= (unsigned)nb) {
					unsigned long mask = (1UL << huff_len[j]) - 1;
					if (((bits >> (nb - huff_len[j])) & mask) == huff_code[j]) {
						putchar(j);
						nb -= huff_len[j];
						bits &= (1UL << nb) - 1;
						goto next;
					}
				}
			}
			break;
			next:;
		}
	}
}

/* HPACK static table (indices 1-61) */
static const char *hpack_n[] = {
	"",":authority",":method",":method",":path",":path",":scheme",":scheme",
	":status",":status",":status",":status",":status",":status",":status",
	"accept-charset","accept-encoding","accept-language","accept-ranges",
	"accept","access-control-allow-origin","age","allow","authorization",
	"cache-control","content-disposition","content-encoding","content-language",
	"content-length","content-location","content-range","content-type","cookie",
	"date","etag","expect","expires","from","host","if-match","if-modified-since",
	"if-none-match","if-range","if-unmodified-since","last-modified","link",
	"location","max-forwards","proxy-authenticate","proxy-authorization","range",
	"referer","refresh","retry-after","server","set-cookie",
	"strict-transport-security","transfer-encoding","user-agent","vary","via",
	"www-authenticate"
};
static const char *hpack_v[] = {
	"","","GET","POST","/","/index.html","http","https","200","204","206",
	"304","400","404","500","","gzip, deflate","","","","","","","","","",
	"","","","","","","","","","","","","","","","","","","","","","","",
	"","","","","","","","","","","","",""
};

static int dec_int(const unsigned char *b, int len, int *p, int n) {
	int m = (1 << n) - 1, v = b[*p] & m, s = 0;
	(*p)++;
	if (v < m) return v;
	while (*p < len && (b[*p] & 128)) { v += (b[(*p)++] & 127) << s; s += 7; }
	if (*p < len) v += (b[(*p)++] & 127) << s;
	return v;
}

static void dec_str(const unsigned char *b, int len, int *p) {
	int h, slen;
	if (*p >= len) return;
	h = b[*p] & 0x80;
	slen = dec_int(b, len, p, 7);
	if (slen > len - *p) slen = len - *p;
	if (h) { huff_dec(b + *p, slen); *p += slen; }
	else while (slen-- > 0 && *p < len) putchar(b[(*p)++]);
}

static void dec_hdr(const unsigned char *b, int len) {
	int p = 0, i;
	unsigned char c;
	while (p < len) {
		c = b[p];
		if (c & 0x80) {
			i = dec_int(b, len, &p, 7);
			if (i > 0 && i < 62) printf("%s: %s\n", hpack_n[i], hpack_v[i]);
		} else if (c & 0x40) {
			i = dec_int(b, len, &p, 6);
			if (i > 0 && i < 62) printf("%s: ", hpack_n[i]);
			else { dec_str(b, len, &p); printf(": "); }
			dec_str(b, len, &p); putchar('\n');
		} else if ((c & 0xf0) == 0 || (c & 0xf0) == 0x10) {
			i = dec_int(b, len, &p, 4);
			if (i > 0 && i < 62) printf("%s: ", hpack_n[i]);
			else { dec_str(b, len, &p); printf(": "); }
			dec_str(b, len, &p); putchar('\n');
		} else if (c & 0x20) {
			dec_int(b, len, &p, 5);
		} else p++;
	}
}

/* HTTP/2 frame buffer */
static unsigned char h2buf[65536];
static int h2len = 0;

static void h2_process(void) {
	int flen, ftype;
	if (h2len >= 24 && memcmp(h2buf, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
		memmove(h2buf, h2buf + 24, h2len - 24);
		h2len -= 24;
	}
	while (h2len >= 9) {
		flen = (h2buf[0] << 16) | (h2buf[1] << 8) | h2buf[2];
		ftype = h2buf[3];
		if (9 + flen > h2len) break;
		if (ftype == 1 || ftype == 9) dec_hdr(h2buf + 9, flen);
		else if (ftype == 0) fwrite(h2buf + 9, 1, flen, stdout);
		memmove(h2buf, h2buf + 9 + flen, h2len - 9 - flen);
		h2len -= 9 + flen;
	}
}

static void h2_feed(const unsigned char *d, int n) {
	if (h2len + n > (int)sizeof(h2buf)) h2len = 0;
	memcpy(h2buf + h2len, d, n);
	h2len += n;
	h2_process();
}

/* === eBPF infrastructure === */

struct event { unsigned int pid, len; unsigned char data[BUFLEN]; };

static volatile sig_atomic_t run = 1;
static int map_fd = -1, prog_fd = -1, perf_fd = -1;
static int pbuf_fd[MAX_CPUS];
static void *pbuf[MAX_CPUS];
static long page_sz;
static int ncpus;

static void die(const char *s) { perror(s); exit(1); }
static void onsig(int sig) { (void)sig; run = 0; }

static long sys_bpf(int cmd, union bpf_attr *a, unsigned int sz) {
	return syscall(__NR_bpf, cmd, a, sz);
}
static long sys_perf(struct perf_event_attr *a, int pid, int cpu, int grp, unsigned long fl) {
	return syscall(__NR_perf_event_open, a, pid, cpu, grp, fl);
}

static int get_uprobe_type(void) {
	int fd, n; char buf[32];
	fd = open("/sys/bus/event_source/devices/uprobe/type", O_RDONLY);
	if (fd < 0) return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) return -1;
	buf[n] = '\0';
	return atoi(buf);
}

static int create_map(int nc) {
	union bpf_attr a;
	memset(&a, 0, sizeof(a));
	a.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
	a.key_size = 4; a.value_size = 4; a.max_entries = nc;
	return sys_bpf(BPF_MAP_CREATE, &a, sizeof(a));
}

static int load_prog(int mfd) {
	union bpf_attr a;
	static char log[4096];
	struct bpf_insn prog[] = {
		{0xbf, 6, 1, 0, 0},           /* mov r6, r1 */
		{0x85, 0, 0, 0, 14},          /* call get_current_pid_tgid */
		{0x77, 0, 0, 0, 32},          /* rsh r0, 32 */
		{0x63, 10, 0, -512, 0},       /* stxw [r10-512], r0 */
		{0x79, 7, 6, 16, 0},          /* ldxdw r7, [r6+16] */
		{0xb5, 7, 0, 1, BUFLEN},      /* jle r7, BUFLEN, +1 */
		{0xb7, 7, 0, 0, BUFLEN},      /* mov r7, BUFLEN */
		{0x63, 10, 7, -508, 0},       /* stxw [r10-508], r7 */
		{0x79, 8, 6, 8, 0},           /* ldxdw r8, [r6+8] */
		{0xbf, 1, 10, 0, 0},          /* mov r1, r10 */
		{0x07, 1, 0, 0, -504},        /* add r1, -504 */
		{0xbf, 2, 7, 0, 0},           /* mov r2, r7 */
		{0xbf, 3, 8, 0, 0},           /* mov r3, r8 */
		{0x85, 0, 0, 0, 112},         /* call probe_read_user */
		{0xbf, 1, 6, 0, 0},           /* mov r1, r6 */
		{0x18, 2, 1, 0, 0},           /* ld_imm64 r2, mfd (patched) */
		{0x00, 0, 0, 0, 0},
		{0x18, 3, 0, 0, -1},          /* ld_imm64 r3, 0xffffffff */
		{0x00, 0, 0, 0, 0},
		{0xbf, 4, 10, 0, 0},          /* mov r4, r10 */
		{0x07, 4, 0, 0, -512},        /* add r4, -512 */
		{0xb7, 5, 0, 0, 512},         /* mov r5, 512 */
		{0x85, 0, 0, 0, 25},          /* call perf_event_output */
		{0xb7, 0, 0, 0, 0},           /* mov r0, 0 */
		{0x95, 0, 0, 0, 0}            /* exit */
	};
	prog[15].imm = mfd;
	memset(&a, 0, sizeof(a));
	a.prog_type = BPF_PROG_TYPE_KPROBE;
	a.insns = (unsigned long)prog;
	a.insn_cnt = sizeof(prog)/sizeof(prog[0]);
	a.license = (unsigned long)"GPL";
	a.log_buf = (unsigned long)log; a.log_size = sizeof(log); a.log_level = 1;
	prog_fd = sys_bpf(BPF_PROG_LOAD, &a, sizeof(a));
	if (prog_fd < 0) fprintf(stderr, "bpf: %s\n", log);
	return prog_fd;
}

static int attach(const char *path, unsigned long off, int pfd) {
	struct perf_event_attr a;
	int type = get_uprobe_type(), fd;
	if (type < 0) return -1;
	memset(&a, 0, sizeof(a));
	a.type = type; a.size = sizeof(a);
	a.config1 = (unsigned long)path; a.config2 = off;
	a.sample_period = 1; a.wakeup_events = 1;
	fd = sys_perf(&a, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0) return -1;
	if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, pfd) < 0) { close(fd); return -1; }
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	return fd;
}

static int setup_pbuf(int mfd, int cpu) {
	struct perf_event_attr a;
	union bpf_attr ba;
	int fd;
	memset(&a, 0, sizeof(a));
	a.type = PERF_TYPE_SOFTWARE; a.size = sizeof(a);
	a.config = PERF_COUNT_SW_BPF_OUTPUT;
	a.sample_period = 1; a.sample_type = PERF_SAMPLE_RAW; a.wakeup_events = 1;
	fd = sys_perf(&a, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0) return -1;
	pbuf[cpu] = mmap(NULL, page_sz * 9, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (pbuf[cpu] == MAP_FAILED) { close(fd); return -1; }
	memset(&ba, 0, sizeof(ba));
	ba.map_fd = mfd; ba.key = (unsigned long)&cpu; ba.value = (unsigned long)&fd;
	if (sys_bpf(BPF_MAP_UPDATE_ELEM, &ba, sizeof(ba)) < 0) { close(fd); return -1; }
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	pbuf_fd[cpu] = fd;
	return fd;
}

static void poll_cpu(int cpu) {
	struct perf_event_mmap_page *hdr;
	char *base;
	unsigned long tail, head, buf_sz, off;
	struct perf_event_header *ev;
	struct event *e;
	if (!pbuf[cpu]) return;
	hdr = pbuf[cpu];
	base = (char *)pbuf[cpu] + page_sz;
	buf_sz = page_sz * 8;
	head = hdr->data_head;
	__sync_synchronize();
	tail = hdr->data_tail;
	while (tail < head) {
		off = tail % buf_sz;
		ev = (struct perf_event_header *)(base + off);
		if (ev->type == PERF_RECORD_SAMPLE) {
			e = (struct event *)((char *)ev + sizeof(*ev) + sizeof(unsigned int));
			if (e->len > 0) { h2_feed(e->data, e->len > BUFLEN ? BUFLEN : e->len); fflush(stdout); }
		}
		tail += ev->size;
	}
	hdr->data_tail = tail;
}

static void poll_all(void) { int i; for (i = 0; i < ncpus; i++) poll_cpu(i); }

int main(int argc, char **argv) {
	char apk[512];
	const char *path, *sep;
	unsigned long off;
	int i;
	struct timespec ts;
	size_t n;
	if (argc != 3) { fprintf(stderr, "usage: %s apk offset\n", argv[0]); return 1; }
	path = argv[1]; off = strtoul(argv[2], NULL, 0); page_sz = PAGE_SIZE;
	sep = strchr(path, '!');
	if (sep) { n = sep - path; if (n >= sizeof(apk)) n = sizeof(apk) - 1;
		memcpy(apk, path, n); apk[n] = '\0'; path = apk; }
	signal(SIGINT, onsig); signal(SIGTERM, onsig);
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpus < 1) ncpus = 1;
	if (ncpus > MAX_CPUS) ncpus = MAX_CPUS;
	map_fd = create_map(ncpus); if (map_fd < 0) die("map");
	prog_fd = load_prog(map_fd); if (prog_fd < 0) die("prog");
	perf_fd = attach(path, off, prog_fd); if (perf_fd < 0) die("attach");
	for (i = 0; i < ncpus; i++)
		if (setup_pbuf(map_fd, i) < 0) fprintf(stderr, "warn: cpu%d\n", i);
	fprintf(stderr, "tracing on %d CPUs...\n", ncpus);
	ts.tv_sec = 0; ts.tv_nsec = 100000000;
	while (run) { nanosleep(&ts, NULL); poll_all(); }
	for (i = 0; i < ncpus; i++) if (pbuf_fd[i] > 0) close(pbuf_fd[i]);
	close(perf_fd); close(prog_fd); close(map_fd);
	return 0;
}
