// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* creche guest observer: process, connect and file-write events from inside a
 * Kata microVM, written to a ring buffer in the wire format (wire.h).
 *
 * Cheap by construction: noise is dropped before any copy, records are
 * variable-length and carry only the pid, a process's context (parent, uid,
 * cgroup, name) is sent only when it changes, and the reader is only woken
 * when it has work to do. */
#include "creche.h"
#include "wire.h"

#define AF_INET 2
#define AF_INET6 10
#define FMODE_WRITE 0x2
#define S_IFMT 0170000
#define S_IFIFO 0010000
#define S_IFCHR 0020000
#define S_IFSOCK 0140000
#define SCRATCH_LEN 1024

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Set by the loader before load. */
const volatile __u8 dedup_enabled = 0;
const volatile __u64 dedup_window_ns = 1000000000ULL;

/* Overhead breakdown only (observer --stage): stop after attaching, or after
 * everything but the ring buffer output. */
#define STAGE_FULL 0
#define STAGE_ATTACH 1
#define STAGE_LOGIC 2
const volatile __u8 stage = STAGE_FULL;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} events SEC(".maps");

/* Build area for records too big for the BPF stack. */
struct scratch {
	char buf[SCRATCH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} scratch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

/* A process's context as a task record carries it (the body of struct ev_task). */
struct task_ctx {
	__u32 ppid;
	__u32 uid;
	__u64 cgroup_id;
	char comm[COMM_LEN];
};

/* What was last sent for the process whose pid maps to this slot. A direct-mapped
 * cache rather than task storage: nothing is allocated or freed per process,
 * which cost about 1.7 us per fork+exec+exit, and the JIT inlines the lookup.
 * Two live processes sharing a slot, or a stale slot, only cost an extra task
 * record. */
#define TASK_SLOTS 4096

struct sent_slot {
	__u32 tgid;
	__u32 epoch;
	struct task_ctx ctx;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, TASK_SLOTS);
	__type(key, __u32);
	__type(value, struct sent_slot);
} sent SEC(".maps");

/* Bumped whenever the host may have missed a task record: by the kernel when a
 * record is dropped, by the observer on a new connection or a queue drop. Every
 * process whose context was sent in an older epoch sends it again. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} epoch SEC(".maps");

struct dedup_key {
	__u32 tgid;
	__u32 pad;
	__u64 inode;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dedup_key);
	__type(value, __u64);
} dedup SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 zero = 0;
	__u64 *d = bpf_map_lookup_elem(&drops, &zero);
	__u32 *e = bpf_map_lookup_elem(&epoch, &zero);

	if (d)
		(*d)++;
	/* The dropped record may have been a task record. */
	if (e)
		__sync_fetch_and_add(e, 1);
}

/* Wake the reader only for the first record after it drained the buffer. It
 * then waits a short batch window and drains everything, so a wakeup for any
 * later record would find it asleep in that window and only cost an irq_work
 * self-IPI, a VM exit. */
static __always_inline __u64 wake_flags(void)
{
	return bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) == 0 ? BPF_RB_FORCE_WAKEUP
								  : BPF_RB_NO_WAKEUP;
}

static __always_inline void fill_hdr(struct ev_hdr *h, __u16 kind, __u16 len)
{
	h->kind = kind;
	h->len = len;
	h->pid = bpf_get_current_pid_tgid() >> 32;
	h->ts_ns = bpf_ktime_get_boot_ns();
}

static __always_inline void *scratch(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&scratch_map, &zero);
}

/* Emit the first len bytes of a scratch-built record. Returns 0 when queued. */
static __always_inline long output(void *rec, __u64 len)
{
	__u64 wake;
	long err;

	if (stage == STAGE_LOGIC)
		return 0;
	wake = wake_flags();
	len &= SCRATCH_LEN - 1;
	((struct ev_hdr *)rec)->len = len;
	err = bpf_ringbuf_output(&events, rec, len, wake);
	if (err)
		count_drop();
	return err;
}

static __always_inline int same_ctx(const struct task_ctx *a, const struct task_ctx *b)
{
	const __u64 *ac = (const __u64 *)a->comm, *bc = (const __u64 *)b->comm;

	return a->ppid == b->ppid && a->uid == b->uid && a->cgroup_id == b->cgroup_id &&
	       ac[0] == bc[0] && ac[1] == bc[1];
}

static __always_inline struct sent_slot *slot_of(__u32 tgid)
{
	__u32 key = tgid & (TASK_SLOTS - 1);

	return bpf_map_lookup_elem(&sent, &key);
}

/* Send the current process's context if it differs from what was last sent for
 * it. Called before every record about the current process, so the host always
 * knows the context of the pid in a record. The name is the process's (its
 * group leader's), not the thread's, so threads with their own names do not
 * keep resending it. Returns the process's slot when it is in sync. */
static __always_inline void current_ctx(struct task_struct *leader, struct task_ctx *now)
{
	now->ppid = leader->real_parent->tgid;
	now->uid = (__u32)bpf_get_current_uid_gid();
	now->cgroup_id = bpf_get_current_cgroup_id();
	bpf_probe_read_kernel(now->comm, sizeof(now->comm), leader->comm);
}

static __always_inline struct sent_slot *sync_task(void)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct task_struct *leader = t->group_leader;
	__u32 zero = 0, tgid = leader->tgid, *ep = bpf_map_lookup_elem(&epoch, &zero);
	struct sent_slot *s = slot_of(tgid);
	struct task_ctx now = {};
	struct ev_task *e;
	long n;

	if (!ep || !s)
		return 0;
	current_ctx(leader, &now);
	if (s->tgid == tgid && s->epoch == *ep && same_ctx(&s->ctx, &now))
		return s;
	e = scratch();
	if (!e)
		return 0;
	fill_hdr(&e->hdr, EV_TASK, 0);
	__builtin_memcpy(&e->ppid, &now, sizeof(now));
	n = bpf_probe_read_kernel_str(e->cgroup, sizeof(e->cgroup), t->cgroups->dfl_cgrp->kn->name);
	if (n < 0)
		n = 0;
	if (n > CGROUP_LEN)
		n = CGROUP_LEN;
	if (output(e, __builtin_offsetof(struct ev_task, cgroup) + n))
		return 0;
	s->tgid = tgid;
	s->epoch = *ep;
	s->ctx = now;
	return s;
}

/* tp_btf and fentry programs get their arguments as an array of u64. The
 * verifier types each one from the kernel's BTF, so fields can be read directly. */

SEC("tp_btf/sched_process_exec")
int on_exec(__u64 *ctx)
{
	struct task_struct *p = (void *)ctx[0];
	struct linux_binprm *bprm = (void *)ctx[2];
	struct task_struct *leader = p->group_leader;
	__u32 zero = 0, tgid = leader->tgid, *ep = bpf_map_lookup_elem(&epoch, &zero);
	struct sent_slot *s = slot_of(tgid);
	struct task_ctx now = {};
	struct ev_exec *e;
	unsigned long len;
	long n;

	if (stage == STAGE_ATTACH)
		return 0;
	if (!ep || !s)
		return 0;
	current_ctx(leader, &now);
	/* The record carries the new context. A task record goes first only when
	 * the host does not know this process yet or must learn a new cgroup name. */
	if (s->tgid != tgid || s->epoch != *ep || s->ctx.cgroup_id != now.cgroup_id)
		sync_task();
	e = scratch();
	if (!e)
		return 0;
	fill_hdr(&e->hdr, EV_EXEC, 0);
	__builtin_memcpy(&e->ppid, &now, sizeof(now));
	n = bpf_probe_read_kernel_str(e->data, PATH_LEN, bprm->filename);
	if (n < 0)
		n = 0;
	if (n > PATH_LEN)
		n = PATH_LEN;
	len = p->mm->arg_end - p->mm->arg_start;
	if (len > ARGS_LEN - 1)
		len = ARGS_LEN - 1;
	/* The arguments follow the path. The masks prove the bounds to the verifier. */
	if (bpf_probe_read_user(e->data + n, len & (ARGS_LEN - 1), (void *)p->mm->arg_start))
		len = 0;
	e->path_len = n;
	e->args_len = len;
	if (output(e, __builtin_offsetof(struct ev_exec, data) + n + (len & (ARGS_LEN - 1))))
		return 0;
	if (s->tgid == tgid && s->epoch == *ep)
		s->ctx = now;
	return 0;
}

SEC("tp_btf/sched_process_fork")
int on_fork(__u64 *ctx)
{
	struct task_struct *parent = (void *)ctx[0];
	struct task_struct *child = (void *)ctx[1];
	struct sent_slot *known, *c;
	struct ev_fork *e;
	__u64 wake;

	if (stage == STAGE_ATTACH)
		return 0;
	/* Only new processes, not new threads. */
	if (child->pid != child->tgid)
		return 0;
	/* The host copies the parent's context to the child, so it must have it. */
	known = sync_task();
	/* Record that the host knows the child's context, so its first event does
	 * not resend it. If the child's own name differs (a fork from a named
	 * thread), the next check finds the difference and sends it. The child has
	 * not run yet, so this can precede the fork record. */
	c = slot_of(child->tgid);
	if (known && c) {
		/* c may be the parent's own slot: copy before changing anything. */
		c->ctx = known->ctx;
		c->epoch = known->epoch;
		c->ctx.ppid = parent->tgid;
		c->tgid = child->tgid;
	}
	if (stage == STAGE_LOGIC)
		return 0;
	/* Decide before reserving, so our own reservation is not counted. */
	wake = wake_flags();
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	fill_hdr(&e->hdr, EV_FORK, sizeof(*e));
	e->hdr.pid = child->tgid;
	e->ppid = parent->tgid;
	e->reserved = 0;
	bpf_ringbuf_submit(e, wake);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int on_exit(__u64 *ctx)
{
	struct task_struct *p = (void *)ctx[0];
	struct ev_exit *e;
	__u64 wake;

	if (stage == STAGE_ATTACH)
		return 0;
	/* Only when the whole process goes away. */
	if (p->pid != p->tgid)
		return 0;
	sync_task();
	if (stage == STAGE_LOGIC)
		return 0;
	wake = wake_flags();
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	fill_hdr(&e->hdr, EV_EXIT, sizeof(*e));
	e->exit_code = p->exit_code >> 8;
	e->reserved = 0;
	bpf_ringbuf_submit(e, wake);
	return 0;
}

SEC("fentry/tcp_connect")
int on_connect(__u64 *ctx)
{
	struct sock *sk = (void *)ctx[0];
	struct ev_connect *e;
	__u64 wake;
	__u32 daddr;

	if (stage == STAGE_ATTACH)
		return 0;
	sync_task();
	if (stage == STAGE_LOGIC)
		return 0;
	wake = wake_flags();
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}
	fill_hdr(&e->hdr, EV_CONNECT, sizeof(*e));
	e->reserved = 0;
	e->family = sk->__sk_common.skc_family;
	e->dport = __builtin_bswap16(sk->__sk_common.skc_dport);
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	if (e->family == AF_INET) {
		daddr = sk->__sk_common.skc_daddr;
		__builtin_memcpy(e->daddr, &daddr, sizeof(daddr));
	} else if (e->family == AF_INET6) {
		bpf_probe_read_kernel(e->daddr, sizeof(e->daddr), &sk->__sk_common.skc_v6_daddr);
	}
	bpf_ringbuf_submit(e, wake);
	return 0;
}

/* Pseudo filesystems and special files the runtime writes to constantly. */
static __always_inline int noise(struct file *f)
{
	struct inode *ino = f->f_inode;
	unsigned int fmt = ino->i_mode & S_IFMT;

	if (fmt == S_IFCHR || fmt == S_IFIFO || fmt == S_IFSOCK)
		return 1;
	switch (ino->i_sb->s_magic) {
	case 0x9fa0:		/* proc */
	case 0x62656572:	/* sysfs */
	case 0x27e0eb:		/* cgroup */
	case 0x63677270:	/* cgroup2 */
	case 0x09041934:	/* anon_inode */
	case 0x50495045:	/* pipefs */
	case 0x534F434B:	/* sockfs */
	case 0x64626720:	/* debugfs */
	case 0x74726163:	/* tracefs */
	case 0xcafe4a11:	/* bpf */
	case 0x73636673:	/* securityfs */
	case 0x6e736673:	/* nsfs */
	case 0x1cd1:		/* devpts */
	case 0x50494446:	/* pidfs */
	case 0x62656570:	/* configfs */
		return 1;
	}
	return 0;
}

/* Repeated opens of the same file by the same process within the window. */
static __always_inline int duplicate(struct file *f)
{
	struct dedup_key k = {
		.tgid = bpf_get_current_pid_tgid() >> 32,
		.inode = (__u64)f->f_inode,
	};
	__u64 now = bpf_ktime_get_boot_ns(), *last;

	last = bpf_map_lookup_elem(&dedup, &k);
	if (last && now - *last < dedup_window_ns)
		return 1;
	bpf_map_update_elem(&dedup, &k, &now, BPF_ANY);
	return 0;
}

SEC("fentry/security_file_open")
int on_open(__u64 *ctx)
{
	struct file *f = (void *)ctx[0];
	struct ev_open *e;
	long n;

	if (stage == STAGE_ATTACH)
		return 0;
	if (!(f->f_mode & FMODE_WRITE) || noise(f))
		return 0;
	if (dedup_enabled && duplicate(f))
		return 0;
	sync_task();
	e = scratch();
	if (!e)
		return 0;
	fill_hdr(&e->hdr, EV_OPEN_WRITE, 0);
	n = bpf_d_path(&f->f_path, e->path, sizeof(e->path));
	if (n < 0)
		n = 0;
	if (n > PATH_LEN)
		n = PATH_LEN;
	e->path_len = n;
	output(e, __builtin_offsetof(struct ev_open, path) + n);
	return 0;
}
