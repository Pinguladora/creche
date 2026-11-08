/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Wire format records produced in the kernel. The Rust side (crate creche-wire)
 * mirrors this layout, and build.rs turns it into static asserts that are checked
 * when this object is compiled. Records are sent truncated to their used bytes
 * where noted. hdr.len is always the length actually sent. */
#ifndef CRECHE_WIRE_H
#define CRECHE_WIRE_H

#define COMM_LEN 16
#define PATH_LEN 256
#define ARGS_LEN 512
#define CGROUP_LEN 96

enum ev_kind {
	EV_EXEC = 1,
	EV_FORK = 2,
	EV_EXIT = 3,
	EV_CONNECT = 4,
	EV_OPEN_WRITE = 5,
	EV_TASK = 6,
};

struct ev_hdr {
	__u16 kind;
	__u16 len;
	__u32 pid;
	__u64 ts_ns;
};

/* A process's context, sent when it differs from what was last sent for that
 * process. Other records carry only the pid. Sent truncated to the used part of
 * cgroup. */
struct ev_task {
	struct ev_hdr hdr;
	__u32 ppid;
	__u32 uid;
	__u64 cgroup_id;
	char comm[COMM_LEN];
	char cgroup[CGROUP_LEN];
};

/* hdr.pid is the child. The child starts with the parent's context. */
struct ev_fork {
	struct ev_hdr hdr;
	__u32 ppid;
	__u32 reserved;
};

struct ev_exit {
	struct ev_hdr hdr;
	__s32 exit_code;
	__u32 reserved;
};

struct ev_connect {
	struct ev_hdr hdr;
	__u16 family;
	__u16 dport;
	__u8 daddr[16];
	__u32 reserved;
};

/* Sent truncated to the used part of path. */
struct ev_open {
	struct ev_hdr hdr;
	__u32 path_len;
	char path[PATH_LEN];
};

/* Carries the process's context, which exec usually changes (the name), so no
 * task record is needed unless the host does not know the process or its cgroup
 * changed (this carries the cgroup id, not the name). data holds path_len bytes
 * of path (NUL included), then args_len bytes of NUL-separated arguments. Sent
 * truncated to the used part. */
struct ev_exec {
	struct ev_hdr hdr;
	__u32 ppid;
	__u32 uid;
	__u64 cgroup_id;
	char comm[COMM_LEN];
	__u16 path_len;
	__u16 args_len;
	char data[PATH_LEN + ARGS_LEN];
};

#endif
