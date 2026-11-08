/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Minimal BPF environment for the creche observer: only the kernel types and
 * helpers it uses, so neither libbpf nor a generated vmlinux.h is needed.
 *
 * The kernel structs below are partial. They are marked preserve_access_index,
 * so clang emits CO-RE relocations and the loader (aya) fixes every field
 * offset against the running kernel's BTF. Field names must match the kernel.
 * Order and the missing fields do not matter. */
#ifndef CRECHE_H
#define CRECHE_H

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
/* linux/stddef.h defines __always_inline as a plain inline hint. Force it. */
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define CO_RE __attribute__((preserve_access_index))

/* Helpers, by id from the UAPI enum bpf_func_id. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
				   __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*bpf_ktime_get_boot_ns)(void) = (void *)BPF_FUNC_ktime_get_boot_ns;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)BPF_FUNC_get_current_comm;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)BPF_FUNC_probe_read_kernel;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size,
					 const void *src) = (void *)BPF_FUNC_probe_read_kernel_str;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *src) = (void *)BPF_FUNC_probe_read_user;
static long (*bpf_d_path)(void *path, char *buf, __u32 size) = (void *)BPF_FUNC_d_path;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size,
				  __u64 flags) = (void *)BPF_FUNC_ringbuf_output;
static __u64 (*bpf_ringbuf_query)(void *ringbuf, __u64 flags) = (void *)BPF_FUNC_ringbuf_query;
static void *(*bpf_get_current_task_btf)(void) = (void *)BPF_FUNC_get_current_task_btf;

/* Kernel types, partial (see above). */
struct kernfs_node {
	const char *name;
} CO_RE;

struct cgroup {
	struct kernfs_node *kn;
} CO_RE;

struct css_set {
	struct cgroup *dfl_cgrp;
} CO_RE;

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
} CO_RE;

struct task_struct {
	int pid;
	int tgid;
	int exit_code;
	char comm[16];
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	struct mm_struct *mm;
	struct css_set *cgroups;
} CO_RE;

struct linux_binprm {
	const char *filename;
} CO_RE;

struct super_block {
	unsigned long s_magic;
} CO_RE;

struct inode {
	unsigned short i_mode;
	struct super_block *i_sb;
} CO_RE;

struct path {
	void *mnt;
	void *dentry;
} CO_RE;

struct file {
	unsigned int f_mode;
	struct path f_path;
	struct inode *f_inode;
} CO_RE;

struct in6_addr_bytes {
	__u8 bytes[16];
} CO_RE;

struct sock_common {
	unsigned short skc_family;
	__be16 skc_dport;
	__be32 skc_daddr;
	struct in6_addr_bytes skc_v6_daddr;
} CO_RE;

struct sock {
	struct sock_common __sk_common;
} CO_RE;

#endif
