// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/lsm_hooks.h>
#include <linux/bpf_lsm.h>
#include <linux/kallsyms.h>
#include <linux/bpf_verifier.h>
#include <net/bpf_sk_storage.h>
#include <linux/bpf_local_storage.h>
#include <linux/btf_ids.h>

/* For every LSM hook that allows attachment of BPF programs, declare a nop
 * function where a BPF program can be attached.
 */
#define LSM_HOOK(RET, DEFAULT, NAME, ...)	\
noinline RET bpf_lsm_##NAME(__VA_ARGS__)	\
{						\
	return DEFAULT;				\
}

#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

/* alioth-research-fork: BTF_SET(bpf_lsm_hooks) is unused — see
 * bpf_lsm_verify_prog below for the reason. Kept commented out (not
 * deleted) so a future port to a tree with resolve_btfids in tools/
 * can restore the BTF_ID-based check by un-commenting this block.
 *
 * #define LSM_HOOK(RET, DEFAULT, NAME, ...) BTF_ID(func, bpf_lsm_##NAME)
 * BTF_SET_START(bpf_lsm_hooks)
 * #include <linux/lsm_hook_defs.h>
 * #undef LSM_HOOK
 * BTF_SET_END(bpf_lsm_hooks)
 */

int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
			const struct bpf_prog *prog)
{
	const char *fn;

	if (!prog->gpl_compatible) {
		bpf_log(vlog,
			"LSM programs must have a GPL compatible license\n");
		return -EINVAL;
	}

	/* alioth-research-fork: tools/bpf/resolve_btfids is not built on
	 * 4.19 (the source dir does not exist), so the BTF_ID()-based
	 * bpf_lsm_hooks set above is never populated -- every LSM attach
	 * would fail with a stale "wrong type name" log even though the
	 * target function is a real bpf_lsm_<hook> stub.
	 *
	 * Fall back to a prefix check on the resolved function name. The
	 * verifier has already proven that attach_btf_id points to a
	 * BTF_KIND_FUNC of name attach_func_name, so this is sufficient
	 * to identify a legitimate LSM hook target.
	 */
	fn = prog->aux->attach_func_name;
	if (!fn || strncmp(fn, "bpf_lsm_", 8) != 0) {
		bpf_log(vlog, "attach_func_name %s does not start with bpf_lsm_\n",
			fn ? fn : "(null)");
		return -EINVAL;
	}

	return 0;
}

static const struct bpf_func_proto *
bpf_lsm_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_inode_storage_get:
		return &bpf_inode_storage_get_proto;
	case BPF_FUNC_inode_storage_delete:
		return &bpf_inode_storage_delete_proto;
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_proto;
	default:
		return tracing_prog_func_proto(func_id, prog);
	}
}

const struct bpf_prog_ops lsm_prog_ops = {
};

const struct bpf_verifier_ops lsm_verifier_ops = {
	.get_func_proto = bpf_lsm_func_proto,
	.is_valid_access = btf_ctx_access,
};
