// SPDX-License-Identifier: GPL-2.0
/*
 * Provide kernel BTF information for introspection and use by eBPF tools.
 *
 * 4.19-research-fork: when btf_vmlinux comes from a runtime FS load (no
 * .BTF section), expose its content here so userspace libbpf can find it
 * at the standard /sys/kernel/btf/vmlinux path. The sysfs file is created
 * lazily by ksu_btf_sysfs_register() called from btf_parse_vmlinux() on
 * successful load.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/init.h>
#include <linux/sysfs.h>

/* See scripts/link-vmlinux.sh, gen_btf() func for details */
extern char __weak __start_BTF[];
extern char __weak __stop_BTF[];

/* The kernel-side btf accessor (in btf.c) so we can read btf->data without
 * pulling btf struct private definitions (and avoid the dependency cycle of
 * including <linux/btf.h> which forward-references struct bpf_prog). */
extern void *ksu_btf_vmlinux_data(u32 *size_out);

static ssize_t
btf_vmlinux_read(struct file *file, struct kobject *kobj,
		 struct bin_attribute *bin_attr,
		 char *buf, loff_t off, size_t len)
{
	void *data;
	u32 size;

	/* Prefer FS-loaded btf_vmlinux when set (P2 path on this build). */
	data = ksu_btf_vmlinux_data(&size);
	if (data && size > 0) {
		if (off >= size)
			return 0;
		if (off + len > size)
			len = size - off;
		memcpy(buf, data + off, len);
		return len;
	}

	/* Fallback to in-kernel .BTF section (only set when
	 * CONFIG_DEBUG_INFO_BTF=y, not the case on this build). */
	memcpy(buf, __start_BTF + off, len);
	return len;
}

static struct bin_attribute bin_attr_btf_vmlinux = {
	.attr = { .name = "vmlinux", .mode = 0444, },
	.read = btf_vmlinux_read,
};

static struct kobject *btf_kobj;
static bool btf_sysfs_registered;

static int btf_vmlinux_sysfs_create(u32 size)
{
	int err;

	if (btf_sysfs_registered)
		return 0;

	bin_attr_btf_vmlinux.size = size;

	if (!btf_kobj) {
		btf_kobj = kobject_create_and_add("btf", kernel_kobj);
		if (!btf_kobj)
			return -ENOMEM;
	}

	err = sysfs_create_bin_file(btf_kobj, &bin_attr_btf_vmlinux);
	if (err)
		return err;

	btf_sysfs_registered = true;
	pr_info("btf: /sys/kernel/btf/vmlinux available (%u bytes)\n", size);
	return 0;
}

/* Called from btf_parse_vmlinux() after successful BTF load (in-kernel
 * .BTF section OR FS-loaded buffer). Registers the sysfs entry the first
 * time it's called. */
int ksu_btf_sysfs_register(u32 size)
{
	return btf_vmlinux_sysfs_create(size);
}
EXPORT_SYMBOL_GPL(ksu_btf_sysfs_register);

static int __init btf_vmlinux_init(void)
{
	/* Eager init only when CONFIG_DEBUG_INFO_BTF=y produced a non-empty
	 * .BTF section. On this build the section is empty, so we wait until
	 * btf_parse_vmlinux() loads BTF from FS and calls ksu_btf_sysfs_register(). */
	u64 in_kernel_size = __stop_BTF - __start_BTF;

	if (!__start_BTF || in_kernel_size == 0)
		return 0;

	return btf_vmlinux_sysfs_create((u32)in_kernel_size);
}

subsys_initcall(btf_vmlinux_init);
