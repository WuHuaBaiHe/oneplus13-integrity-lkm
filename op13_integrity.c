// SPDX-License-Identifier: GPL-2.0-only
/*
 * Read-only kernel integrity monitor for the OnePlus SM8750 6.6.118 branch.
 *
 * The load_info declaration mirrors kernel/module/internal.h in the target
 * source. It is intentionally kept local because that header is not exported
 * to external modules.
 */
#include <linux/atomic.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/elf.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>

#define OP13_HASH_SIZE 32
#define OP13_CHECK_INTERVAL (60 * 60 * HZ)
#define OP13_NAME_LEN 64

struct op13_load_info {
	const char *name;
	struct module *mod;
	Elf_Ehdr *hdr;
	unsigned long len;
	Elf_Shdr *sechdrs;
	char *secstrings, *strtab;
	unsigned long symoffs, stroffs, init_typeoffs, core_typeoffs;
	bool sig_ok;
#ifdef CONFIG_KALLSYMS
	unsigned long mod_kallsyms_init_off;
#endif
#ifdef CONFIG_MODULE_DECOMPRESS
#ifdef CONFIG_MODULE_STATS
	unsigned long compressed_len;
#endif
	struct page **pages;
	unsigned int max_pages;
	unsigned int used_pages;
#endif
	struct {
		unsigned int sym, str, mod, vers, info, pcpu;
	} index;
};

typedef unsigned long (*op13_kallsyms_lookup_name_t)(const char *name);

static struct crypto_shash *op13_sha256;
static unsigned long *op13_sys_call_table;
static unsigned long op13_syscall_baseline[__NR_syscalls];
static u8 op13_syscall_hash[OP13_HASH_SIZE];
static bool op13_baseline_ready;
static bool op13_syscall_changed;
static atomic_t op13_module_events = ATOMIC_INIT(0);
static struct delayed_work op13_check_work;
static struct proc_dir_entry *op13_proc_entry;

static int op13_hash(const void *data, size_t len, u8 *out)
{
	SHASH_DESC_ON_STACK(desc, op13_sha256);
	int ret;

	if (!data || !out || IS_ERR_OR_NULL(op13_sha256))
		return -EINVAL;

	desc->tfm = op13_sha256;
	ret = crypto_shash_digest(desc, data, len, out);
	memzero_explicit(desc, sizeof(*desc) + crypto_shash_descsize(op13_sha256));
	return ret;
}

static unsigned long op13_lookup_symbol(const char *name)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};
	op13_kallsyms_lookup_name_t lookup;
	unsigned long address;
	int ret;

	ret = register_kprobe(&kp);
	if (ret)
		return 0;

	lookup = (op13_kallsyms_lookup_name_t)kp.addr;
	address = lookup ? lookup(name) : 0;
	unregister_kprobe(&kp);
	return address;
}

static int op13_check_syscall_table(void)
{
	u8 current_hash[OP13_HASH_SIZE];
	int ret;

	if (!op13_sys_call_table || !op13_baseline_ready)
		return -ENODEV;

	ret = op13_hash(op13_sys_call_table,
			sizeof(op13_syscall_baseline), current_hash);
	if (ret)
		return ret;

	if (memcmp(current_hash, op13_syscall_hash, sizeof(current_hash))) {
		if (!op13_syscall_changed)
			pr_warn("op13_integrity: syscall table hash changed\n");
		op13_syscall_changed = true;
		return -EUCLEAN;
	}

	return 0;
}

static void op13_check_workfn(struct work_struct *work)
{
	op13_check_syscall_table();
	schedule_delayed_work(&op13_check_work, OP13_CHECK_INTERVAL);
}

static char *op13_find_modinfo_name(struct op13_load_info *info)
{
	Elf_Shdr *sections;
	Elf_Shdr *strings;
	char *section_names;
	char *modinfo = NULL;
	unsigned int i;

	if (!info || !info->hdr)
		return NULL;

	sections = (void *)info->hdr + info->hdr->e_shoff;
	if (info->hdr->e_shstrndx >= info->hdr->e_shnum)
		return NULL;

	strings = &sections[info->hdr->e_shstrndx];
	section_names = (void *)info->hdr + strings->sh_offset;
	for (i = 1; i < info->hdr->e_shnum; i++) {
		if (sections[i].sh_name >= strings->sh_size)
			continue;
		if (!strcmp(section_names + sections[i].sh_name, ".modinfo")) {
			modinfo = (void *)info->hdr + sections[i].sh_offset;
			break;
		}
	}

	if (modinfo) {
		unsigned long remaining = sections[i].sh_size;
		while (remaining) {
			unsigned long len = strnlen(modinfo, remaining);
			if (len == remaining)
				break;
			if (len > 5 && !memcmp(modinfo, "name=", 5))
				return modinfo + 5;
			modinfo += len + 1;
			remaining -= len + 1;
		}
	}

	return NULL;
}

static int op13_module_entry(struct kretprobe_instance *instance,
				     struct pt_regs *regs)
{
	struct op13_load_info *info;
	u8 hash[OP13_HASH_SIZE];
	char *name;
	int ret;

	if (!regs)
		return 0;

	info = (struct op13_load_info *)regs_get_kernel_argument(regs, 0);
	if (!info || !info->hdr || !info->len || info->len > ULONG_MAX / 2)
		return 0;

	ret = op13_hash(info->hdr, info->len, hash);
	if (ret)
		return 0;

	name = op13_find_modinfo_name(info);
	if (name)
		pr_info("op13_integrity: module=%.*s sha256=%*phN\n",
			OP13_NAME_LEN, name, OP13_HASH_SIZE, hash);
	else
		pr_info("op13_integrity: module name unavailable sha256=%*phN\n",
			OP13_HASH_SIZE, hash);

	atomic_inc(&op13_module_events);
	return 0;
}

static struct kretprobe op13_module_probe = {
	.kp.symbol_name = "load_module",
	.entry_handler = op13_module_entry,
	.maxactive = 32,
};

static int op13_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "version=oneplus-sm8750-6.6.118\n");
	seq_printf(m, "syscall_table=%s\n",
		   op13_sys_call_table ? "resolved" : "unresolved");
	seq_printf(m, "baseline=%s\n",
		   op13_baseline_ready ? "ready" : "unavailable");
	seq_printf(m, "syscall_table_changed=%s\n",
		   op13_syscall_changed ? "true" : "false");
	seq_printf(m, "module_events=%d\n", atomic_read(&op13_module_events));
	return 0;
}

static int op13_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, op13_proc_show, NULL);
}

static const struct proc_ops op13_proc_ops = {
	.proc_open = op13_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init op13_integrity_init(void)
{
	int ret;

	op13_sha256 = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(op13_sha256))
		return PTR_ERR(op13_sha256);

	op13_sys_call_table = (unsigned long *)op13_lookup_symbol("sys_call_table");
	if (!op13_sys_call_table) {
		pr_err("op13_integrity: sys_call_table not found\n");
		ret = -ENOENT;
		goto free_sha256;
	}

	memcpy(op13_syscall_baseline, op13_sys_call_table,
	       sizeof(op13_syscall_baseline));
	ret = op13_hash(op13_syscall_baseline, sizeof(op13_syscall_baseline),
			op13_syscall_hash);
	if (ret)
		goto free_sha256;
	op13_baseline_ready = true;

	op13_proc_entry = proc_create("op13_integrity", 0444, NULL,
				      &op13_proc_ops);
	if (!op13_proc_entry) {
		ret = -ENOMEM;
		goto free_sha256;
	}

	ret = register_kretprobe(&op13_module_probe);
	if (ret)
		goto remove_proc;

	INIT_DELAYED_WORK(&op13_check_work, op13_check_workfn);
	schedule_delayed_work(&op13_check_work, OP13_CHECK_INTERVAL);
	pr_info("op13_integrity: loaded, syscall baseline ready\n");
	return 0;

remove_proc:
	proc_remove(op13_proc_entry);
	op13_proc_entry = NULL;
free_sha256:
	crypto_free_shash(op13_sha256);
	op13_sha256 = NULL;
	return ret;
}

static void __exit op13_integrity_exit(void)
{
	cancel_delayed_work_sync(&op13_check_work);
	unregister_kretprobe(&op13_module_probe);
	if (op13_proc_entry)
		proc_remove(op13_proc_entry);
	if (op13_sha256)
		crypto_free_shash(op13_sha256);
	pr_info("op13_integrity: unloaded\n");
}

module_init(op13_integrity_init);
module_exit(op13_integrity_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI");
MODULE_DESCRIPTION("Read-only syscall and module-load integrity monitor");
