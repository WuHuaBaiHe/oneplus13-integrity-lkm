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
#include <crypto/hash.h>
#include <linux/delay.h>
#include <linux/elf.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>

#define OP13_HASH_SIZE 32
#define OP13_CHECK_INTERVAL (60 * 60 * HZ)
#define OP13_NAME_LEN 64
#define OP13_MAX_MODULE_IMAGE (16UL * 1024 * 1024)
#define OP13_MAX_WHITELIST 128
#define OP13_MAX_EVENTS 10
#define OP13_EVENT_FLAG 10000

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
static struct workqueue_struct *op13_module_wq;
static struct proc_dir_entry *op13_proc_entry;
static struct proc_dir_entry *op13_ko_entry;
static struct proc_dir_entry *op13_systbl_entry;
static struct proc_dir_entry *op13_status_entry;
static DEFINE_MUTEX(op13_state_lock);
static bool op13_status_ready;

struct op13_whitelist_entry {
	bool valid;
	char name[OP13_NAME_LEN];
	u8 hash[OP13_HASH_SIZE];
};

struct op13_module_event {
	bool valid;
	bool allowed;
	char name[OP13_NAME_LEN];
	u8 hash[OP13_HASH_SIZE];
	unsigned long stamp;
};

struct op13_syscall_event {
	bool valid;
	unsigned long stamp;
	u8 hash[OP13_HASH_SIZE];
};

static struct op13_whitelist_entry op13_whitelist[OP13_MAX_WHITELIST];
static struct op13_module_event op13_module_log[OP13_MAX_EVENTS];
static struct op13_syscall_event op13_syscall_log[OP13_MAX_EVENTS];
static unsigned int op13_whitelist_count;
static unsigned int op13_module_log_next;
static unsigned int op13_module_log_count;
static unsigned int op13_syscall_log_next;
static unsigned int op13_syscall_log_count;

struct op13_module_work {
	struct work_struct work;
	void *image;
	size_t len;
};

static __nocfi unsigned long op13_call_lookup(kprobe_opcode_t *addr,
						const char *name)
{
	op13_kallsyms_lookup_name_t lookup =
		(op13_kallsyms_lookup_name_t)addr;

	return lookup ? lookup(name) : 0;
}

static int op13_hash(const void *data, size_t len, u8 *out)
{
	SHASH_DESC_ON_STACK(desc, op13_sha256);
	int ret;

	if (!data || !out || IS_ERR_OR_NULL(op13_sha256) || len > UINT_MAX)
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
	unsigned long address;
	int ret;

	ret = register_kprobe(&kp);
	if (ret)
		return 0;

	address = kp.addr ? op13_call_lookup(kp.addr, name) : 0;
	unregister_kprobe(&kp);
	return address;
}

static void op13_hash_to_hex(const u8 *hash, char *out)
{
	static const char hex[] = "0123456789abcdef";
	unsigned int i;

	for (i = 0; i < OP13_HASH_SIZE; i++) {
		out[i * 2] = hex[hash[i] >> 4];
		out[i * 2 + 1] = hex[hash[i] & 0xf];
	}
	out[OP13_HASH_SIZE * 2] = '\0';
}

static int op13_hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int op13_parse_hash(const char *text, u8 *hash)
{
	unsigned int i;
	int high, low;

	if (strlen(text) != OP13_HASH_SIZE * 2)
		return -EINVAL;
	for (i = 0; i < OP13_HASH_SIZE; i++) {
		high = op13_hex_value(text[i * 2]);
		low = op13_hex_value(text[i * 2 + 1]);
		if (high < 0 || low < 0)
			return -EINVAL;
		hash[i] = (high << 4) | low;
	}
	return 0;
}

static bool op13_is_whitelisted(const char *name, const u8 *hash)
{
	unsigned int i;
	bool allowed = false;

	mutex_lock(&op13_state_lock);
	for (i = 0; i < OP13_MAX_WHITELIST; i++) {
		if (op13_whitelist[i].valid &&
		    !strcmp(op13_whitelist[i].name, name) &&
		    !memcmp(op13_whitelist[i].hash, hash, OP13_HASH_SIZE)) {
			allowed = true;
			break;
		}
	}
	mutex_unlock(&op13_state_lock);
	return allowed;
}

static void op13_record_module_event(const char *name, const u8 *hash,
					     bool allowed)
{
	struct op13_module_event *event;

	mutex_lock(&op13_state_lock);
	event = &op13_module_log[op13_module_log_next];
	event->valid = true;
	event->allowed = allowed;
	strscpy(event->name, name, sizeof(event->name));
	memcpy(event->hash, hash, OP13_HASH_SIZE);
	event->stamp = jiffies;
	op13_module_log_next = (op13_module_log_next + 1) % OP13_MAX_EVENTS;
	if (op13_module_log_count < OP13_MAX_EVENTS)
		op13_module_log_count++;
	mutex_unlock(&op13_state_lock);
}

static void op13_record_syscall_event(const u8 *hash)
{
	struct op13_syscall_event *event;

	mutex_lock(&op13_state_lock);
	event = &op13_syscall_log[op13_syscall_log_next];
	event->valid = true;
	memcpy(event->hash, hash, OP13_HASH_SIZE);
	event->stamp = jiffies;
	op13_syscall_log_next = (op13_syscall_log_next + 1) % OP13_MAX_EVENTS;
	if (op13_syscall_log_count < OP13_MAX_EVENTS)
		op13_syscall_log_count++;
	mutex_unlock(&op13_state_lock);
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
		if (!op13_syscall_changed) {
			op13_record_syscall_event(current_hash);
			pr_warn("op13_integrity: syscall table hash changed flag=%d\n",
				OP13_EVENT_FLAG);
		}
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

static char *op13_find_modinfo_name(void *image, size_t image_len)
{
	Elf_Ehdr *hdr = image;
	Elf_Shdr *sections;
	Elf_Shdr *strings;
	char *section_names;
	unsigned long table_len;
	unsigned int i;

	if (!image || image_len < sizeof(*hdr) ||
	    hdr->e_shentsize != sizeof(Elf_Shdr) || !hdr->e_shnum ||
	    hdr->e_shstrndx >= hdr->e_shnum || hdr->e_shoff > image_len ||
	    check_mul_overflow((unsigned long)hdr->e_shnum,
				(unsigned long)hdr->e_shentsize, &table_len) ||
	    table_len > image_len - hdr->e_shoff)
		return NULL;

	sections = (void *)hdr + hdr->e_shoff;
	strings = &sections[hdr->e_shstrndx];
	if (strings->sh_offset > image_len ||
	    strings->sh_size > image_len - strings->sh_offset ||
	    !strings->sh_size)
		return NULL;
	section_names = (void *)hdr + strings->sh_offset;

	for (i = 1; i < hdr->e_shnum; i++) {
		Elf_Shdr *section = &sections[i];
		size_t name_len;

		if (section->sh_offset > image_len ||
		    section->sh_size > image_len - section->sh_offset ||
		    section->sh_name >= strings->sh_size)
			continue;
		name_len = strnlen(section_names + section->sh_name,
				   strings->sh_size - section->sh_name);
		if (name_len == strings->sh_size - section->sh_name ||
		    strcmp(section_names + section->sh_name, ".modinfo"))
			continue;

		{
			char *modinfo = (void *)hdr + section->sh_offset;
			size_t remaining = section->sh_size;

			while (remaining) {
				size_t len = strnlen(modinfo, remaining);

				if (len == remaining)
					break;
				if (len > 5 && !memcmp(modinfo, "name=", 5))
					return modinfo + 5;
				modinfo += len + 1;
				remaining -= len + 1;
			}
		}
		break;
	}

	return NULL;
}

static int op13_module_entry(struct kretprobe_instance *instance,
				     struct pt_regs *regs)
{
	struct op13_load_info *info;
	struct op13_module_work *event;

	if (!regs || !instance)
		return 0;
	*(struct op13_module_work **)instance->data = NULL;
	info = (struct op13_load_info *)regs_get_kernel_argument(regs, 0);
	if (!info || !info->hdr || info->len < sizeof(Elf_Ehdr) ||
	    info->len > OP13_MAX_MODULE_IMAGE)
		return 0;
	event = kmalloc(sizeof(*event), GFP_ATOMIC);
	if (!event)
		return 0;
	event->image = kvmalloc(info->len, GFP_ATOMIC);
	if (!event->image) {
		kfree(event);
		return 0;
	}
	memcpy(event->image, info->hdr, info->len);
	event->len = info->len;
	*(struct op13_module_work **)instance->data = event;
	return 0;
}

static void op13_module_workfn(struct work_struct *work)
{
	struct op13_module_work *event = container_of(work,
						      struct op13_module_work, work);
	u8 hash[OP13_HASH_SIZE];
	char *name;
	char name_buf[OP13_NAME_LEN];
	bool allowed = false;

	if (!op13_hash(event->image, event->len, hash)) {
		name = op13_find_modinfo_name(event->image, event->len);
		if (name)
			strscpy(name_buf, name, sizeof(name_buf));
		else
			strscpy(name_buf, "<unknown>", sizeof(name_buf));
		allowed = op13_is_whitelisted(name_buf, hash);
		op13_record_module_event(name_buf, hash, allowed);
		pr_info("op13_integrity: module=%s sha256=%*phN allowed=%s flag=%d\n",
			name_buf, OP13_HASH_SIZE, hash, allowed ? "true" : "false",
			OP13_EVENT_FLAG);
		atomic_inc(&op13_module_events);
	}
	kvfree(event->image);
	kfree(event);
}

static int op13_module_return(struct kretprobe_instance *instance,
				      struct pt_regs *regs)
{
	struct op13_module_work *event;

	if (!instance)
		return 0;
	event = *(struct op13_module_work **)instance->data;
	if (!event)
		return 0;
	INIT_WORK(&event->work, op13_module_workfn);
	queue_work(op13_module_wq, &event->work);
	return 0;
}

static struct kretprobe op13_module_probe = {
	.kp.symbol_name = "load_module",
	.entry_handler = op13_module_entry,
	.handler = op13_module_return,
	.data_size = sizeof(struct op13_module_work *),
	.maxactive = 32,
};

static int op13_ko_show(struct seq_file *m, void *v)
{
	unsigned int i;
	char hex[OP13_HASH_SIZE * 2 + 1];

	mutex_lock(&op13_state_lock);
	seq_printf(m, "count=%u max=%u flag=%d\n", op13_whitelist_count,
		   OP13_MAX_WHITELIST, OP13_EVENT_FLAG);
	for (i = 0; i < OP13_MAX_WHITELIST; i++) {
		if (!op13_whitelist[i].valid)
			continue;
		op13_hash_to_hex(op13_whitelist[i].hash, hex);
		seq_printf(m, "%s %s\n", op13_whitelist[i].name, hex);
	}
	mutex_unlock(&op13_state_lock);
	return 0;
}

static int op13_systbl_show(struct seq_file *m, void *v)
{
	unsigned int i;
	char hex[OP13_HASH_SIZE * 2 + 1];

	mutex_lock(&op13_state_lock);
	seq_printf(m, "changed=%s count=%u max=%u flag=%d\n",
		   op13_syscall_changed ? "true" : "false",
		   op13_syscall_log_count, OP13_MAX_EVENTS, OP13_EVENT_FLAG);
	for (i = 0; i < OP13_MAX_EVENTS; i++) {
		if (!op13_syscall_log[i].valid)
			continue;
		op13_hash_to_hex(op13_syscall_log[i].hash, hex);
		seq_printf(m, "jiffies=%lu sha256=%s\n",
			   op13_syscall_log[i].stamp, hex);
	}
	mutex_unlock(&op13_state_lock);
	return 0;
}

static int op13_status_show(struct seq_file *m, void *v)
{
	mutex_lock(&op13_state_lock);
	seq_printf(m, "status=%s\n", op13_status_ready ? "ready" : "pending");
	seq_printf(m, "syscall_table_changed=%s\n",
		   op13_syscall_changed ? "true" : "false");
	mutex_unlock(&op13_state_lock);
	return 0;
}

static int op13_ko_open(struct inode *inode, struct file *file)
{
	return single_open(file, op13_ko_show, NULL);
}

static int op13_systbl_open(struct inode *inode, struct file *file)
{
	return single_open(file, op13_systbl_show, NULL);
}

static int op13_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, op13_status_show, NULL);
}

static ssize_t op13_ko_write(struct file *file, const char __user *buffer,
				     size_t count, loff_t *ppos)
{
	char *line, *trimmed, name[OP13_NAME_LEN], hash_text[OP13_HASH_SIZE * 2 + 1];
	u8 hash[OP13_HASH_SIZE];
	unsigned int i;
	int ret;

	if (!count || count > 256)
		return -EINVAL;
	line = memdup_user_nul(buffer, count);
	if (IS_ERR(line))
		return PTR_ERR(line);
	trimmed = strim(line);
	if (!strcmp(trimmed, "clear")) {
		mutex_lock(&op13_state_lock);
		memset(op13_whitelist, 0, sizeof(op13_whitelist));
		op13_whitelist_count = 0;
		mutex_unlock(&op13_state_lock);
		kfree(line);
		return count;
	}
	ret = sscanf(trimmed, "%63s %64s", name, hash_text);
	if (ret != 2 || op13_parse_hash(hash_text, hash)) {
		kfree(line);
		return -EINVAL;
	}
	mutex_lock(&op13_state_lock);
	for (i = 0; i < OP13_MAX_WHITELIST; i++) {
		if (op13_whitelist[i].valid && !strcmp(op13_whitelist[i].name, name))
			break;
	}
	if (i == OP13_MAX_WHITELIST) {
		for (i = 0; i < OP13_MAX_WHITELIST; i++)
			if (!op13_whitelist[i].valid)
				break;
	}
	if (i == OP13_MAX_WHITELIST) {
		mutex_unlock(&op13_state_lock);
		kfree(line);
		return -ENOSPC;
	}
	if (!op13_whitelist[i].valid)
		op13_whitelist_count++;
	op13_whitelist[i].valid = true;
	strscpy(op13_whitelist[i].name, name, sizeof(op13_whitelist[i].name));
	memcpy(op13_whitelist[i].hash, hash, sizeof(hash));
	mutex_unlock(&op13_state_lock);
	kfree(line);
	return count;
}

static ssize_t op13_clear_write(struct file *file, const char __user *buffer,
					size_t count, loff_t *ppos)
{
	char *line, *trimmed;

	if (!count || count > 32)
		return -EINVAL;
	line = memdup_user_nul(buffer, count);
	if (IS_ERR(line))
		return PTR_ERR(line);
	trimmed = strim(line);
	if (strcmp(trimmed, "clear")) {
		kfree(line);
		return -EINVAL;
	}
	mutex_lock(&op13_state_lock);
	memset(op13_syscall_log, 0, sizeof(op13_syscall_log));
	op13_syscall_log_count = 0;
	op13_syscall_log_next = 0;
	mutex_unlock(&op13_state_lock);
	kfree(line);
	return count;
}

static ssize_t op13_status_write(struct file *file, const char __user *buffer,
					size_t count, loff_t *ppos)
{
	char *line, *trimmed;
	bool ready;

	if (!count || count > 32)
		return -EINVAL;
	line = memdup_user_nul(buffer, count);
	if (IS_ERR(line))
		return PTR_ERR(line);
	trimmed = strim(line);
	if (kstrtobool(trimmed, &ready)) {
		kfree(line);
		return -EINVAL;
	}
	mutex_lock(&op13_state_lock);
	op13_status_ready = ready;
	mutex_unlock(&op13_state_lock);
	kfree(line);
	return count;
}

static const struct proc_ops op13_ko_ops = {
	.proc_open = op13_ko_open,
	.proc_read = seq_read,
	.proc_write = op13_ko_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops op13_systbl_ops = {
	.proc_open = op13_systbl_open,
	.proc_read = seq_read,
	.proc_write = op13_clear_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops op13_status_ops = {
	.proc_open = op13_status_open,
	.proc_read = seq_read,
	.proc_write = op13_status_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int op13_proc_show(struct seq_file *m, void *v)
{
	mutex_lock(&op13_state_lock);
	seq_printf(m, "version=oneplus-sm8750-6.6.118\n");
	seq_printf(m, "syscall_table=%s\n",
		   op13_sys_call_table ? "resolved" : "unresolved");
	seq_printf(m, "baseline=%s\n",
		   op13_baseline_ready ? "ready" : "unavailable");
	seq_printf(m, "syscall_table_changed=%s\n",
		   op13_syscall_changed ? "true" : "false");
	seq_printf(m, "module_events=%d\n", atomic_read(&op13_module_events));
	seq_printf(m, "module_event_log=%u/%u\n",
		   op13_module_log_count, OP13_MAX_EVENTS);
	seq_printf(m, "whitelist=%u/%u\n",
		   op13_whitelist_count, OP13_MAX_WHITELIST);
	seq_printf(m, "status=%s\n", op13_status_ready ? "ready" : "pending");
	mutex_unlock(&op13_state_lock);
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

	op13_module_wq = alloc_workqueue("op13_integrity",
					WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!op13_module_wq) {
		ret = -ENOMEM;
		goto free_sha256;
	}

	op13_proc_entry = proc_create("op13_integrity", 0444, NULL,
				      &op13_proc_ops);
	op13_ko_entry = proc_create("inte_ko", 0600, NULL, &op13_ko_ops);
	op13_systbl_entry = proc_create("inte_systbl", 0600, NULL,
					&op13_systbl_ops);
	op13_status_entry = proc_create("inte_status", 0600, NULL,
					&op13_status_ops);
	if (!op13_proc_entry || !op13_ko_entry || !op13_systbl_entry ||
	    !op13_status_entry) {
		ret = -ENOMEM;
		goto remove_compat_proc;
	}

	ret = register_kretprobe(&op13_module_probe);
	if (ret)
		goto remove_compat_proc;

	mutex_lock(&op13_state_lock);
	op13_status_ready = true;
	mutex_unlock(&op13_state_lock);
	INIT_DELAYED_WORK(&op13_check_work, op13_check_workfn);
	schedule_delayed_work(&op13_check_work, OP13_CHECK_INTERVAL);
	pr_info("op13_integrity: loaded, syscall baseline ready\n");
	return 0;

remove_compat_proc:
	if (op13_status_entry)
		proc_remove(op13_status_entry);
	op13_status_entry = NULL;
	if (op13_systbl_entry)
		proc_remove(op13_systbl_entry);
	op13_systbl_entry = NULL;
	if (op13_ko_entry)
		proc_remove(op13_ko_entry);
	op13_ko_entry = NULL;
remove_proc:
	if (op13_proc_entry)
		proc_remove(op13_proc_entry);
	op13_proc_entry = NULL;
destroy_workqueue:
	destroy_workqueue(op13_module_wq);
	op13_module_wq = NULL;
free_sha256:
	crypto_free_shash(op13_sha256);
	op13_sha256 = NULL;
	return ret;
}

static void __exit op13_integrity_exit(void)
{
	cancel_delayed_work_sync(&op13_check_work);
	unregister_kretprobe(&op13_module_probe);
	if (op13_status_entry)
		proc_remove(op13_status_entry);
	if (op13_systbl_entry)
		proc_remove(op13_systbl_entry);
	if (op13_ko_entry)
		proc_remove(op13_ko_entry);
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
MODULE_DESCRIPTION("Syscall and module-load integrity monitor with original-style whitelist interfaces");
