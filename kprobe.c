#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/time.h>

static int pid = 495;
module_param(pid,int,S_IRUGO);
#define MAX_SYMBOL_LEN  64
static char symbol[MAX_SYMBOL_LEN] = "handle_mm_fault";
module_param_string(symbol, symbol, sizeof(symbol), 0644);
struct timespec ts;

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
                .symbol_name    = symbol,
};



/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
                if(current->pid == pid) //to determine target pid is obtained due to page fault
                {
                getnstimeofday(&ts);
                pr_info("<%s> pre_handler: pid = %d,  %ld, flags = 0x%lx , %ld \n",
                                                p->symbol_name, current->pid, regs->si, regs->flags,ts.tv_nsec);
#endif
                }
                        /* A dump_stack() here will give a stack backtrace */
                        return 0;
}


/*
 *  * fault_handler: this is called if an exception is generated for any
 *   * instruction within the pre- or post-handler, or when Kprobes
 *    * single-steps the probed instruction.
 *     */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
                pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
                        /* Return 0 because we don't handle the fault. */
                        return 0;
}


static int __init kprobe_init(void)
{
                int ret;
                        kp.pre_handler = handler_pre;
                                kp.post_handler = NULL;
                                        kp.fault_handler = handler_fault;

                                                ret = register_kprobe(&kp);
                                                        if (ret < 0) {
                                                                                pr_err("register_kprobe failed, returned %d\n", ret);
                                                                                                return ret;
                                                                                                        }
                                                                pr_info("Planted kprobe at %p\n", kp.addr);
                                                                        return 0;
}

static void __exit kprobe_exit(void)
{
                unregister_kprobe(&kp);
                        pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
        module_exit(kprobe_exit)
        MODULE_LICENSE("GPL");
                                      