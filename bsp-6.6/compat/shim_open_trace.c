// SPDX-License-Identifier: GPL-2.0-only
/* H30 diagnostic interposers. tools/wl_opentrace.py redirects only the
 * guarded CALL sites below. LR is the original caller's text address even
 * through an ARM module PLT. No guessed runtime address or skipped call.
 * Remove the blob trace patch to disable these otherwise dormant exports. */
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include "shim_skb.h"
#include "shim_skb_layout.h"

/* Only change_virtual_iface CALL relocations opt into these wrappers.
 * Native primitives still perform every lock/unlock, with unchanged flags.
 * The RAM lock word and return site identify a blocked acquisition. */
noinline void bcm_shim_ap_mutex_lock(struct mutex *lock)
{
 pr_info("H30_AP mutex enter caller=%pS lock=%px owner=%lx\n",
  __builtin_return_address(0), lock, atomic_long_read(&lock->owner));
 mutex_lock(lock);
 pr_info("H30_AP mutex acquired\n");
}
EXPORT_SYMBOL(bcm_shim_ap_mutex_lock);

noinline void bcm_shim_ap_mutex_unlock(struct mutex *lock)
{
 mutex_unlock(lock);
 pr_info("H30_AP mutex released\n");
}
EXPORT_SYMBOL(bcm_shim_ap_mutex_unlock);

noinline unsigned long bcm_shim_ap_spin_lock(raw_spinlock_t *lock)
{
 unsigned long flags;
 pr_info("H30_AP spin enter caller=%pS lock=%px word=%08x\n",
  __builtin_return_address(0), lock, READ_ONCE(*(u32 *)lock));
 raw_spin_lock_irqsave(lock, flags);
 pr_info("H30_AP spin acquired caller=%pS\n", __builtin_return_address(0));
 return flags;
}
EXPORT_SYMBOL(bcm_shim_ap_spin_lock);

noinline void bcm_shim_ap_spin_unlock(raw_spinlock_t *lock, unsigned long flags)
{
 raw_spin_unlock_irqrestore(lock, flags);
 pr_info("H30_AP spin released caller=%pS\n", __builtin_return_address(0));
}
EXPORT_SYMBOL(bcm_shim_ap_spin_unlock);

static bool ap_ioctl_trace;
module_param(ap_ioctl_trace, bool, 0600);

/* Trace the common get/set front doors, after attach when explicitly enabled.
 * ioctl request geometry is the blob's own 24-byte stack object. Never log
 * request values (they can contain key material); iovar names stop at NUL. */
#define TRACE_AP_IOCTL(label, site) \
noinline int bcm_shim_ap_ioctl_##label(void *dev, u32 *req, u32 cmd) \
{ \
 unsigned long caller = (unsigned long)__builtin_return_address(0); \
 int (*original)(void *, u32 *, u32) = (void *)(caller - ((site) + 4) + 0x3114f4); \
 int ret; \
 if (ap_ioctl_trace) { \
  pr_info("H30_AP ioctl " #label " enter cmd=%u len=%u\n", cmd, req[2]); \
  if ((cmd == 262 || cmd == 263) && req[1] && req[2]) \
   pr_info("H30_AP iovar name=%.*s\n", (int)min_t(u32, req[2], 32), (char *)req[1]); \
 } \
 ret = original(dev, req, cmd); \
 if (ap_ioctl_trace) pr_info("H30_AP ioctl " #label " exit cmd=%u rc=%d\n", cmd, ret); \
 return ret; \
} \
EXPORT_SYMBOL(bcm_shim_ap_ioctl_##label)
TRACE_AP_IOCTL(63b294, 0x63b294);
TRACE_AP_IOCTL(63b2cc, 0x63b2cc);
TRACE_AP_IOCTL(63b380, 0x63b380);
TRACE_AP_IOCTL(63b3fc, 0x63b3fc);
TRACE_AP_IOCTL(63b4a4, 0x63b4a4);
TRACE_AP_IOCTL(63b514, 0x63b514);
TRACE_AP_IOCTL(63b5bc, 0x63b5bc);
TRACE_AP_IOCTL(63b674, 0x63b674);
TRACE_AP_IOCTL(63b8cc, 0x63b8cc);
TRACE_AP_IOCTL(63b918, 0x63b918);
TRACE_AP_IOCTL(63b968, 0x63b968);
TRACE_AP_IOCTL(63ba98, 0x63ba98);
TRACE_AP_IOCTL(63bc10, 0x63bc10);
TRACE_AP_IOCTL(63bd68, 0x63bd68);
TRACE_AP_IOCTL(63bec4, 0x63bec4);
TRACE_AP_IOCTL(63bfe4, 0x63bfe4);
TRACE_AP_IOCTL(63c0fc, 0x63c0fc);
TRACE_AP_IOCTL(63c230, 0x63c230);
TRACE_AP_IOCTL(63c2f0, 0x63c2f0);
TRACE_AP_IOCTL(63c358, 0x63c358);
TRACE_AP_IOCTL(63c3bc, 0x63c3bc);
TRACE_AP_IOCTL(63c404, 0x63c404);
TRACE_AP_IOCTL(63c45c, 0x63c45c);
TRACE_AP_IOCTL(63c4a0, 0x63c4a0);
TRACE_AP_IOCTL(63c518, 0x63c518);

noinline int bcm_shim_ap_trylock_bh(raw_spinlock_t *lock)
{
 int ret = raw_spin_trylock_bh(lock);
 if (ap_ioctl_trace) {
  if (ret)
   pr_info("H30_AP ioctl lock acquired word=%08x\n", READ_ONCE(*(u32 *)lock));
  else
   pr_info_ratelimited("H30_AP ioctl lock busy word=%08x\n", READ_ONCE(*(u32 *)lock));
 }
 return ret;
}
EXPORT_SYMBOL(bcm_shim_ap_trylock_bh);

#define TRACE_VOID(n, site, target, label) \
noinline void bcm_shim_open_trace_##n(void *arg) \
{ \
	unsigned long caller = (unsigned long)__builtin_return_address(0); \
	void (*original)(void *) = (void *)(caller - ((site) + 4) + (target)); \
	pr_info("H30_OPEN " label " enter\n"); \
	original(arg); \
	pr_info("H30_OPEN " label " exit\n"); \
} \
EXPORT_SYMBOL(bcm_shim_open_trace_##n)

TRACE_VOID(0, 0x340c00, 0x4d0be4, "mlo_init_down");
TRACE_VOID(1, 0x341474, 0x46258c, "led_init");
TRACE_VOID(2, 0x34147c, 0x3b64d4, "bmac_hw_up");
TRACE_VOID(4, 0x340d70, 0x30ffdc, "wl_init");
TRACE_VOID(5, 0x340d84, 0x3b8c10, "bmac_up_finish");

noinline int bcm_shim_open_trace_3(void *arg)
{
	unsigned long caller = (unsigned long)__builtin_return_address(0);
	int (*original)(void *) = (void *)(caller - 0x340cf0 + 0x3cbbe8);
	int ret;

	pr_info("H30_OPEN bmac_up_prep enter\n");
	ret = original(arg);
	pr_info("H30_OPEN bmac_up_prep exit rc=%d\n", ret);
	return ret;
}
EXPORT_SYMBOL(bcm_shim_open_trace_3);

/* HND functions are in a separate loaded module. run_open reads its .text
 * from sysfs after loading hnd/wl (wl holds hnd), then sets this diagnostic
 * parameter. All audited calls use AAPCS r0-r3, no stack/FP arguments.
 * Preserve the return register even for sites whose caller ignores it. */
static unsigned long open_trace_hnd_text;
module_param(open_trace_hnd_text, ulong, 0600);
MODULE_PARM_DESC(open_trace_hnd_text, "H30 only: loaded hnd .text from module sysfs");

/* Only dma_rxfill@259a48 opts in. Stock dma_rxreclaim@25a880 returns
 * packets to pktpool_free without undoing its previous headroom pull.
 * Restore the owned buffer geometry before the next DMA posting. */
noinline struct skb419_view *bcm_shim_ap_rx_pool_get(void *pool, u32 type, u32 flags)
{
	struct skb419_view *(*get)(void *, u32, u32);
	struct skb419_view *skb;
	static atomic_t calls = ATOMIC_INIT(0);
	u16 len;
	int ret, n;
	if (!open_trace_hnd_text || !pool ||
	    copy_from_kernel_nofault(&len, (u8 *)pool + 14, sizeof(len)) ||
	    !len || len > 16384)
		return NULL;
	get = (void *)(open_trace_hnd_text + 0x14ad8);
	skb = get(pool, type, flags);
	if (!skb)
		return NULL;
	ret = shim_skb_pool_reset(skb, 64, len);
	if (ret) {
		pr_err_ratelimited("H30_RX_POOL reset refused rc=%d skb=%px retained\n", ret, skb);
		return NULL;
	}
	n = atomic_inc_return(&calls);
	if (n <= 4 || !(n % 65536))
		pr_info("H30_RX_POOL reset=%d len=%u headroom=64\n", n, len);
	return skb;
}
EXPORT_SYMBOL(bcm_shim_ap_rx_pool_get);

noinline void bcm_shim_ap_rx_free(void *osh, struct skb419_view *skb,
				 unsigned int send, void *caller)
{
	static atomic_t count = ATOMIC_INIT(0);
	void (*original)(void *, struct skb419_view *, unsigned int, void *);
	int n = atomic_inc_return(&count);
	if (!open_trace_hnd_text) {
		pr_err("H30_RX missing hnd base; free refused\n");
		return;
	}
	if (n <= 24 && shim_skb_is_legacy(skb)) {
		u8 *data, *head, *end;
		u32 len, words[2] = { 0, 0 };
		memcpy(&data, (u8 *)skb + SK419_off_sk_buff_data, sizeof(data));
		memcpy(&head, (u8 *)skb + SK419_off_sk_buff_head, sizeof(head));
		memcpy(&end, (u8 *)skb + SK419_off_sk_buff_end, sizeof(end));
		memcpy(&len, (u8 *)skb + SK419_off_sk_buff_len, sizeof(len));
		if (data >= head && end >= data && end - data >= sizeof(words))
			copy_from_kernel_nofault(words, data, sizeof(words));
		pr_info("H30_RX free=%d caller=%pS skb=%px data=%px len=%u first=%08x/%08x send=%u\n",
			n, __builtin_return_address(0), skb, data, len, words[0], words[1], send);
	}
	original = (void *)(open_trace_hnd_text + 0x1aec0);
	original(osh, skb, send, caller);
}
EXPORT_SYMBOL(bcm_shim_ap_rx_free);

noinline u64 bcm_shim_ap_rx_phys(void *osh, void *va)
{
	static atomic_t count = ATOMIC_INIT(0);
	u64 (*original)(void *, void *);
	u64 pa;
	int n = atomic_inc_return(&count);
	if (!open_trace_hnd_text)
		return ~0ULL;
	original = (void *)(open_trace_hnd_text + 0x19c08);
	pa = original(osh, va);
	if (n <= 8)
		pr_info("H30_RX phys=%d caller=%pS va=%px old_pa=%llx native_pa=%llx valid=%d\n",
			n, __builtin_return_address(0), va, pa,
			virt_addr_valid(va) ? (u64)virt_to_phys(va) : ~0ULL, virt_addr_valid(va));
	return pa;
}
EXPORT_SYMBOL(bcm_shim_ap_rx_phys);

#define TRACE_HND(n, offset, label) \
noinline u32 bcm_shim_open_trace_##n(u32 a, u32 b, u32 c, u32 d) \
{ \
 u32 (*original)(u32, u32, u32, u32); \
 u32 ret; \
 if (!open_trace_hnd_text) { \
  pr_err("H30_OPEN missing hnd base\n"); \
  return (u32)-ENODEV; \
 } \
 original = (void *)(open_trace_hnd_text + (offset)); \
 pr_info("H30_OPEN " label " enter\n"); \
 ret = original(a, b, c, d); \
 pr_info("H30_OPEN " label " exit r0=%x\n", ret); \
 return ret; \
} \
EXPORT_SYMBOL(bcm_shim_open_trace_##n)
TRACE_HND(6, 0x210bc, "si_clkctl_xtal@3b6514");
TRACE_HND(7, 0x20ea4, "si_clkctl_init@3b6524");
/* The first GPIO call stalls in ai_corereg. Snapshot SI-owned RAM only;
 * leave all MMIO reads/writes to the original function. */
noinline u32 bcm_shim_open_trace_8(u32 a, u32 b, u32 c, u32 d)
{
 u32 *si = (void *)a;
 u32 *table = (void *)READ_ONCE(si[45]);
 u32 (*original)(u32, u32, u32, u32);
 u32 ret;

 if (!open_trace_hnd_text || !table)
  return (u32)-ENODEV;
 pr_info("H30_GPIO si=%08x bus=%u chip=%x enum=%08x va=%08x bp=%08x cur=%u cores=%u regs0=%08x id0=%x as0=%08x mask=%x val=%x priority=%x\n",
  a, si[1], si[16], si[25], si[26], si[27], si[41], si[42],
  table[0], table[32], table[64], b, c, d);
 original = (void *)(open_trace_hnd_text + 0x2226c);
 pr_info("H30_OPEN si_gpiocontrol@3b6584 enter\n");
 ret = original(a, b, c, d);
 pr_info("H30_OPEN si_gpiocontrol@3b6584 exit r0=%x\n", ret);
 return ret;
}
EXPORT_SYMBOL(bcm_shim_open_trace_8);
TRACE_HND(9, 0x2256c, "si_gpioled@3b659c");
TRACE_HND(10, 0x2233c, "si_gpioout@3b65f4");
TRACE_HND(11, 0x222d4, "si_gpioouten@3b6608");
TRACE_HND(12, 0x225b4, "si_gpiopull@3b6620");
TRACE_HND(13, 0x225b4, "si_gpiopull@3b6634");
TRACE_HND(14, 0x16aec, "si_pmu_chipcontrol@3b6690");
TRACE_HND(15, 0x16aec, "si_pmu_chipcontrol@3b66b0");
TRACE_HND(16, 0x2226c, "si_gpiocontrol@3b66f4");
TRACE_HND(17, 0x222d4, "si_gpioouten@3b6708");
TRACE_HND(18, 0x2233c, "si_gpioout@3b671c");
TRACE_HND(19, 0x210bc, "si_clkctl_xtal@3b6760");
TRACE_HND(20, 0x210bc, "si_clkctl_xtal@3b67a8");
TRACE_HND(21, 0x2233c, "si_gpioout@3b67d8");
TRACE_HND(22, 0x222d4, "si_gpioouten@3b67f0");
TRACE_HND(23, 0x2421c, "si_btcgpiowar@3b6868");
TRACE_HND(24, 0x220d8, "si_pci_fixcfg@3b6884");
TRACE_HND(25, 0x173b4, "si_pmu_res_init@3b689c");

/* Cubby callbacks take (context, object). The audited BLX r2/r3 sites
 * already carry the function pointer in a scratch argument register. */
noinline void bcm_shim_ap_cubby_deinit(void *ctx, void *obj,
                                     void (*fn)(void *, void *))
{
 if (ap_ioctl_trace) pr_info("H30_AP cubby deinit %ps enter\n", fn);
 fn(ctx, obj);
 if (ap_ioctl_trace) pr_info("H30_AP cubby deinit %ps exit\n", fn);
}
EXPORT_SYMBOL(bcm_shim_ap_cubby_deinit);

noinline int bcm_shim_ap_cubby_init(void *ctx, void *obj, u32 unused,
                                  int (*fn)(void *, void *))
{
 int result;
 if (ap_ioctl_trace) pr_info("H30_AP cubby init %ps enter\n", fn);
 result = fn(ctx, obj);
 if (ap_ioctl_trace) pr_info("H30_AP cubby init %ps exit %d\n", fn, result);
 return result;
}
EXPORT_SYMBOL(bcm_shim_ap_cubby_init);
#include "shim_ap_reinit_trace.h"
