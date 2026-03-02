// SPDX-License-Identifier: GPL-2.0
/*
 * JARVIS AI Kernel Integration Driver - DIBS client
 *
 * Registers JARVIS as a DIBS (Direct Internal Buffer Sharing) client so the
 * AI daemon can register pre-allocated DMBs (Direct Memory Buffers) for
 * zero-copy transfer of large inference payloads.
 *
 * Usage model
 * -----------
 * 1. The AI daemon registers a DMB via JARVIS_IOC_DIBS_REG, providing its
 *    DIBS token and buffer length.  The driver stores it in a slot table and
 *    returns the slot index.
 *
 * 2. When a kernel caller wants to supply a large blob to the AI it can call
 *    jarvis_dibs_write_slot(slot, data, len) to DMA the data directly into
 *    the pre-registered DMB buffer, avoiding a user-copy.
 *
 * 3. The daemon reads from the DMB via its own memory-mapped view and signals
 *    completion back through the normal JARVIS_IOC_RESPOND path.
 *
 * Copyright (c) 2025 JARVISos Contributors
 */
#define pr_fmt(fmt) "jarvis-dibs: " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/dibs.h>
#include <linux/uaccess.h>

#include <uapi/linux/jarvis.h>
#include "jarvis_dibs.h"

#define JARVIS_DIBS_MAX_SLOTS   8

struct jarvis_dmb_slot {
	bool             used;
	struct dibs_dmb  dmb;
};

static struct jarvis_dmb_slot slots[JARVIS_DIBS_MAX_SLOTS];
static DEFINE_SPINLOCK(slots_lock);

/* -----------------------------------------------------------------------
 * DIBS client callbacks
 * --------------------------------------------------------------------- */

static int jarvis_dibs_add_dev(struct dibs_dev *dibs)
{
	pr_debug("DIBS device added: fabric 0x%04x\n",
		 dibs->ops->get_fabric_id(dibs));
	return 0;
}

static void jarvis_dibs_del_dev(struct dibs_dev *dibs)
{
	pr_debug("DIBS device removed\n");
}

static void jarvis_dibs_rx(struct dibs_dev *dibs, struct dibs_dmb *dmb,
			   u32 offset, u32 len)
{
	/*
	 * Inbound data notification from a remote DIBS sender.
	 * For future use — e.g. receiving inference results pushed by an
	 * accelerator into a shared DMB.
	 */
	pr_debug("rx: dmb tok %llu offset %u len %u\n",
		 (unsigned long long)dmb->dmb_tok, offset, len);
}

static const struct dibs_client_ops jarvis_dibs_ops = {
	.add_dev = jarvis_dibs_add_dev,
	.del_dev = jarvis_dibs_del_dev,
	.rx      = jarvis_dibs_rx,
};

static struct dibs_client jarvis_dibs_client = {
	.name = "jarvis",
	.ops  = &jarvis_dibs_ops,
};

/* -----------------------------------------------------------------------
 * Slot management (called from jarvis_core.c ioctl handler)
 * --------------------------------------------------------------------- */

long jarvis_dibs_ioctl(unsigned int cmd, void __user *uarg)
{
	unsigned long flags;
	int rc = 0;

	switch (cmd) {

	case JARVIS_IOC_DIBS_REG: {
		struct jarvis_dibs_reg reg;
		int slot = -1;

		if (copy_from_user(&reg, uarg, sizeof(reg)))
			return -EFAULT;

		spin_lock_irqsave(&slots_lock, flags);
		for (int i = 0; i < JARVIS_DIBS_MAX_SLOTS; i++) {
			if (!slots[i].used) {
				slot = i;
				slots[i].used        = true;
				slots[i].dmb.dmb_tok = reg.dmb_tok;
				slots[i].dmb.dmb_len = reg.dmb_len;
				break;
			}
		}
		spin_unlock_irqrestore(&slots_lock, flags);

		if (slot < 0)
			return -ENOSPC;

		reg.slot = (u32)slot;
		if (copy_to_user(uarg, &reg, sizeof(reg))) {
			/* Roll back slot allocation */
			spin_lock_irqsave(&slots_lock, flags);
			slots[slot].used = false;
			spin_unlock_irqrestore(&slots_lock, flags);
			return -EFAULT;
		}

		pr_debug("registered DMB tok=%llu len=%u → slot %d\n",
			 (unsigned long long)reg.dmb_tok, reg.dmb_len, slot);
		break;
	}

	case JARVIS_IOC_DIBS_UNREG: {
		__u32 slot;

		if (copy_from_user(&slot, uarg, sizeof(slot)))
			return -EFAULT;

		if (slot >= JARVIS_DIBS_MAX_SLOTS)
			return -EINVAL;

		spin_lock_irqsave(&slots_lock, flags);
		if (!slots[slot].used) {
			spin_unlock_irqrestore(&slots_lock, flags);
			return -ENOENT;
		}
		memset(&slots[slot], 0, sizeof(slots[slot]));
		spin_unlock_irqrestore(&slots_lock, flags);

		pr_debug("unregistered slot %u\n", slot);
		break;
	}

	default:
		rc = -ENOTTY;
	}

	return rc;
}

/**
 * jarvis_dibs_write_slot - copy data into a pre-registered DMB (zero-copy path)
 * @slot:  slot index returned by JARVIS_IOC_DIBS_REG
 * @data:  source kernel buffer
 * @len:   bytes to copy (must be ≤ slot dmb_len)
 *
 * Returns 0 on success, negative error code on failure.
 * Can be called from any context that may sleep (uses GFP_KERNEL internally).
 */
int jarvis_dibs_write_slot(unsigned int slot, const void *data, u32 len)
{
	unsigned long flags;
	void *cpu_addr;
	u32 dmb_len;

	if (slot >= JARVIS_DIBS_MAX_SLOTS || !data || len == 0)
		return -EINVAL;

	spin_lock_irqsave(&slots_lock, flags);
	if (!slots[slot].used) {
		spin_unlock_irqrestore(&slots_lock, flags);
		return -ENOENT;
	}
	cpu_addr = slots[slot].dmb.cpu_addr;
	dmb_len  = slots[slot].dmb.dmb_len;
	spin_unlock_irqrestore(&slots_lock, flags);

	if (!cpu_addr)
		return -ENXIO;  /* buffer not yet physically mapped */

	if (len > dmb_len)
		return -ENOSPC;

	memcpy(cpu_addr, data, len);
	return 0;
}
EXPORT_SYMBOL_GPL(jarvis_dibs_write_slot);

/* -----------------------------------------------------------------------
 * Init / exit
 * --------------------------------------------------------------------- */

int jarvis_dibs_init(void)
{
	int rc;

	memset(slots, 0, sizeof(slots));

	rc = dibs_register_client(&jarvis_dibs_client);
	if (rc) {
		pr_err("failed to register as DIBS client: %d\n", rc);
		return rc;
	}

	pr_info("registered as DIBS client (max %d slots)\n",
		JARVIS_DIBS_MAX_SLOTS);
	return 0;
}

void jarvis_dibs_exit(void)
{
	dibs_unregister_client(&jarvis_dibs_client);
	pr_info("unregistered DIBS client\n");
}
