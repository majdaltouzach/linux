// SPDX-License-Identifier: GPL-2.0
/*
 * JARVIS AI Kernel Integration Driver - Core
 *
 * Exposes /dev/jarvis as a misc character device.  Kernel subsystems enqueue
 * structured queries via jarvis_post_query(); the AI daemon reads them with
 * read(), posts responses with JARVIS_IOC_RESPOND, and polls for new work
 * with poll()/select().
 *
 * Ring buffer layout
 * ------------------
 * We maintain two KFIFO ring buffers (lockless on the hot path):
 *   query_fifo  — kernel writers, single daemon reader
 *   pending_ids — parallel queue of query IDs that have been read out but
 *                 not yet answered (for response matching)
 *
 * Security
 * --------
 * Only CAP_SYS_ADMIN may open /dev/jarvis (O_RDWR) as the AI daemon.
 * Kernel-internal callers use jarvis_post_query() directly.
 *
 * Copyright (c) 2025 JARVISos Contributors
 */
#define pr_fmt(fmt) "jarvis: " fmt

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/kfifo.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/sysfs.h>
#include <linux/device.h>

#include <uapi/linux/jarvis.h>
#include "jarvis_dibs.h"

/* Internal query slot stored in the ring buffer */
struct jarvis_qslot {
	struct jarvis_query q;
};

/* Response waiting for a caller blocked on jarvis_query_wait() */
struct jarvis_pending {
	u64 id;
	struct completion done;
	struct jarvis_response resp;
	struct list_head node;
};

/* -----------------------------------------------------------------------
 * Driver-wide state
 * --------------------------------------------------------------------- */

#define QUERY_FIFO_SIZE   32   /* max outstanding kernel→AI queries */

/* One KFIFO entry = one full jarvis_qslot (copy-based, simple, safe) */
DEFINE_KFIFO(query_fifo, struct jarvis_qslot, QUERY_FIFO_SIZE);

static DECLARE_WAIT_QUEUE_HEAD(query_wq);
static DEFINE_SPINLOCK(fifo_lock);

/* AI daemon file state — at most one opener */
static DEFINE_MUTEX(daemon_lock);
static bool daemon_connected;

/* Daemon-reported state */
static atomic_t jarvis_state    = ATOMIC_INIT(JARVIS_STATE_OFFLINE);
static char     jarvis_model[JARVIS_MODEL_NAME_LEN];
static DEFINE_SPINLOCK(model_lock);

/* Pending responses (kernel callers blocked waiting for AI reply) */
static LIST_HEAD(pending_list);
static DEFINE_SPINLOCK(pending_lock);

/* Monotonically increasing query ID */
static atomic64_t next_query_id = ATOMIC64_INIT(1);

/* -----------------------------------------------------------------------
 * Public kernel API
 * --------------------------------------------------------------------- */

/**
 * jarvis_post_query - submit a query to the AI daemon (fire-and-forget)
 * @type:  one of enum jarvis_query_type
 * @data:  query payload (NUL-terminated string or binary blob)
 * @len:   number of bytes in @data (must be ≤ JARVIS_MAX_QUERY_LEN)
 *
 * Returns 0 on success, -ENODEV if no daemon is connected, -ENOSPC if the
 * ring buffer is full, -EINVAL on bad arguments.
 *
 * Safe to call from interrupt context (uses spin_lock_irqsave internally).
 */
int jarvis_post_query(enum jarvis_query_type type, const void *data, u32 len)
{
	struct jarvis_qslot slot = {};
	unsigned long flags;
	int rc;

	if (!data || len == 0 || len > JARVIS_MAX_QUERY_LEN)
		return -EINVAL;

	if (!READ_ONCE(daemon_connected))
		return -ENODEV;

	slot.q.id        = atomic64_fetch_add(1, &next_query_id);
	slot.q.type      = type;
	slot.q.len       = len;
	slot.q.timestamp = ktime_get_ns();
	memcpy(slot.q.data, data, len);

	spin_lock_irqsave(&fifo_lock, flags);
	rc = kfifo_put(&query_fifo, slot) ? 0 : -ENOSPC;
	spin_unlock_irqrestore(&fifo_lock, flags);

	if (!rc)
		wake_up_interruptible(&query_wq);

	return rc;
}
EXPORT_SYMBOL_GPL(jarvis_post_query);

/**
 * jarvis_query_sync - submit a query and block until the AI replies
 * @type:    query type
 * @data:    payload
 * @len:     payload length
 * @resp:    output — filled with the AI response on success
 * @timeout: wait timeout in jiffies (0 = wait forever)
 *
 * Returns 0 on success, -ETIME on timeout, or a negative error code.
 * Must NOT be called from interrupt context.
 */
int jarvis_query_sync(enum jarvis_query_type type, const void *data, u32 len,
		      struct jarvis_response *resp, unsigned long timeout)
{
	struct jarvis_pending *pend;
	struct jarvis_qslot slot = {};
	unsigned long flags;
	long rem;
	int rc;

	if (!data || len == 0 || len > JARVIS_MAX_QUERY_LEN || !resp)
		return -EINVAL;

	if (!READ_ONCE(daemon_connected))
		return -ENODEV;

	pend = kzalloc(sizeof(*pend), GFP_KERNEL);
	if (!pend)
		return -ENOMEM;

	init_completion(&pend->done);
	pend->id = atomic64_fetch_add(1, &next_query_id);

	slot.q.id        = pend->id;
	slot.q.type      = type;
	slot.q.len       = len;
	slot.q.timestamp = ktime_get_ns();
	memcpy(slot.q.data, data, len);

	spin_lock_irqsave(&pending_lock, flags);
	list_add_tail(&pend->node, &pending_list);
	spin_unlock_irqrestore(&pending_lock, flags);

	spin_lock_irqsave(&fifo_lock, flags);
	rc = kfifo_put(&query_fifo, slot) ? 0 : -ENOSPC;
	spin_unlock_irqrestore(&fifo_lock, flags);

	if (rc) {
		spin_lock_irqsave(&pending_lock, flags);
		list_del(&pend->node);
		spin_unlock_irqrestore(&pending_lock, flags);
		kfree(pend);
		return rc;
	}

	wake_up_interruptible(&query_wq);

	if (timeout)
		rem = wait_for_completion_interruptible_timeout(&pend->done, timeout);
	else
		rem = wait_for_completion_interruptible(&pend->done);

	if (rem < 0) {
		rc = rem; /* -ERESTARTSYS */
	} else if (rem == 0 && timeout) {
		rc = -ETIME;
	} else {
		*resp = pend->resp;
		rc = 0;
	}

	/* If timed out/interrupted, remove from pending list */
	if (rc) {
		spin_lock_irqsave(&pending_lock, flags);
		list_del(&pend->node);
		spin_unlock_irqrestore(&pending_lock, flags);
	}

	kfree(pend);
	return rc;
}
EXPORT_SYMBOL_GPL(jarvis_query_sync);

/* -----------------------------------------------------------------------
 * File operations
 * --------------------------------------------------------------------- */

static int jarvis_open(struct inode *inode, struct file *filp)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	mutex_lock(&daemon_lock);
	if (daemon_connected) {
		mutex_unlock(&daemon_lock);
		return -EBUSY; /* Only one daemon at a time */
	}
	daemon_connected = true;
	atomic_set(&jarvis_state, JARVIS_STATE_IDLE);
	mutex_unlock(&daemon_lock);

	pr_info("AI daemon connected\n");
	return 0;
}

static int jarvis_release(struct inode *inode, struct file *filp)
{
	struct jarvis_pending *pend, *tmp;
	unsigned long flags;

	mutex_lock(&daemon_lock);
	daemon_connected = false;
	atomic_set(&jarvis_state, JARVIS_STATE_OFFLINE);
	mutex_unlock(&daemon_lock);

	/* Wake any kernel callers blocked in jarvis_query_sync() */
	spin_lock_irqsave(&pending_lock, flags);
	list_for_each_entry_safe(pend, tmp, &pending_list, node) {
		list_del(&pend->node);
		pend->resp.status = UINT_MAX; /* error sentinel */
		complete(&pend->done);
	}
	spin_unlock_irqrestore(&pending_lock, flags);

	pr_info("AI daemon disconnected\n");
	return 0;
}

/*
 * read() — the daemon pulls one query at a time.
 * Blocks until a query is available (or O_NONBLOCK returns -EAGAIN).
 */
static ssize_t jarvis_read(struct file *filp, char __user *ubuf,
			   size_t count, loff_t *pos)
{
	struct jarvis_qslot slot;
	unsigned long flags;
	unsigned int copied;
	int rc;

	if (count < sizeof(slot.q))
		return -EINVAL;

	/* Block until data available (or interrupted) */
	rc = wait_event_interruptible(query_wq,
		({ spin_lock_irqsave(&fifo_lock, flags);
		   bool have = !kfifo_is_empty(&query_fifo);
		   spin_unlock_irqrestore(&fifo_lock, flags);
		   have; }) || (filp->f_flags & O_NONBLOCK));

	if (rc)
		return rc;

	spin_lock_irqsave(&fifo_lock, flags);
	copied = kfifo_get(&query_fifo, &slot);
	spin_unlock_irqrestore(&fifo_lock, flags);

	if (!copied) {
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		return -EIO;
	}

	if (copy_to_user(ubuf, &slot.q, sizeof(slot.q)))
		return -EFAULT;

	return sizeof(slot.q);
}

static __poll_t jarvis_poll(struct file *filp, poll_table *wait)
{
	unsigned long flags;
	bool have_data;

	poll_wait(filp, &query_wq, wait);

	spin_lock_irqsave(&fifo_lock, flags);
	have_data = !kfifo_is_empty(&query_fifo);
	spin_unlock_irqrestore(&fifo_lock, flags);

	return have_data ? (EPOLLIN | EPOLLRDNORM) : 0;
}

static long jarvis_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	unsigned long flags;
	int rc = 0;

	switch (cmd) {

	case JARVIS_IOC_STATUS: {
		struct jarvis_status st = {};
		st.state = atomic_read(&jarvis_state);
		spin_lock_irqsave(&fifo_lock, flags);
		st.pending_queries = kfifo_len(&query_fifo);
		spin_unlock_irqrestore(&fifo_lock, flags);
		spin_lock_irqsave(&model_lock, flags);
		strlcpy(st.model_name, jarvis_model, sizeof(st.model_name));
		st.model_loaded = (jarvis_model[0] != '\0') ? 1 : 0;
		spin_unlock_irqrestore(&model_lock, flags);
		if (copy_to_user(uarg, &st, sizeof(st)))
			return -EFAULT;
		break;
	}

	case JARVIS_IOC_SET_STATE: {
		__u32 state;
		if (copy_from_user(&state, uarg, sizeof(state)))
			return -EFAULT;
		if (state > JARVIS_STATE_ERROR)
			return -EINVAL;
		atomic_set(&jarvis_state, state);
		pr_debug("daemon state → %u\n", state);
		break;
	}

	case JARVIS_IOC_SET_MODEL: {
		char name[JARVIS_MODEL_NAME_LEN] = {};
		if (copy_from_user(name, uarg, sizeof(name) - 1))
			return -EFAULT;
		spin_lock_irqsave(&model_lock, flags);
		strlcpy(jarvis_model, name, sizeof(jarvis_model));
		spin_unlock_irqrestore(&model_lock, flags);
		pr_info("AI model: %s\n", jarvis_model);
		break;
	}

	case JARVIS_IOC_RESPOND: {
		struct jarvis_response *resp;
		struct jarvis_pending *pend;
		bool found = false;

		resp = kmalloc(sizeof(*resp), GFP_KERNEL);
		if (!resp)
			return -ENOMEM;

		if (copy_from_user(resp, uarg, sizeof(*resp))) {
			kfree(resp);
			return -EFAULT;
		}

		spin_lock_irqsave(&pending_lock, flags);
		list_for_each_entry(pend, &pending_list, node) {
			if (pend->id == resp->id) {
				pend->resp = *resp;
				list_del(&pend->node);
				complete(&pend->done);
				found = true;
				break;
			}
		}
		spin_unlock_irqrestore(&pending_lock, flags);

		kfree(resp);

		if (!found)
			pr_debug("response for unknown query id %llu\n",
				 (unsigned long long)resp->id);
		break;
	}

	case JARVIS_IOC_FLUSH: {
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		spin_lock_irqsave(&fifo_lock, flags);
		kfifo_reset(&query_fifo);
		spin_unlock_irqrestore(&fifo_lock, flags);
		pr_info("query queue flushed\n");
		break;
	}

	/* DIBS ioctls handled in jarvis_dibs.c when compiled in */
	case JARVIS_IOC_DIBS_REG:
	case JARVIS_IOC_DIBS_UNREG:
#ifdef CONFIG_JARVIS_DIBS
		rc = jarvis_dibs_ioctl(cmd, uarg);
#else
		rc = -ENOTSUPP;
#endif
		break;

	default:
		return -ENOTTY;
	}

	return rc;
}

/* -----------------------------------------------------------------------
 * sysfs attributes (when CONFIG_JARVIS_SYSFS_METRICS=y)
 * --------------------------------------------------------------------- */
#ifdef CONFIG_JARVIS_SYSFS_METRICS

static ssize_t state_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	static const char * const names[] = {
		[JARVIS_STATE_OFFLINE]    = "offline",
		[JARVIS_STATE_IDLE]       = "idle",
		[JARVIS_STATE_PROCESSING] = "processing",
		[JARVIS_STATE_ERROR]      = "error",
	};
	unsigned int s = atomic_read(&jarvis_state);
	if (s >= ARRAY_SIZE(names) || !names[s])
		return sysfs_emit(buf, "unknown\n");
	return sysfs_emit(buf, "%s\n", names[s]);
}
static DEVICE_ATTR_RO(state);

static ssize_t model_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	unsigned long flags;
	char name[JARVIS_MODEL_NAME_LEN];

	spin_lock_irqsave(&model_lock, flags);
	strlcpy(name, jarvis_model, sizeof(name));
	spin_unlock_irqrestore(&model_lock, flags);

	return sysfs_emit(buf, "%s\n", name[0] ? name : "(none)");
}
static DEVICE_ATTR_RO(model);

static ssize_t pending_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	unsigned long flags;
	unsigned int n;

	spin_lock_irqsave(&fifo_lock, flags);
	n = kfifo_len(&query_fifo);
	spin_unlock_irqrestore(&fifo_lock, flags);

	return sysfs_emit(buf, "%u\n", n);
}
static DEVICE_ATTR_RO(pending);

static struct attribute *jarvis_dev_attrs[] = {
	&dev_attr_state.attr,
	&dev_attr_model.attr,
	&dev_attr_pending.attr,
	NULL,
};
ATTRIBUTE_GROUPS(jarvis_dev);

#endif /* CONFIG_JARVIS_SYSFS_METRICS */

/* -----------------------------------------------------------------------
 * Misc device registration
 * --------------------------------------------------------------------- */

static const struct file_operations jarvis_fops = {
	.owner          = THIS_MODULE,
	.open           = jarvis_open,
	.release        = jarvis_release,
	.read           = jarvis_read,
	.poll           = jarvis_poll,
	.unlocked_ioctl = jarvis_ioctl,
	.compat_ioctl   = jarvis_ioctl,
};

static struct miscdevice jarvis_misc = {
	.minor  = MISC_DYNAMIC_MINOR,
	.name   = "jarvis",
	.fops   = &jarvis_fops,
	.mode   = 0600,
#ifdef CONFIG_JARVIS_SYSFS_METRICS
	.groups = jarvis_dev_groups,
#endif
};

/* -----------------------------------------------------------------------
 * Module init / exit
 * --------------------------------------------------------------------- */

static int __init jarvis_init(void)
{
	int rc;

	rc = misc_register(&jarvis_misc);
	if (rc) {
		pr_err("failed to register misc device: %d\n", rc);
		return rc;
	}

#ifdef CONFIG_JARVIS_DIBS
	rc = jarvis_dibs_init();
	if (rc) {
		pr_err("DIBS integration init failed: %d (continuing without DIBS)\n", rc);
		/* Non-fatal — driver still works without DIBS */
	}
#endif

	pr_info("JARVIS AI kernel integration driver loaded (/dev/jarvis)\n");
	return 0;
}

static void __exit jarvis_exit(void)
{
#ifdef CONFIG_JARVIS_DIBS
	jarvis_dibs_exit();
#endif
	misc_deregister(&jarvis_misc);
	pr_info("JARVIS driver unloaded\n");
}

module_init(jarvis_init);
module_exit(jarvis_exit);

MODULE_AUTHOR("JARVISos Contributors");
MODULE_DESCRIPTION("JARVIS AI kernel integration driver");
MODULE_LICENSE("GPL");
