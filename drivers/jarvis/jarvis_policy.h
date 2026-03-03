/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _JARVIS_POLICY_H
#define _JARVIS_POLICY_H

#include <linux/device.h>
#include <uapi/linux/jarvis.h>

#ifdef CONFIG_JARVIS_POLICY

bool jarvis_policy_check(const char *server, const char *tool,
			 enum jarvis_policy_tier *tier_out);
long jarvis_policy_ioctl(unsigned int cmd, void __user *uarg);
int  jarvis_policy_load_defaults(void);
int  jarvis_policy_init(struct device *parent_dev);
void jarvis_policy_exit(struct device *parent_dev);

#else

static inline bool jarvis_policy_check(const char *server, const char *tool,
					enum jarvis_policy_tier *tier_out)
{
	*tier_out = JARVIS_TIER_ELEVATED;
	return true; /* permissive when policy module not built */
}
static inline long jarvis_policy_ioctl(unsigned int cmd, void __user *uarg)
{
	return -ENOTSUPP;
}
static inline int  jarvis_policy_load_defaults(void)      { return 0; }
static inline int  jarvis_policy_init(struct device *d)   { return 0; }
static inline void jarvis_policy_exit(struct device *d)   {}

#endif /* CONFIG_JARVIS_POLICY */
#endif /* _JARVIS_POLICY_H */
