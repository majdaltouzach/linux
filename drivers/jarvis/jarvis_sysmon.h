/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _JARVIS_SYSMON_H
#define _JARVIS_SYSMON_H

#include <linux/device.h>
#include <uapi/linux/jarvis.h>

#ifdef CONFIG_JARVIS_SYSMON

void jarvis_sysmon_sample(struct jarvis_sysmon *s);
int  jarvis_sysmon_init(struct device *parent_dev);
void jarvis_sysmon_exit(struct device *parent_dev);

#else

static inline void jarvis_sysmon_sample(struct jarvis_sysmon *s)
{
	memset(s, 0, sizeof(*s));
}
static inline int  jarvis_sysmon_init(struct device *d) { return 0; }
static inline void jarvis_sysmon_exit(struct device *d) {}

#endif /* CONFIG_JARVIS_SYSMON */
#endif /* _JARVIS_SYSMON_H */
