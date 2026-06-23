/* SPDX-License-Identifier: GPL-2.0 */
/*
 * JARVIS DIBS integration — internal interface between jarvis_core and jarvis_dibs
 */
#ifndef _JARVIS_DIBS_H
#define _JARVIS_DIBS_H

#include <linux/types.h>

#ifdef CONFIG_JARVIS_DIBS

int  jarvis_dibs_init(void);
void jarvis_dibs_exit(void);
long jarvis_dibs_ioctl(unsigned int cmd, void __user *uarg);
int  jarvis_dibs_write_slot(unsigned int slot, const void *data, u32 len);

#else

static inline int  jarvis_dibs_init(void)  { return 0; }
static inline void jarvis_dibs_exit(void)  {}
static inline long jarvis_dibs_ioctl(unsigned int cmd, void __user *uarg)
{
	return -ENOTSUPP;
}
static inline int  jarvis_dibs_write_slot(unsigned int slot,
					  const void *data, u32 len)
{
	return -ENOTSUPP;
}

#endif /* CONFIG_JARVIS_DIBS */
#endif /* _JARVIS_DIBS_H */
