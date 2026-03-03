/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _JARVIS_KEYS_H
#define _JARVIS_KEYS_H

#include <uapi/linux/jarvis.h>

#ifdef CONFIG_JARVIS_KEYS

int  jarvis_keys_init(void);
void jarvis_keys_exit(void);
long jarvis_keys_ioctl(unsigned int cmd, void __user *uarg);
int  jarvis_key_lookup(const char *id, char *buf, size_t buflen);

#else

static inline int  jarvis_keys_init(void)  { return 0; }
static inline void jarvis_keys_exit(void)  {}
static inline long jarvis_keys_ioctl(unsigned int cmd, void __user *uarg)
{
	return -ENOTSUPP;
}
static inline int  jarvis_key_lookup(const char *id, char *buf, size_t buflen)
{
	return -ENOTSUPP;
}

#endif /* CONFIG_JARVIS_KEYS */
#endif /* _JARVIS_KEYS_H */
