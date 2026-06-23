/* SPDX-License-Identifier: GPL-2.0 */
/*
 * linux/jarvis.h — in-kernel API for the JARVIS AI integration driver
 *
 * Other kernel subsystems (thermal, OOM, audit, etc.) use these to submit
 * natural-language events to the JARVIS daemon via jarvis_post_query() and
 * to gate tool execution via jarvis_policy_check().
 *
 * Userspace API is in <uapi/linux/jarvis.h>.
 */
#ifndef _LINUX_JARVIS_H
#define _LINUX_JARVIS_H

#include <uapi/linux/jarvis.h>

#ifdef CONFIG_JARVIS

int jarvis_post_query(enum jarvis_query_type type, const void *data, u32 len);
int jarvis_query_sync(enum jarvis_query_type type, const void *data, u32 len,
		      struct jarvis_response *resp, unsigned long timeout);

#else /* !CONFIG_JARVIS */

static inline int jarvis_post_query(enum jarvis_query_type type,
				    const void *data, u32 len)
{ return -ENODEV; }

static inline int jarvis_query_sync(enum jarvis_query_type type,
				    const void *data, u32 len,
				    struct jarvis_response *resp,
				    unsigned long timeout)
{ return -ENODEV; }

#endif /* CONFIG_JARVIS */

#ifdef CONFIG_JARVIS_POLICY

bool jarvis_policy_check(const char *server, const char *tool, const char *path,
			 enum jarvis_policy_tier *tier_out);

#else

static inline bool jarvis_policy_check(const char *server, const char *tool,
				       const char *path,
				       enum jarvis_policy_tier *tier_out)
{ return true; }

#endif /* CONFIG_JARVIS_POLICY */

#ifdef CONFIG_JARVIS_KEYS

int jarvis_key_lookup(const char *id, char *buf, size_t buflen);

#else

static inline int jarvis_key_lookup(const char *id, char *buf, size_t buflen)
{ return -ENODEV; }

#endif /* CONFIG_JARVIS_KEYS */

#endif /* _LINUX_JARVIS_H */
