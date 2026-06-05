/* SPDX-License-Identifier: GPL-2.0 */
/*
 * JARVIS in-kernel API — kernel -> AI daemon query interface.
 *
 * Userspace ABI lives in <uapi/linux/jarvis.h>. This header declares the
 * symbols exported by drivers/jarvis/jarvis_core.c for use by other kernel
 * modules.
 */
#ifndef _LINUX_JARVIS_H
#define _LINUX_JARVIS_H

#include <linux/types.h>
#include <uapi/linux/jarvis.h>

int jarvis_post_query(enum jarvis_query_type type, const void *data, u32 len);
int jarvis_query_sync(enum jarvis_query_type type, const void *data, u32 len,
		      struct jarvis_response *resp, unsigned long timeout);

#endif /* _LINUX_JARVIS_H */
