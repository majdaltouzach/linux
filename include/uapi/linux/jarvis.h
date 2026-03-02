/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * JARVIS AI Kernel Integration Driver - Userspace API
 *
 * Provides the interface for the Project-JARVIS AI assistant daemon to
 * communicate with kernel subsystems via /dev/jarvis.
 *
 * Message flow:
 *   Kernel → AI : write jarvis_query  to the device ring buffer
 *   AI → Kernel : write jarvis_response via JARVIS_IOC_RESPOND ioctl
 *   AI polls /dev/jarvis for pending queries (POLLIN when queue non-empty)
 *
 * DIBS integration:
 *   For large payloads (e.g. inference context blobs) the AI can register a
 *   pre-allocated DIBS DMB via JARVIS_IOC_DIBS_REG so subsequent transfers
 *   bypass the copy path entirely.
 */
#ifndef _UAPI_LINUX_JARVIS_H
#define _UAPI_LINUX_JARVIS_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* -----------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */

#define JARVIS_MAX_QUERY_LEN    4096   /* max bytes in a single kernel query  */
#define JARVIS_MAX_RESP_LEN     65536  /* max bytes in a single AI response   */
#define JARVIS_MODEL_NAME_LEN   64     /* max length of reported model name   */

/* -----------------------------------------------------------------------
 * Query types — describes the semantic meaning of a kernel-originated query
 * --------------------------------------------------------------------- */
enum jarvis_query_type {
	JARVIS_QTYPE_GENERIC    = 0,   /* free-form natural-language query        */
	JARVIS_QTYPE_SYSEVT     = 1,   /* kernel system event (thermal, OOM, …)   */
	JARVIS_QTYPE_AUDIT      = 2,   /* security/audit event for AI analysis    */
	JARVIS_QTYPE_DIAG       = 3,   /* hardware/driver diagnostic request      */
	JARVIS_QTYPE_VOICE_CMD  = 4,   /* voice command payload from voice driver */
	JARVIS_QTYPE_MCP_CALL   = 5,   /* direct MCP tool-call request            */
};

/* -----------------------------------------------------------------------
 * AI agent state — reported by the daemon via JARVIS_IOC_SET_STATE
 * --------------------------------------------------------------------- */
enum jarvis_state {
	JARVIS_STATE_OFFLINE    = 0,   /* daemon not connected              */
	JARVIS_STATE_IDLE       = 1,   /* connected, waiting for queries    */
	JARVIS_STATE_PROCESSING = 2,   /* actively running inference        */
	JARVIS_STATE_ERROR      = 3,   /* daemon encountered fatal error    */
};

/* -----------------------------------------------------------------------
 * Structures
 * --------------------------------------------------------------------- */

/**
 * struct jarvis_query - a kernel-originated message to the AI daemon
 * @id:        unique monotonic query identifier (assigned by kernel)
 * @type:      one of enum jarvis_query_type
 * @flags:     reserved, must be zero
 * @len:       number of valid bytes in @data (≤ JARVIS_MAX_QUERY_LEN)
 * @timestamp: kernel ktime at query creation (nanoseconds, CLOCK_MONOTONIC)
 * @data:      query payload (NUL-terminated string or binary blob)
 */
struct jarvis_query {
	__u64 id;
	__u32 type;
	__u32 flags;
	__u32 len;
	__u32 __pad;
	__u64 timestamp;
	__u8  data[JARVIS_MAX_QUERY_LEN];
};

/**
 * struct jarvis_response - AI response sent back to the kernel
 * @id:     query id this response belongs to (must match jarvis_query.id)
 * @status: 0 = success, non-zero = AI-level error code
 * @flags:  reserved, must be zero
 * @len:    number of valid bytes in @data (≤ JARVIS_MAX_RESP_LEN)
 * @data:   response payload
 */
struct jarvis_response {
	__u64 id;
	__u32 status;
	__u32 flags;
	__u32 len;
	__u32 __pad;
	__u8  data[JARVIS_MAX_RESP_LEN];
};

/**
 * struct jarvis_status - snapshot of driver + daemon state
 * @state:          current enum jarvis_state of the connected daemon
 * @pending_queries: number of queries waiting in the kernel ring buffer
 * @model_loaded:   1 if the daemon reports a model is loaded, 0 otherwise
 * @model_name:     NUL-terminated name of the active AI model
 */
struct jarvis_status {
	__u32 state;
	__u32 pending_queries;
	__u32 model_loaded;
	__u8  model_name[JARVIS_MODEL_NAME_LEN];
};

/**
 * struct jarvis_dibs_reg - register a DIBS Direct Memory Buffer
 * @dmb_tok:  DIBS token identifying the DMB to register
 * @dmb_len:  length of the buffer in bytes
 * @slot:     output — slot index assigned by the driver (0..JARVIS_DIBS_MAX-1)
 */
struct jarvis_dibs_reg {
	__u64 dmb_tok;
	__u32 dmb_len;
	__u32 slot;      /* filled by driver on return */
};

/* -----------------------------------------------------------------------
 * ioctl commands
 *
 *  JARVIS_IOC_STATUS    → get driver/daemon status (struct jarvis_status)
 *  JARVIS_IOC_SET_STATE → daemon reports its state (__u32 jarvis_state)
 *  JARVIS_IOC_SET_MODEL → daemon reports loaded model name (char[64])
 *  JARVIS_IOC_RESPOND   → daemon posts a response (struct jarvis_response)
 *  JARVIS_IOC_DIBS_REG  → register a DIBS DMB (struct jarvis_dibs_reg)
 *  JARVIS_IOC_DIBS_UNREG→ unregister a DIBS DMB slot (__u32 slot)
 *  JARVIS_IOC_FLUSH     → discard all pending queries (admin only)
 * --------------------------------------------------------------------- */
#define JARVIS_IOC_MAGIC      'J'

#define JARVIS_IOC_STATUS     _IOR(JARVIS_IOC_MAGIC,  1, struct jarvis_status)
#define JARVIS_IOC_SET_STATE  _IOW(JARVIS_IOC_MAGIC,  2, __u32)
#define JARVIS_IOC_SET_MODEL  _IOW(JARVIS_IOC_MAGIC,  3, char[JARVIS_MODEL_NAME_LEN])
#define JARVIS_IOC_RESPOND    _IOW(JARVIS_IOC_MAGIC,  4, struct jarvis_response)
#define JARVIS_IOC_DIBS_REG   _IOWR(JARVIS_IOC_MAGIC, 5, struct jarvis_dibs_reg)
#define JARVIS_IOC_DIBS_UNREG _IOW(JARVIS_IOC_MAGIC,  6, __u32)
#define JARVIS_IOC_FLUSH      _IO(JARVIS_IOC_MAGIC,   7)

#endif /* _UAPI_LINUX_JARVIS_H */
