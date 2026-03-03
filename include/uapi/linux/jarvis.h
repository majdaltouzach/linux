/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * JARVIS AI Kernel Integration Driver - Userspace API
 *
 * linux-jarvisos: custom Linux kernel with native AI assistant integration.
 * This header defines the complete interface between the JARVIS daemon and
 * all kernel driver sub-modules:
 *
 *   jarvis_core    — query/response channel  (/dev/jarvis)
 *   jarvis_dibs    — zero-copy DIBS buffers
 *   jarvis_sysmon  — live hardware metrics for model selection
 *   jarvis_policy  — AI action security policy engine
 *   jarvis_keys    — secure API-key storage via kernel keyring
 *
 * Message flow:
 *   Kernel → AI : enqueue jarvis_query via jarvis_post_query()
 *   AI reads    : read() on /dev/jarvis, one jarvis_query per call
 *   AI replies  : JARVIS_IOC_RESPOND ioctl
 *   AI polls    : poll()/select() for POLLIN when queue non-empty
 *
 * LLM provider model:
 *   Local  — Ollama daemon, model chosen based on JARVIS_IOC_SYSMON hardware caps
 *   Cloud  — Claude, OpenAI, etc.; API keys stored via JARVIS_IOC_KEY_STORE
 */
#ifndef _UAPI_LINUX_JARVIS_H
#define _UAPI_LINUX_JARVIS_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* -----------------------------------------------------------------------
 * Common constants
 * --------------------------------------------------------------------- */

#define JARVIS_MAX_QUERY_LEN     4096   /* max query payload bytes             */
#define JARVIS_MAX_RESP_LEN      65536  /* max response payload bytes          */
#define JARVIS_MODEL_NAME_LEN    64     /* max model name / provider string    */
#define JARVIS_KEY_ID_LEN        64     /* max key description length          */
#define JARVIS_KEY_DATA_LEN      512    /* max key value length (API keys)     */
#define JARVIS_POLICY_PATTERN_LEN 128   /* max server:tool pattern length      */
#define JARVIS_THERMAL_MAX_ZONES 16     /* max thermal zones reported          */

/* -----------------------------------------------------------------------
 * Query types
 * --------------------------------------------------------------------- */
enum jarvis_query_type {
	JARVIS_QTYPE_GENERIC    = 0,   /* free-form natural-language query        */
	JARVIS_QTYPE_SYSEVT     = 1,   /* kernel system event (thermal, OOM …)    */
	JARVIS_QTYPE_AUDIT      = 2,   /* security/audit event for AI analysis    */
	JARVIS_QTYPE_DIAG       = 3,   /* hardware/driver diagnostic request      */
	JARVIS_QTYPE_VOICE_CMD  = 4,   /* voice command payload from voice driver */
	JARVIS_QTYPE_MCP_CALL   = 5,   /* direct MCP tool-call forwarded to AI    */
	JARVIS_QTYPE_POLICY_REQ = 6,   /* policy authorisation request            */
};

/* -----------------------------------------------------------------------
 * AI agent state
 * --------------------------------------------------------------------- */
enum jarvis_state {
	JARVIS_STATE_OFFLINE    = 0,   /* daemon not connected                    */
	JARVIS_STATE_IDLE       = 1,   /* connected, ready                        */
	JARVIS_STATE_PROCESSING = 2,   /* running inference                       */
	JARVIS_STATE_ERROR      = 3,   /* daemon fatal error                      */
};

/* -----------------------------------------------------------------------
 * LLM provider type — reported by daemon via JARVIS_IOC_SET_PROVIDER
 * --------------------------------------------------------------------- */
enum jarvis_provider {
	JARVIS_PROVIDER_NONE    = 0,   /* not yet configured                      */
	JARVIS_PROVIDER_OLLAMA  = 1,   /* local Ollama (llama3, mistral, etc.)    */
	JARVIS_PROVIDER_CLAUDE  = 2,   /* Anthropic Claude API                    */
	JARVIS_PROVIDER_OPENAI  = 3,   /* OpenAI / ChatGPT API                    */
	JARVIS_PROVIDER_OPENAI_COMPAT = 4, /* OpenAI-compatible endpoint          */
};

/* -----------------------------------------------------------------------
 * Policy action tiers
 * --------------------------------------------------------------------- */
enum jarvis_policy_tier {
	JARVIS_TIER_SAFE      = 0,   /* always allowed, no confirmation needed    */
	JARVIS_TIER_ELEVATED  = 1,   /* allowed with audit log entry              */
	JARVIS_TIER_DANGEROUS = 2,   /* requires explicit user confirmation       */
	JARVIS_TIER_FORBIDDEN = 3,   /* never allowed, kernel will block          */
};

/* -----------------------------------------------------------------------
 * Core structures
 * --------------------------------------------------------------------- */

/**
 * struct jarvis_query - kernel → AI message
 * @id:        monotonic query id (assigned by driver)
 * @type:      jarvis_query_type
 * @flags:     reserved, zero
 * @len:       valid bytes in @data
 * @timestamp: ktime_get_ns() at creation
 * @data:      NUL-terminated string or binary blob
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
 * struct jarvis_response - AI → kernel reply
 * @id:     matching jarvis_query.id
 * @status: 0 = OK, non-zero = AI-level error
 * @flags:  reserved, zero
 * @len:    valid bytes in @data
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
 * struct jarvis_status - driver + daemon snapshot
 * @state:           jarvis_state of the connected daemon
 * @provider:        jarvis_provider currently active
 * @pending_queries: queries waiting in the ring buffer
 * @model_loaded:    1 if model is ready, 0 otherwise
 * @model_name:      NUL-terminated active model name
 * @provider_name:   NUL-terminated provider string (e.g. "ollama", "claude")
 */
struct jarvis_status {
	__u32 state;
	__u32 provider;
	__u32 pending_queries;
	__u32 model_loaded;
	__u8  model_name[JARVIS_MODEL_NAME_LEN];
	__u8  provider_name[JARVIS_MODEL_NAME_LEN];
};

/**
 * struct jarvis_dibs_reg - DIBS Direct Memory Buffer registration
 * @dmb_tok:  DIBS fabric token
 * @dmb_len:  buffer length in bytes
 * @slot:     output — slot index assigned by driver
 */
struct jarvis_dibs_reg {
	__u64 dmb_tok;
	__u32 dmb_len;
	__u32 slot;
};

/* -----------------------------------------------------------------------
 * System monitor structure (jarvis_sysmon sub-module)
 * --------------------------------------------------------------------- */

/**
 * struct jarvis_sysmon - live hardware snapshot for model/task selection
 *
 * Used by the AI daemon to decide:
 *   - Whether to use Ollama (local) vs cloud API
 *   - Which Ollama model fits available VRAM / RAM
 *   - Whether to throttle requests under thermal pressure
 *
 * @cpu_load_1min:   CPU load average × 100 (e.g. 125 = 1.25)
 * @cpu_count:       online CPU count
 * @mem_total_mb:    total RAM in MiB
 * @mem_free_mb:     free RAM in MiB
 * @mem_avail_mb:    available RAM (free + reclaimable) in MiB
 * @thermal_count:   number of valid entries in @thermal_celsius
 * @thermal_celsius: temperature of each thermal zone in °C (integer)
 * @thermal_crit_c:  critical trip-point of the hottest zone (0 = unknown)
 * @swap_total_mb:   total swap space in MiB
 * @swap_free_mb:    free swap space in MiB
 */
struct jarvis_sysmon {
	__u32 cpu_load_1min;
	__u32 cpu_count;
	__u64 mem_total_mb;
	__u64 mem_free_mb;
	__u64 mem_avail_mb;
	__u32 thermal_count;
	__s32 thermal_celsius[JARVIS_THERMAL_MAX_ZONES];
	__s32 thermal_crit_c;
	__u64 swap_total_mb;
	__u64 swap_free_mb;
};

/* -----------------------------------------------------------------------
 * Policy structures (jarvis_policy sub-module)
 * --------------------------------------------------------------------- */

/**
 * struct jarvis_policy_entry - one policy rule
 * @pattern: "server:tool" glob pattern (e.g. "ShellMCP:*", "*:delete_file")
 *           Use "*" to match anything in that field.
 * @tier:    jarvis_policy_tier for matching actions
 * @ratelimit_per_min: max allowed calls/minute (0 = unlimited)
 */
struct jarvis_policy_entry {
	__u8  pattern[JARVIS_POLICY_PATTERN_LEN];
	__u32 tier;
	__u32 ratelimit_per_min;
};

/**
 * struct jarvis_policy_check - policy check request / result
 * @server:  server name of the action being checked (input)
 * @tool:    tool name of the action being checked (input)
 * @tier:    resolved tier (output, filled by driver)
 * @allowed: 1 if allowed at current rate, 0 if blocked (output)
 */
struct jarvis_policy_check {
	__u8  server[JARVIS_POLICY_PATTERN_LEN];
	__u8  tool[JARVIS_POLICY_PATTERN_LEN];
	__u32 tier;
	__u32 allowed;
};

/* -----------------------------------------------------------------------
 * Key structures (jarvis_keys sub-module)
 * --------------------------------------------------------------------- */

/**
 * struct jarvis_key_op - store or retrieve an API key
 * @id:    NUL-terminated key identifier (e.g. "claude-api-key")
 * @data:  key value (for STORE: plaintext; for GET: filled by driver)
 * @len:   on GET: filled by driver with actual key length
 */
struct jarvis_key_op {
	__u8  id[JARVIS_KEY_ID_LEN];
	__u8  data[JARVIS_KEY_DATA_LEN];
	__u32 len;
	__u32 __pad;
};

/* -----------------------------------------------------------------------
 * ioctl command table
 *
 * Numbers 1–9   : core (query/response/state/model/DIBS/flush)
 * Numbers 10–15 : sysmon
 * Numbers 20–29 : policy
 * Numbers 30–39 : keys
 * --------------------------------------------------------------------- */
#define JARVIS_IOC_MAGIC         'J'

/* --- Core --- */
#define JARVIS_IOC_STATUS        _IOR(JARVIS_IOC_MAGIC,  1, struct jarvis_status)
#define JARVIS_IOC_SET_STATE     _IOW(JARVIS_IOC_MAGIC,  2, __u32)
#define JARVIS_IOC_SET_MODEL     _IOW(JARVIS_IOC_MAGIC,  3, char[JARVIS_MODEL_NAME_LEN])
#define JARVIS_IOC_RESPOND       _IOW(JARVIS_IOC_MAGIC,  4, struct jarvis_response)
#define JARVIS_IOC_DIBS_REG      _IOWR(JARVIS_IOC_MAGIC, 5, struct jarvis_dibs_reg)
#define JARVIS_IOC_DIBS_UNREG    _IOW(JARVIS_IOC_MAGIC,  6, __u32)
#define JARVIS_IOC_FLUSH         _IO(JARVIS_IOC_MAGIC,   7)
#define JARVIS_IOC_SET_PROVIDER  _IOW(JARVIS_IOC_MAGIC,  8, __u32)

/* --- Sysmon --- */
#define JARVIS_IOC_SYSMON        _IOR(JARVIS_IOC_MAGIC, 10, struct jarvis_sysmon)

/* --- Policy --- */
#define JARVIS_IOC_POLICY_ADD    _IOW(JARVIS_IOC_MAGIC,  20, struct jarvis_policy_entry)
#define JARVIS_IOC_POLICY_DEL    _IOW(JARVIS_IOC_MAGIC,  21, __u8[JARVIS_POLICY_PATTERN_LEN])
#define JARVIS_IOC_POLICY_CHECK  _IOWR(JARVIS_IOC_MAGIC, 22, struct jarvis_policy_check)
#define JARVIS_IOC_POLICY_RESET  _IO(JARVIS_IOC_MAGIC,   23)

/* --- Keys --- */
#define JARVIS_IOC_KEY_STORE     _IOW(JARVIS_IOC_MAGIC,  30, struct jarvis_key_op)
#define JARVIS_IOC_KEY_GET       _IOWR(JARVIS_IOC_MAGIC, 31, struct jarvis_key_op)
#define JARVIS_IOC_KEY_DEL       _IOW(JARVIS_IOC_MAGIC,  32, __u8[JARVIS_KEY_ID_LEN])

#endif /* _UAPI_LINUX_JARVIS_H */
