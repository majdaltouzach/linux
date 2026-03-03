// SPDX-License-Identifier: GPL-2.0
/*
 * JARVIS AI Action Security Policy Engine
 *
 * Provides a tiered authorisation system for actions the AI dispatches to
 * MCP servers.  Every time the JARVIS daemon wants to execute an action it
 * calls JARVIS_IOC_POLICY_CHECK; the kernel consults the policy table and
 * returns a tier + a rate-limit decision.
 *
 * Tier semantics
 * --------------
 *   SAFE      — execute silently, no confirmation, no audit entry
 *   ELEVATED  — execute and write an audit log entry
 *   DANGEROUS — block until the user explicitly confirms; kernel emits a
 *               JARVIS_QTYPE_POLICY_REQ query which the daemon presents to
 *               the user and responds to with JARVIS_IOC_RESPOND
 *   FORBIDDEN — always blocked, never executed
 *
 * Policy table
 * ------------
 * Built-in defaults are hardcoded below and cover the known MCP servers
 * (ShellMCP, FileSystemMCP, CodeGenMCP, etc.).  Admins can add/remove rules
 * via JARVIS_IOC_POLICY_ADD / JARVIS_IOC_POLICY_DEL ioctls.  Rules are
 * matched first-match-wins in insertion order, so add more specific rules
 * before broad wildcards.
 *
 * Pattern format:  "server:tool"
 *   - Either field may be "*" to match any value.
 *   - No other glob syntax is supported (KISS).
 *
 * Rate limiting
 * -------------
 * Each policy entry carries an optional ratelimit_per_min value.  If > 0,
 * the kernel enforces it with a token-bucket refilled every 60 seconds.
 *
 * Copyright (c) 2025 JARVISos Contributors
 */
#define pr_fmt(fmt) "jarvis-policy: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/ratelimit.h>
#include <linux/jiffies.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/seq_buf.h>

#include <uapi/linux/jarvis.h>
#include "jarvis_policy.h"

/* -----------------------------------------------------------------------
 * Internal policy rule node
 * --------------------------------------------------------------------- */

struct policy_rule {
	struct list_head   node;
	char               pattern[JARVIS_POLICY_PATTERN_LEN]; /* "server:tool" */
	enum jarvis_policy_tier tier;
	u32                ratelimit_per_min;

	/* Token-bucket state for per-rule rate limiting */
	spinlock_t         rl_lock;
	u32                rl_tokens;       /* current tokens available */
	unsigned long      rl_last_refill;  /* jiffies of last refill   */
};

/* -----------------------------------------------------------------------
 * Policy table
 * --------------------------------------------------------------------- */

static LIST_HEAD(policy_list);
static DEFINE_RWLOCK(policy_lock);

#define MAX_POLICY_RULES 128
static unsigned int rule_count;

/* -----------------------------------------------------------------------
 * Built-in default policy rules
 *
 * Order matters: first match wins.
 * --------------------------------------------------------------------- */
static const struct {
	const char *pattern;
	enum jarvis_policy_tier tier;
	u32 ratelimit_per_min;
} jarvis_default_policy[] = {
	/* File reads are safe */
	{ "FileSystemMCP:read_file",       JARVIS_TIER_SAFE,      0   },
	{ "FileSystemMCP:list_directory",  JARVIS_TIER_SAFE,      0   },
	{ "FileSystemMCP:get_file_info",   JARVIS_TIER_SAFE,      0   },
	/* File writes are elevated — audit logged */
	{ "FileSystemMCP:write_file",      JARVIS_TIER_ELEVATED,  30  },
	{ "FileSystemMCP:create_directory",JARVIS_TIER_ELEVATED,  20  },
	/* File deletion is dangerous — needs user confirmation */
	{ "FileSystemMCP:delete_file",     JARVIS_TIER_DANGEROUS, 5   },
	{ "FileSystemMCP:delete_directory",JARVIS_TIER_DANGEROUS, 2   },
	/* Any other filesystem op: elevated */
	{ "FileSystemMCP:*",               JARVIS_TIER_ELEVATED,  20  },
	/* Shell: all commands require user confirmation */
	{ "ShellMCP:run_command",          JARVIS_TIER_DANGEROUS, 20  },
	{ "ShellMCP:run_script",           JARVIS_TIER_DANGEROUS, 10  },
	{ "ShellMCP:approve_command",      JARVIS_TIER_ELEVATED,  0   },
	{ "ShellMCP:deny_command",         JARVIS_TIER_ELEVATED,  0   },
	{ "ShellMCP:*",                    JARVIS_TIER_DANGEROUS, 20  },
	/* Code generation / analysis: elevated */
	{ "CodeGenMCP:*",                  JARVIS_TIER_ELEVATED,  0   },
	{ "CodeAnalysisMCP:*",             JARVIS_TIER_ELEVATED,  0   },
	/* Echo server: always safe (used for testing) */
	{ "EchoMCP:*",                     JARVIS_TIER_SAFE,      0   },
	/* Catch-all: anything unknown is elevated */
	{ "*:*",                           JARVIS_TIER_ELEVATED,  60  },
};

/* -----------------------------------------------------------------------
 * Pattern matching — "server:tool" with per-field "*" wildcard
 * --------------------------------------------------------------------- */

static bool pattern_match(const char *pattern, const char *server, const char *tool)
{
	const char *sep = strchr(pattern, ':');
	char pat_server[JARVIS_POLICY_PATTERN_LEN];
	const char *pat_tool;
	size_t slen;

	if (!sep)
		return false;

	slen = sep - pattern;
	if (slen >= JARVIS_POLICY_PATTERN_LEN)
		return false;

	memcpy(pat_server, pattern, slen);
	pat_server[slen] = '\0';
	pat_tool = sep + 1;

	/* Match server field */
	if (strcmp(pat_server, "*") != 0 && strcmp(pat_server, server) != 0)
		return false;

	/* Match tool field */
	if (strcmp(pat_tool, "*") != 0 && strcmp(pat_tool, tool) != 0)
		return false;

	return true;
}

/* -----------------------------------------------------------------------
 * Rate limiter (simple token bucket, no floating point)
 * --------------------------------------------------------------------- */

static bool ratelimit_check(struct policy_rule *rule)
{
	unsigned long now, elapsed;
	u32 new_tokens;

	if (rule->ratelimit_per_min == 0)
		return true; /* unlimited */

	spin_lock(&rule->rl_lock);

	now     = jiffies;
	elapsed = now - rule->rl_last_refill;

	/* Refill: ratelimit_per_min tokens per 60 seconds */
	if (elapsed >= 60 * HZ) {
		rule->rl_tokens      = rule->ratelimit_per_min;
		rule->rl_last_refill = now;
	} else {
		/* Partial refill proportional to elapsed time */
		new_tokens = (u32)((u64)elapsed * rule->ratelimit_per_min / (60 * HZ));
		rule->rl_tokens = min(rule->rl_tokens + new_tokens,
				      rule->ratelimit_per_min);
		if (new_tokens > 0)
			rule->rl_last_refill = now;
	}

	if (rule->rl_tokens > 0) {
		rule->rl_tokens--;
		spin_unlock(&rule->rl_lock);
		return true;
	}

	spin_unlock(&rule->rl_lock);
	return false;
}

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

/**
 * jarvis_policy_check - look up the policy tier for a server:tool action
 * @server:   MCP server name
 * @tool:     MCP tool name
 * @tier_out: filled with resolved tier
 *
 * Returns true if the action is allowed at the current rate, false if
 * rate-limited or FORBIDDEN.
 */
bool jarvis_policy_check(const char *server, const char *tool,
			 enum jarvis_policy_tier *tier_out)
{
	struct policy_rule *rule;
	bool allowed = false;

	read_lock(&policy_lock);

	list_for_each_entry(rule, &policy_list, node) {
		if (!pattern_match(rule->pattern, server, tool))
			continue;

		*tier_out = rule->tier;

		if (rule->tier == JARVIS_TIER_FORBIDDEN) {
			pr_info("FORBIDDEN: %s:%s\n", server, tool);
			allowed = false;
		} else {
			allowed = ratelimit_check(rule);
			if (!allowed)
				pr_warn("rate-limited: %s:%s (tier=%u, limit=%u/min)\n",
					server, tool, rule->tier,
					rule->ratelimit_per_min);
		}
		goto out;
	}

	/* No rule matched — default to ELEVATED, allowed */
	*tier_out = JARVIS_TIER_ELEVATED;
	allowed   = true;

out:
	read_unlock(&policy_lock);
	return allowed;
}
EXPORT_SYMBOL_GPL(jarvis_policy_check);

/* -----------------------------------------------------------------------
 * ioctl handlers — called from jarvis_core.c
 * --------------------------------------------------------------------- */

long jarvis_policy_ioctl(unsigned int cmd, void __user *uarg)
{
	switch (cmd) {

	case JARVIS_IOC_POLICY_ADD: {
		struct jarvis_policy_entry entry;
		struct policy_rule *rule;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&entry, uarg, sizeof(entry)))
			return -EFAULT;
		if (entry.tier > JARVIS_TIER_FORBIDDEN)
			return -EINVAL;
		if (strnlen(entry.pattern, JARVIS_POLICY_PATTERN_LEN) == 0 ||
		    !strchr(entry.pattern, ':'))
			return -EINVAL;

		write_lock(&policy_lock);
		if (rule_count >= MAX_POLICY_RULES) {
			write_unlock(&policy_lock);
			return -ENOSPC;
		}

		rule = kzalloc(sizeof(*rule), GFP_ATOMIC);
		if (!rule) {
			write_unlock(&policy_lock);
			return -ENOMEM;
		}

		strlcpy(rule->pattern, entry.pattern, sizeof(rule->pattern));
		rule->tier             = entry.tier;
		rule->ratelimit_per_min = entry.ratelimit_per_min;
		spin_lock_init(&rule->rl_lock);
		rule->rl_tokens      = entry.ratelimit_per_min;
		rule->rl_last_refill = jiffies;

		/* Insert at head (highest priority) */
		list_add(&rule->node, &policy_list);
		rule_count++;
		write_unlock(&policy_lock);

		pr_info("policy added: \"%s\" tier=%u rate=%u/min\n",
			rule->pattern, rule->tier, rule->ratelimit_per_min);
		return 0;
	}

	case JARVIS_IOC_POLICY_DEL: {
		char pattern[JARVIS_POLICY_PATTERN_LEN] = {};
		struct policy_rule *rule, *tmp;
		bool found = false;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(pattern, uarg, sizeof(pattern) - 1))
			return -EFAULT;

		write_lock(&policy_lock);
		list_for_each_entry_safe(rule, tmp, &policy_list, node) {
			if (strncmp(rule->pattern, pattern,
				    JARVIS_POLICY_PATTERN_LEN) == 0) {
				list_del(&rule->node);
				kfree(rule);
				rule_count--;
				found = true;
				break;
			}
		}
		write_unlock(&policy_lock);

		return found ? 0 : -ENOENT;
	}

	case JARVIS_IOC_POLICY_CHECK: {
		struct jarvis_policy_check check;
		enum jarvis_policy_tier tier;
		bool allowed;

		if (copy_from_user(&check, uarg, sizeof(check)))
			return -EFAULT;

		check.server[sizeof(check.server) - 1] = '\0';
		check.tool[sizeof(check.tool) - 1]     = '\0';

		allowed        = jarvis_policy_check(check.server, check.tool, &tier);
		check.tier     = tier;
		check.allowed  = allowed ? 1 : 0;

		if (copy_to_user(uarg, &check, sizeof(check)))
			return -EFAULT;
		return 0;
	}

	case JARVIS_IOC_POLICY_RESET: {
		struct policy_rule *rule, *tmp;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		write_lock(&policy_lock);
		list_for_each_entry_safe(rule, tmp, &policy_list, node) {
			list_del(&rule->node);
			kfree(rule);
		}
		rule_count = 0;
		write_unlock(&policy_lock);

		/* Re-install defaults */
		return jarvis_policy_load_defaults();
	}

	default:
		return -ENOTTY;
	}
}

/* -----------------------------------------------------------------------
 * Sysfs: read the current policy table
 * --------------------------------------------------------------------- */

static ssize_t policy_table_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct policy_rule *rule;
	ssize_t len = 0;
	static const char * const tier_names[] = {
		"safe", "elevated", "dangerous", "forbidden"
	};

	read_lock(&policy_lock);
	list_for_each_entry(rule, &policy_list, node) {
		const char *tier_str = (rule->tier < ARRAY_SIZE(tier_names))
					? tier_names[rule->tier] : "?";
		len += sysfs_emit_at(buf, len, "%-40s  %-10s  %u/min\n",
				     rule->pattern, tier_str,
				     rule->ratelimit_per_min);
		if (len >= PAGE_SIZE - 80)
			break;
	}
	read_unlock(&policy_lock);

	return len ?: sysfs_emit(buf, "(empty)\n");
}
static DEVICE_ATTR_RO(policy_table);

static struct attribute *jarvis_policy_attrs[] = {
	&dev_attr_policy_table.attr,
	NULL,
};

static const struct attribute_group jarvis_policy_attr_group = {
	.name  = "policy",
	.attrs = jarvis_policy_attrs,
};

/* -----------------------------------------------------------------------
 * Default rule loader
 * --------------------------------------------------------------------- */

int jarvis_policy_load_defaults(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(jarvis_default_policy); i++) {
		struct policy_rule *rule;

		if (rule_count >= MAX_POLICY_RULES)
			break;

		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule)
			return -ENOMEM;

		strlcpy(rule->pattern, jarvis_default_policy[i].pattern,
			sizeof(rule->pattern));
		rule->tier              = jarvis_default_policy[i].tier;
		rule->ratelimit_per_min = jarvis_default_policy[i].ratelimit_per_min;
		spin_lock_init(&rule->rl_lock);
		rule->rl_tokens      = rule->ratelimit_per_min;
		rule->rl_last_refill = jiffies;

		list_add_tail(&rule->node, &policy_list);
		rule_count++;
	}

	pr_info("loaded %u default policy rules\n", rule_count);
	return 0;
}

/* -----------------------------------------------------------------------
 * Init / exit
 * --------------------------------------------------------------------- */

int jarvis_policy_init(struct device *parent_dev)
{
	int rc;

	rc = jarvis_policy_load_defaults();
	if (rc)
		return rc;

	rc = sysfs_create_group(&parent_dev->kobj, &jarvis_policy_attr_group);
	if (rc)
		pr_err("failed to create policy sysfs group: %d\n", rc);
	else
		pr_info("policy engine ready (%u rules)\n", rule_count);
	return rc;
}

void jarvis_policy_exit(struct device *parent_dev)
{
	struct policy_rule *rule, *tmp;

	sysfs_remove_group(&parent_dev->kobj, &jarvis_policy_attr_group);

	write_lock(&policy_lock);
	list_for_each_entry_safe(rule, tmp, &policy_list, node) {
		list_del(&rule->node);
		kfree(rule);
	}
	rule_count = 0;
	write_unlock(&policy_lock);
}
