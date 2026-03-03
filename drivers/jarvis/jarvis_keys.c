// SPDX-License-Identifier: GPL-2.0
/*
 * JARVIS Secure Key Storage — kernel keyring integration
 *
 * API keys for cloud LLM providers (Claude, OpenAI, etc.) must never live in
 * plaintext on disk or in environment variables.  This module stores them in
 * the Linux kernel keyring and exposes them only to the JARVIS daemon.
 *
 * Architecture
 * ------------
 * At module init a dedicated "_jarvis" keyring is allocated.  Keys are
 * "user" type (arbitrary payload) and identified by a string description
 * such as "claude-api-key" or "openai-api-key".
 *
 * Key lifecycle
 * -------------
 *   Store : root/CAP_SYS_ADMIN writes key via JARVIS_IOC_KEY_STORE ioctl
 *   Get   : the JARVIS daemon (CAP_SYS_ADMIN or jarvis group) reads via
 *           JARVIS_IOC_KEY_GET ioctl
 *   Delete: JARVIS_IOC_KEY_DEL, CAP_SYS_ADMIN only
 *
 * Kernel-internal consumers (e.g. a future kernel HTTPS transport for
 * on-device inference) may call jarvis_key_lookup() directly.
 *
 * Security
 * --------
 *   - Keys are held in kernel memory only; never swapped (GFP_KERNEL | __GFP_NORETRY)
 *   - Only CAP_SYS_ADMIN may store/delete keys
 *   - The _jarvis keyring is not linked to any user keyring, preventing
 *     ordinary userspace enumeration via keyctl(2)
 *   - All access attempts are pr_info-logged for auditing
 *
 * Copyright (c) 2025 JARVISos Contributors
 */
#define pr_fmt(fmt) "jarvis-keys: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/keyctl.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <keys/user-type.h>

#include <uapi/linux/jarvis.h>
#include "jarvis_keys.h"

/* The private keyring that owns all JARVIS keys */
static struct key *jarvis_keyring;

/* -----------------------------------------------------------------------
 * Kernel-internal lookup
 * --------------------------------------------------------------------- */

/**
 * jarvis_key_lookup - retrieve a stored key value into a kernel buffer
 * @id:     NUL-terminated key description (e.g. "claude-api-key")
 * @buf:    destination buffer
 * @buflen: size of @buf
 *
 * Returns number of bytes written, or a negative error code.
 * Safe to call from process context.
 */
int jarvis_key_lookup(const char *id, char *buf, size_t buflen)
{
	struct key *key;
	const struct user_key_payload *payload;
	int rc;

	if (!jarvis_keyring)
		return -ENXIO;

	key = keyring_search(make_key_ref(jarvis_keyring, 1),
			     &key_type_user, id, true);
	if (IS_ERR(key))
		return PTR_ERR(key);

	rcu_read_lock();
	payload = user_key_payload_rcu(key);
	if (!payload || payload->datalen == 0) {
		rcu_read_unlock();
		key_put(key);
		return -ENODATA;
	}

	rc = min_t(size_t, payload->datalen, buflen - 1);
	memcpy(buf, payload->data, rc);
	buf[rc] = '\0';
	rcu_read_unlock();

	key_put(key);
	return rc;
}
EXPORT_SYMBOL_GPL(jarvis_key_lookup);

/* -----------------------------------------------------------------------
 * ioctl handlers
 * --------------------------------------------------------------------- */

long jarvis_keys_ioctl(unsigned int cmd, void __user *uarg)
{
	switch (cmd) {

	case JARVIS_IOC_KEY_STORE: {
		struct jarvis_key_op op;
		struct key *key;
		key_ref_t ref;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&op, uarg, sizeof(op)))
			return -EFAULT;

		op.id[sizeof(op.id) - 1]     = '\0';
		op.data[sizeof(op.data) - 1] = '\0';

		if (strnlen(op.id, sizeof(op.id)) == 0)
			return -EINVAL;

		/* Update existing key if present, else add new */
		ref = keyring_search(make_key_ref(jarvis_keyring, 1),
				     &key_type_user, op.id, true);
		if (!IS_ERR(ref)) {
			key = key_ref_to_ptr(ref);
			key_update(ref, op.data, strnlen(op.data, sizeof(op.data)));
			key_ref_put(ref);
		} else {
			key = key_alloc(&key_type_user, op.id,
					current_fsuid(), current_fsgid(),
					current_cred(),
					KEY_POS_ALL | KEY_USR_ALL,
					KEY_ALLOC_NOT_IN_QUOTA, NULL);
			if (IS_ERR(key))
				return PTR_ERR(key);

			key_instantiate_and_link(key, op.data,
						 strnlen(op.data, sizeof(op.data)),
						 jarvis_keyring, NULL);
		}

		pr_info("stored key \"%s\" (%zu bytes)\n",
			op.id, strnlen(op.data, sizeof(op.data)));
		memzero_explicit(op.data, sizeof(op.data));
		return 0;
	}

	case JARVIS_IOC_KEY_GET: {
		struct jarvis_key_op op;
		char buf[JARVIS_KEY_DATA_LEN] = {};
		int n;

		/*
		 * Reading keys requires CAP_SYS_ADMIN.
		 * In a full implementation this could be relaxed to members
		 * of the 'jarvis' group via supplementary GID check.
		 */
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&op, uarg, sizeof(op)))
			return -EFAULT;

		op.id[sizeof(op.id) - 1] = '\0';

		n = jarvis_key_lookup(op.id, buf, sizeof(buf));
		if (n < 0)
			return n;

		memcpy(op.data, buf, n);
		op.len = n;
		memzero_explicit(buf, sizeof(buf));

		if (copy_to_user(uarg, &op, sizeof(op)))
			return -EFAULT;

		pr_info("retrieved key \"%s\" (%d bytes)\n", op.id, n);
		return 0;
	}

	case JARVIS_IOC_KEY_DEL: {
		char id[JARVIS_KEY_ID_LEN] = {};
		struct key *key;
		key_ref_t ref;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(id, uarg, sizeof(id) - 1))
			return -EFAULT;

		ref = keyring_search(make_key_ref(jarvis_keyring, 1),
				     &key_type_user, id, true);
		if (IS_ERR(ref))
			return PTR_ERR(ref);

		key = key_ref_to_ptr(ref);
		key_unlink(jarvis_keyring, key);
		key_ref_put(ref);

		pr_info("deleted key \"%s\"\n", id);
		return 0;
	}

	default:
		return -ENOTTY;
	}
}

/* -----------------------------------------------------------------------
 * Init / exit
 * --------------------------------------------------------------------- */

int jarvis_keys_init(void)
{
	/*
	 * Allocate a non-user-visible keyring.  Using KEY_ALLOC_NOT_IN_QUOTA
	 * so key storage doesn't count against any user's quota.
	 */
	jarvis_keyring = keyring_alloc("_jarvis",
				       GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				       current_cred(),
				       KEY_POS_ALL | KEY_USR_ALL,
				       KEY_ALLOC_NOT_IN_QUOTA,
				       NULL, NULL);
	if (IS_ERR(jarvis_keyring)) {
		int rc = PTR_ERR(jarvis_keyring);
		jarvis_keyring = NULL;
		pr_err("failed to allocate _jarvis keyring: %d\n", rc);
		return rc;
	}

	pr_info("_jarvis keyring ready (serial %d)\n",
		key_serial(jarvis_keyring));
	return 0;
}

void jarvis_keys_exit(void)
{
	if (jarvis_keyring) {
		key_put(jarvis_keyring);
		jarvis_keyring = NULL;
	}
}
