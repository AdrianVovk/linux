// SPDX-License-Identifier: GPL-2.0+

#include "../integrity.h"

static __init int vendor_keyring_init(void)
{
	int rc;

	rc = integrity_init_keyring(INTEGRITY_KEYRING_VENDOR);
	if (rc)
		return rc;

	pr_notice("Vendor keyring initialized\n");
	return 0;
}
device_initcall(vendor_keyring_init);

void __init add_to_vendor_keyring(const char *source, const void *data, size_t len)
{
	key_perm_t perm;
	int rc;

	perm = (KEY_POS_ALL & ~KEY_POS_SETATTR) | KEY_USR_VIEW;
	rc = integrity_load_cert(INTEGRITY_KEYRING_VENDOR, source, data, len, perm);
	if (rc)
		pr_info("Error adding keys to vendor keyring %s\n", source);
}
