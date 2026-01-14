// SPDX-License-Identifier: GPL-2.0
/*
 * This module contains support for the Linux Vendor Signing Keys (VSK)
 * EFI configuration table, which is identified by LINUX_EFI_VSK_TABLE_GUID.
 * This provides a mechanism for EFI bootloaders to insert keys belonging to the
 * OS vendor into the kernel's keyring.
 *
 * The table has the following format:
 * - The first 8 bytes are VSK_TABLE_MAGIC
 * - The next 8 bytes are the size of the following EFI Signature List
 * - The rest of the table is an EFI Signature List
 *
 * This format allows for convenient manipulation by bootloaders, and the
 * inclusion of multiple keys. The UEFI shim loader can store its compiled-in
 * vendor certificates in ESL format, and so it can install that data directly
 * into a config table. Later boot stages (i.e. systemd-stub) can have their own
 * vendor certificates to add to the list, and they can do so by reading the
 * config table, concating their certificates onto the end, and updating the
 * size.
 *
 * The EFI signature list is made available to userspace via a read-only sysfs
 * entry under /sys/firmware/efi/vsk
 */

#define pr_fmt(fmt) "vsk-table: " fmt

#include <linux/capability.h>
#include <linux/efi.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include <asm/early_ioremap.h>

static struct efi_vsk_table *efi_vsk_table;
static size_t __initdata efi_vsk_table_size;

#define VSK_TABLE_MAGIC 0x56656e644b657973 // "VendKeys"

void __init efi_vsk_table_init(void)
{
	efi_memory_desc_t mem_desc;
	struct efi_vsk_table *table;
	u64 magic;
	u64 esl_size;
	int rc;

	if (!efi_enabled(EFI_MEMMAP))
		return;

	if (efi.vsk_table == EFI_INVALID_TABLE_ADDR)
		return;

	rc = efi_mem_desc_lookup(efi.vsk_table, &mem_desc);
	if (rc) {
		pr_warn("Table is not within the EFI memory map\n");
		return;
	}

	table = early_memremap(efi.vsk_table, sizeof(*table));
	if (table == NULL) {
		pr_err("Could not map table header\n");
		return;
	}

	magic = table->magic;
	esl_size = table->esl_size;
	early_memunmap(table, sizeof(*table));

	if (magic != VSK_TABLE_MAGIC) {
		pr_err("Table has wrong magic number\n");
		return;
	}

	if (esl_size == 0) {
		pr_err("Table has no certs\n");
		return;
	}

	efi_vsk_table_size = sizeof(*table) + esl_size;

	if (mem_desc.type == EFI_BOOT_SERVICES_DATA)
		efi_mem_reserve(efi.vsk_table, efi_vsk_table_size);
}

struct efi_vsk_table *efi_get_vsk(void)
{
	return efi_vsk_table;
}

static ssize_t vsk_read(struct file *filp, struct kobject *kobj,
			const struct bin_attribute *attr, char *buf,
			loff_t offset, size_t count)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (offset >= efi_vsk_table->esl_size)
		return 0;
	if (count > efi_vsk_table->esl_size - offset)
		count = efi_vsk_table->esl_size - offset;

	memcpy(buf, efi_vsk_table->esl + offset, count);
	return count;
}

static struct bin_attribute efi_vsk_bin_attr = {
	.attr = {
		.name = "vsk",
		.mode = 0400,
	},
	.read = vsk_read,
};

static int __init efi_vsk_sysfs_init(void)
{
	int rc;

	if (efi_vsk_table_size == 0)
		return -ENOENT;

	efi_vsk_table = memremap(efi.vsk_table, efi_vsk_table_size, MEMREMAP_WB);
	if (efi_vsk_table == NULL) {
		pr_err("Could not map table\n");
		return -ENOMEM;
	}

	efi_vsk_bin_attr.size = efi_vsk_table.esl_size;
	rc = sysfs_create_bin_file(efi_kobj, &efi_vsk_bin_attr);
	if (rc) {
		pr_err("Failed to create sysfs entry\n");
		return rc;
	}

	return 0;
}
fs_initcall(efi_vsk_sysfs_init);
