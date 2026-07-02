// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <ccan/hash/hash.h>
#include <ccan/htable/htable_type.h>

#include <libnvme.h>

#include "private.h"
#include "private-ctrl-map.h"
#include "compiler-attributes.h"
#include "cleanup.h"

#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <winioctl.h>
#include <ntddscsi.h>

#include <initguid.h>
#include <devpkey.h>

struct ctrl_map_entry {
	char *ctrl_name;   /* format "nvmeX" */
	WCHAR *ctrl_path;  /* format "\\\\?\\pci..." */
	struct nvme_id_ctrl id_ctrl;
	char *subsys_name; /* borrowed from subsys_map */
};

static const char *ctrl_map_entry_keyof(const struct ctrl_map_entry *entry)
{
	return entry->ctrl_name;
}

static size_t ctrl_map_entry_hash(const char *ctrl_name)
{
	return hash_string(ctrl_name);
}

static bool ctrl_map_entry_eq(const struct ctrl_map_entry *entry,
			      const char *ctrl_name)
{
	return strcmp(entry->ctrl_name, ctrl_name) == 0;
}

HTABLE_DEFINE_TYPE(struct ctrl_map_entry, ctrl_map_entry_keyof,
		   ctrl_map_entry_hash, ctrl_map_entry_eq, ctrl_map);

/*
 * Maps a subsystem NQN to its subsystem name.  The subnqn is a
 * fixed-length, space-padded buffer (not necessarily NUL-terminated),
 * so it is hashed and compared over its full NVME_NQN_LENGTH bytes.
 */
struct subsys_entry {
	char subnqn[NVME_NQN_LENGTH];
	char *subsys_name;
};

static const char *subsys_entry_keyof(const struct subsys_entry *entry)
{
	return entry->subnqn;
}

static size_t subsys_entry_hash(const char *subnqn)
{
	return hash(subnqn, NVME_NQN_LENGTH, 0);
}

static bool subsys_entry_eq(const struct subsys_entry *entry,
			    const char *subnqn)
{
	return memcmp(entry->subnqn, subnqn, NVME_NQN_LENGTH) == 0;
}

HTABLE_DEFINE_TYPE(struct subsys_entry, subsys_entry_keyof,
		   subsys_entry_hash, subsys_entry_eq, subsys_map);

static struct ctrl_map ctrl_map;
static bool ctrl_map_initialized = false;
static struct subsys_map subsys_map;
static bool htables_ready = false;  /* ccan hash tables have been initialized */

/*
 * Compare two controller names numerically.  Names share a common
 * textual prefix ("nvme") followed by an integer index, so a plain
 * strcmp() would order "nvme10" before "nvme2".  Walk both strings
 * together and, whenever a run of digits begins in both, compare the
 * runs by numeric value; otherwise fall back to byte comparison.
 */
static int ctrl_name_cmp(const void *a, const void *b)
{
	const char *const *ka = a;
	const char *const *kb = b;
	const char *sa = *ka;
	const char *sb = *kb;

	while (*sa && *sb) {
		if (isdigit((unsigned char)*sa) &&
		    isdigit((unsigned char)*sb)) {
			char *enda, *endb;
			unsigned long va = strtoul(sa, &enda, 10);
			unsigned long vb = strtoul(sb, &endb, 10);

			if (va != vb)
				return va < vb ? -1 : 1;

			sa = enda;
			sb = endb;
			continue;
		}

		if (*sa != *sb)
			return (unsigned char)*sa - (unsigned char)*sb;

		sa++;
		sb++;
	}

	return (unsigned char)*sa - (unsigned char)*sb;
}

const char **libnvme_ctrl_map_get_ctrl_names(size_t *count)
{
	struct ctrl_map_iter iter;
	struct ctrl_map_entry *entry;
	const char **keys;
	size_t n = ctrl_map_count(&ctrl_map);
	size_t i = 0;

	if (count)
		*count = 0;

	if (!n)
		return NULL;

	keys = calloc(n + 1, sizeof(*keys));
	if (!keys)
		return NULL;

	for (entry = ctrl_map_first(&ctrl_map, &iter); entry;
	     entry = ctrl_map_next(&ctrl_map, &iter)) {
		if (i >= n)
			break;

		keys[i++] = ctrl_map_entry_keyof(entry);
	}

	qsort(keys, i, sizeof(*keys), ctrl_name_cmp);
	keys[i] = NULL;

	if (count)
		*count = i;

	return keys;
}

void libnvme_ctrl_map_clear(void)
{
	struct ctrl_map_entry *entry;
	struct ctrl_map_iter ctrl_iter;
	struct subsys_entry *subsys;
	struct subsys_map_iter subsys_iter;

	if (!htables_ready)
		return;

	for (entry = ctrl_map_first(&ctrl_map, &ctrl_iter); entry;
	     entry = ctrl_map_next(&ctrl_map, &ctrl_iter)) {
		free(entry->ctrl_name);
		free(entry->ctrl_path);
		/* subsys_name is owned by subsys_map, freed below */
		free(entry);
	}
	ctrl_map_clear(&ctrl_map);

	for (subsys = subsys_map_first(&subsys_map, &subsys_iter); subsys;
	     subsys = subsys_map_next(&subsys_map, &subsys_iter)) {
		free(subsys->subsys_name);
		free(subsys);
	}
	subsys_map_clear(&subsys_map);

	ctrl_map_initialized = false;
	htables_ready = false;
}

/*
 * Resolve the subsystem name for a controller's subnqn.  Looks the
 * subnqn up in subsys_map; if present, returns the cached name.
 * Otherwise generates the next "nvme-subsysN" name, inserts it, and
 * returns it.  The returned string is owned by subsys_map (borrowed by
 * the caller).  Returns NULL on allocation failure.
 */
static char *find_or_create_subsys_name(const struct nvme_id_ctrl *id_ctrl)
{
	struct subsys_entry *entry;
	char *subsys_name;
	int next_subsys_index;

	entry = subsys_map_get(&subsys_map, id_ctrl->subnqn);
	if (entry)
		return entry->subsys_name;

	next_subsys_index = subsys_map_count(&subsys_map);
	if (asprintf(&subsys_name, "nvme-subsys%d", next_subsys_index) < 0)
		return NULL;

	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		free(subsys_name);
		return NULL;
	}

	memcpy(entry->subnqn, id_ctrl->subnqn, NVME_NQN_LENGTH);
	entry->subsys_name = subsys_name;

	/* Key is derived from entry->subnqn via subsys_entry_keyof() */
	if (!subsys_map_add(&subsys_map, entry)) {
		free(subsys_name);
		free(entry);
		return NULL;
	}

	return subsys_name;
}

static int libnvme_ctrl_map_add(DWORD ctrl_index, const WCHAR *ctrl_path,
		const struct nvme_id_ctrl *id_ctrl)
{
	struct ctrl_map_entry *entry;
	char *ctrl_name_copy;
	WCHAR *ctrl_path_copy;
	char *subsys_name;

	if (!ctrl_path)
		return -EINVAL;

	if (asprintf(&ctrl_name_copy, "nvme%lu", ctrl_index) < 0)
		return -ENOMEM;

	ctrl_path_copy = _wcsdup(ctrl_path);
	if (!ctrl_path_copy) {
		free(ctrl_name_copy);
		return -ENOMEM;
	}

	subsys_name = find_or_create_subsys_name(id_ctrl);
	if (!subsys_name) {
		free(ctrl_name_copy);
		free(ctrl_path_copy);
		return -ENOMEM;
	}

	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		free(ctrl_name_copy);
		free(ctrl_path_copy);
		return -ENOMEM;
	}

	entry->ctrl_name = ctrl_name_copy;
	entry->ctrl_path = ctrl_path_copy;
	entry->id_ctrl = *id_ctrl;
	entry->subsys_name = subsys_name;

	/* Key is derived from entry->ctrl_name via ctrl_map_entry_keyof() */
	if (!ctrl_map_add(&ctrl_map, entry)) {
		free(ctrl_name_copy);
		free(ctrl_path_copy);
		free(entry);
		return -ENOMEM;
	}

	return 0;
}

/*
 * Extract the "nvmeX" controller portion from a controller or namespace
 * name (e.g. "nvme0" or "nvme0n1"), where X is one or more digits, and
 * return it as a newly allocated string.  Returns NULL if the name does
 * not begin with "nvme" followed by a digit, or on allocation failure.
 * Any trailing characters after the controller index are ignored; the
 * caller must free the result.
 */
static char *ctrl_name_extract(const char *ctrl_name)
{
	const char *p = ctrl_name;
	const char *ctrl_end;
	char *ctrl;
	size_t len;

	if (!ctrl_name)
		return NULL;

	/* ctrl_name must start with "nvme" */
	if (strncmp(p, "nvme", 4))
		return NULL;
	p += 4;

	/* X: one or more digits */
	if (!isdigit((unsigned char)*p))
		return NULL;
	while (isdigit((unsigned char)*p))
		p++;

	ctrl_end = p;

	len = ctrl_end - ctrl_name;
	ctrl = malloc(len + 1);
	if (!ctrl)
		return NULL;

	memcpy(ctrl, ctrl_name, len);
	ctrl[len] = '\0';

	return ctrl;
}

/*
 * Issue an Identify Controller command on the given handle.
 * Creates a temporary transport handle internally using the caller's
 * global context.
 * Returns 0 on success with id_ctrl filled in, negative errno on failure.
 */
static int identify_ctrl_from_handle(struct libnvme_global_ctx *ctx,
		libnvme_fd_t h, struct nvme_id_ctrl *id_ctrl)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int ret;

	hdl = __libnvme_create_transport_handle(ctx);
	if (!hdl)
		return -ENOMEM;

	hdl->fd = h;
	hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;

	memset(id_ctrl, 0, sizeof(*id_ctrl));
	nvme_init_identify_ctrl(&cmd, id_ctrl);
	ret = libnvme_exec_admin_passthru(hdl, &cmd);

	/*
	 * Detach the handle before freeing the transport
	 * handle so the caller retains ownership of the handle.
	 */
	hdl->fd = INVALID_HANDLE_VALUE;
	free(hdl);

	return ret;
}

/*
 * Query adapter BusType via IOCTL_STORAGE_QUERY_PROPERTY /
 * StorageAdapterProperty.
 * Returns 0 on success (bus type written to *out_bus_type).
 */
static int get_adapter_bus_type(libnvme_fd_t h, STORAGE_BUS_TYPE *out_bus_type)
{
	STORAGE_PROPERTY_QUERY q = { 0 };
	STORAGE_DESCRIPTOR_HEADER hdr;
	STORAGE_ADAPTER_DESCRIPTOR *ad;
	BYTE *buf;
	DWORD bytes = 0;

	q.PropertyId = StorageAdapterProperty;
	q.QueryType = PropertyStandardQuery;

	/* First query to get the required buffer size */
	if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
			     &q, sizeof(q), &hdr, sizeof(hdr),
			     &bytes, NULL))
		return -1;

	buf = calloc(1, hdr.Size);
	if (!buf)
		return -ENOMEM;

	if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
			     &q, sizeof(q),
			     buf, hdr.Size,
			     &bytes, NULL)) {
		free(buf);
		return -1;
	}

	ad = (STORAGE_ADAPTER_DESCRIPTOR *)buf;
	*out_bus_type = (STORAGE_BUS_TYPE)ad->BusType;
	free(buf);
	return 0;
}

/*
 * Enumerate the next device interface and return a wide-string
 * copy of the device path.  Returns:
 *   0  success  (*device_interface_path set, caller must free)
 *   -1  non-fatal failure (skip this interface)
 *   -ENOMEM  allocation failure
 *   -ENOENT  no more items (enumeration complete)
 */
static int get_device_interface_path(HDEVINFO hdev,
		DWORD index,
		WCHAR **device_interface_path,
		SP_DEVINFO_DATA *devinfo_data_out)
{
	SP_DEVICE_INTERFACE_DATA if_data = {
		.cbSize = sizeof(if_data),
	};
	DWORD required_size = 0;
	PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail;
	SP_DEVINFO_DATA dev_info_data = {
		.cbSize = sizeof(SP_DEVINFO_DATA),
	};

	if (!SetupDiEnumDeviceInterfaces(hdev, NULL,
					 &GUID_DEVINTERFACE_STORAGEPORT,
					 index, &if_data)) {
		if (GetLastError() == ERROR_NO_MORE_ITEMS)
			return -ENOENT;
		return -1;
	}

	SetupDiGetDeviceInterfaceDetailW(hdev, &if_data, NULL, 0,
					 &required_size, NULL);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !required_size)
		return -1;

	detail = calloc(1, required_size);
	if (!detail)
		return -ENOMEM;

	detail->cbSize = sizeof(*detail);
	if (!SetupDiGetDeviceInterfaceDetailW(hdev, &if_data, detail,
					      required_size,
					      NULL, &dev_info_data)) {
		free(detail);
		return -1;
	}

	*device_interface_path = _wcsdup(detail->DevicePath);
	free(detail);
	if (!*device_interface_path)
		return -ENOMEM;

	if (devinfo_data_out)
		*devinfo_data_out = dev_info_data;

	return 0;
}

int libnvme_ctrl_map_init(struct libnvme_global_ctx *ctx)
{
	HDEVINFO hdev;
	PWSTR ctrl_path = NULL;
	HANDLE h = INVALID_HANDLE_VALUE;
	int ret;
	DWORD index;
	DWORD ctrl_index = 0;
	STORAGE_BUS_TYPE bus_type;

	if (ctrl_map_initialized)
		return 0;

	ctrl_map_init(&ctrl_map);
	subsys_map_init(&subsys_map);
	htables_ready = true;

	hdev = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_STORAGEPORT, NULL, NULL,
				    DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (hdev == INVALID_HANDLE_VALUE)
		return -ENODEV;

	for (index = 0;; index++) {
		struct nvme_id_ctrl id_ctrl;

		h = INVALID_HANDLE_VALUE;
		ctrl_path = NULL;

		ret = get_device_interface_path(hdev, index, &ctrl_path, NULL);
		if (ret == -ENOENT)
			break;
		if (ret == -ENOMEM)
			goto enomem;
		if (ret == -1)
			continue;

		h = CreateFileW(ctrl_path, 0,
				FILE_SHARE_READ | FILE_SHARE_WRITE |
				FILE_SHARE_DELETE,
				NULL, OPEN_EXISTING, 0, NULL);
		if (h == INVALID_HANDLE_VALUE)
			goto next_entry;

		if (get_adapter_bus_type(h, &bus_type) ||
		    bus_type != BusTypeNvme)
			goto next_entry;

		ret = identify_ctrl_from_handle(ctx, h, &id_ctrl);
		if (ret)
			goto next_entry;

		ret = libnvme_ctrl_map_add(ctrl_index, ctrl_path, &id_ctrl);
		if (ret < 0)
			goto enomem;
		ctrl_index++;

next_entry:
		free(ctrl_path);
		ctrl_path = NULL;
		if (h != INVALID_HANDLE_VALUE)
			CloseHandle(h);
	}

	SetupDiDestroyDeviceInfoList(hdev);
	ctrl_map_initialized = true;
	return 0;

enomem:
	free(ctrl_path);
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
	SetupDiDestroyDeviceInfoList(hdev);
	libnvme_ctrl_map_clear();
	return -ENOMEM;
}

struct ctrl_map_entry *libnvme_ctrl_map_lookup(struct libnvme_global_ctx *ctx,
		const char *ctrl_name)
{
	__cleanup_free char *ctrl_name_copy = NULL;

	if (!ctrl_name)
		return NULL;

	ctrl_name_copy = ctrl_name_extract(ctrl_name);
	if (!ctrl_name_copy)
		return NULL;

	if (libnvme_ctrl_map_init(ctx))
		return NULL;

	return ctrl_map_get(&ctrl_map, ctrl_name_copy);
}

const struct ctrl_map_entry *
libnvme_ctrl_map_lookup_by_physdrive(struct libnvme_global_ctx *ctx,
		const char *drive_path)
{
	DWORD target_num;
	char *endptr;
	const char *num_str;
	struct ctrl_map_entry *entry;
	struct ctrl_map_iter iter;

	if (!drive_path)
		return NULL;

	/*
	 * Accept \\.\PhysicalDriveX format and extract the
	 * device number X from the path.
	 */
	num_str = drive_path;
	if (strncmp(num_str, "\\\\.\\PhysicalDrive", 17) == 0)
		num_str += 17;
	else if (strncmp(num_str, "PhysicalDrive", 13) == 0)
		num_str += 13;

	target_num = strtoul(num_str, &endptr, 10);
	if (endptr == num_str || *endptr != '\0')
		return NULL;

	if (libnvme_ctrl_map_init(ctx))
		return NULL;

	for (entry = ctrl_map_first(&ctrl_map, &iter); entry;
	     entry = ctrl_map_next(&ctrl_map, &iter)) {
		DWORD *device_numbers = NULL;
		int dev_count = 0;
		int ret;
		int j;

		ret = libnvme_ctrl_map_entry_scan_device_numbers(
			entry, &device_numbers, &dev_count);
		if (ret)
			continue;

		for (j = 0; j < dev_count; j++) {
			if (device_numbers[j] == target_num) {
				free(device_numbers);
				return entry;
			}
		}

		free(device_numbers);
	}

	return NULL;
}

int libnvme_ctrl_map_entry_set_id_ctrl(struct ctrl_map_entry *entry,
		const struct nvme_id_ctrl *id)
{
	if (!entry || !id)
		return -EINVAL;

	entry->id_ctrl = *id;
	return 0;
}

const char *libnvme_ctrl_map_entry_get_ctrl_name(
		const struct ctrl_map_entry *entry)
{
	if (!entry || !entry->ctrl_name)
		return NULL;

	return entry->ctrl_name;
}

int libnvme_ctrl_map_entry_get_ctrl_path(const struct ctrl_map_entry *entry,
		char **ctrl_path)
{
	int path_len;
	char *ctrl_path_copy;

	if (!entry || !ctrl_path || !entry->ctrl_path)
		return -EINVAL;

	*ctrl_path = NULL;

	path_len = WideCharToMultiByte(CP_UTF8, 0, entry->ctrl_path, -1,
				       NULL, 0, NULL, NULL);
	if (path_len <= 0)
		return -EINVAL;

	ctrl_path_copy = malloc(path_len);
	if (!ctrl_path_copy)
		return -ENOMEM;

	if (!WideCharToMultiByte(CP_UTF8, 0, entry->ctrl_path, -1,
				 ctrl_path_copy, path_len, NULL, NULL)) {
		free(ctrl_path_copy);
		return -EINVAL;
	}

	*ctrl_path = ctrl_path_copy;
	return 0;
}

int libnvme_ctrl_map_entry_get_pci_address(const struct ctrl_map_entry *entry,
		char **address)
{
	WCHAR instance_id[MAX_DEVICE_ID_LEN];
	WCHAR location_info[256];
	DEVPROPTYPE prop_type = 0;
	ULONG size;
	CONFIGRET cr;
	DEVINST devinst;
	unsigned int bus = 0, device = 0, function = 0;
	char *addr;

	if (!entry || !address || !entry->ctrl_path)
		return -EINVAL;

	*address = NULL;

	/* Get the device instance ID from the interface path */
	size = sizeof(instance_id);
	cr = CM_Get_Device_Interface_PropertyW(
		entry->ctrl_path,
		&DEVPKEY_Device_InstanceId,
		&prop_type,
		(PBYTE)instance_id,
		&size,
		0);
	if (cr != CR_SUCCESS || prop_type != DEVPROP_TYPE_STRING)
		return -ENODEV;

	cr = CM_Locate_DevNodeW(&devinst, instance_id,
				CM_LOCATE_DEVNODE_NORMAL);
	if (cr != CR_SUCCESS)
		return -ENODEV;

	/*
	 * Query DEVPKEY_Device_LocationInfo which returns a string like
	 * "PCI bus 2, device 0, function 0"
	 */
	size = sizeof(location_info);
	prop_type = 0;
	cr = CM_Get_DevNode_PropertyW(
		devinst,
		&DEVPKEY_Device_LocationInfo,
		&prop_type,
		(PBYTE)location_info,
		&size,
		0);
	if (cr != CR_SUCCESS || prop_type != DEVPROP_TYPE_STRING)
		return -ENODEV;

	if (swscanf(location_info, L"PCI bus %u, device %u, function %u",
		    &bus, &device, &function) != 3)
		return -EINVAL;

	/* Format as Linux-compatible BDF: DOMAIN:BUS:DEVICE.FUNCTION */
	if (asprintf(&addr, "0000:%02x:%02x.%x",
		     bus, device, function) < 0)
		return -ENOMEM;

	*address = addr;
	return 0;
}


static int get_device_number(libnvme_fd_t h, DWORD *device_number)
{
	STORAGE_DEVICE_NUMBER info = { 0 };
	DWORD bytes_returned = 0;

	if (!device_number)
		return -EINVAL;

	*device_number = 0;
	if (h == INVALID_HANDLE_VALUE)
		return -EINVAL;

	if (!DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER,
			     NULL, 0, &info, sizeof(info),
			     &bytes_returned, NULL))
		return -1;

	*device_number = info.DeviceNumber;
	return 0;
}

int libnvme_ctrl_map_entry_scan_device_numbers(
		const struct ctrl_map_entry *entry,
		DWORD **device_numbers,
		int *count)
{
	WCHAR ctrl_instance_id[MAX_DEVICE_ID_LEN];
	DEVPROPTYPE prop_type = 0;
	ULONG id_size = sizeof(ctrl_instance_id);
	CONFIGRET cr;
	DEVINST ctrl_devinst, child;
	DWORD *nums = NULL;
	int capacity = 0;
	int num_count = 0;

	if (!entry || !device_numbers || !count)
		return -EINVAL;

	*device_numbers = NULL;
	*count = 0;

	cr = CM_Get_Device_Interface_PropertyW(
		entry->ctrl_path,
		&DEVPKEY_Device_InstanceId,
		&prop_type,
		(PBYTE)ctrl_instance_id,
		&id_size,
		0);
	if (cr != CR_SUCCESS || prop_type != DEVPROP_TYPE_STRING)
		return -ENODEV;

	cr = CM_Locate_DevNodeW(&ctrl_devinst, ctrl_instance_id,
				CM_LOCATE_DEVNODE_NORMAL);
	if (cr != CR_SUCCESS)
		return -ENODEV;

	cr = CM_Get_Child(&child, ctrl_devinst, 0);
	while (cr == CR_SUCCESS) {
		WCHAR child_id[MAX_DEVICE_ID_LEN];
		ULONG child_id_size = sizeof(child_id);
		DEVPROPTYPE child_prop_type = 0;
		ULONG list_size = 0;
		WCHAR *iface_list = NULL;
		CONFIGRET cr2;
		DEVINST sibling;

		cr2 = CM_Get_DevNode_PropertyW(
			child,
			&DEVPKEY_Device_InstanceId,
			&child_prop_type,
			(PBYTE)child_id,
			&child_id_size,
			0);
		if (cr2 != CR_SUCCESS)
			goto next_child;

		cr2 = CM_Get_Device_Interface_List_SizeW(
			&list_size,
			(LPGUID)&GUID_DEVINTERFACE_DISK,
			child_id,
			CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
		if (cr2 != CR_SUCCESS || list_size <= 1)
			goto next_child;

		iface_list = malloc(list_size * sizeof(WCHAR));
		if (!iface_list)
			goto enomem;

		cr2 = CM_Get_Device_Interface_ListW(
			(LPGUID)&GUID_DEVINTERFACE_DISK,
			child_id,
			iface_list,
			list_size,
			CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
		if (cr2 != CR_SUCCESS)
			goto next_child;

		for (WCHAR *iface = iface_list; *iface;
		     iface += wcslen(iface) + 1) {
			DWORD device_number = 0;
			HANDLE h;

			h = CreateFileW(iface, 0,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					NULL, OPEN_EXISTING, 0, NULL);
			if (get_device_number(h, &device_number)) {
				if (h != INVALID_HANDLE_VALUE)
					CloseHandle(h);
				continue;
			}
			CloseHandle(h);

			if (num_count == capacity) {
				int new_capacity = capacity ?
						   capacity * 2 : 8;
				DWORD *new_nums;

				new_nums = realloc(
					nums,
					(size_t)new_capacity *
					sizeof(*nums));
				if (!new_nums) {
					free(iface_list);
					goto enomem;
				}
				nums = new_nums;
				capacity = new_capacity;
			}

			nums[num_count++] = device_number;
		}

next_child:
		free(iface_list);
		cr = CM_Get_Sibling(&sibling, child, 0);
		child = sibling;
	}

	*device_numbers = nums;
	*count = num_count;
	return 0;

enomem:
	free(nums);
	return -ENOMEM;
}

int libnvme_ctrl_map_entry_map_nsid_to_drive_path(
		const struct ctrl_map_entry *entry,
		__u32 nsid,
		char **drive_path)
{
	DWORD *device_numbers = NULL;
	int dev_count = 0;
	int ret;
	int i;

	if (!entry || !drive_path || nsid == 0)
		return -EINVAL;

	*drive_path = NULL;

	ret = libnvme_ctrl_map_entry_scan_device_numbers(entry,
							 &device_numbers,
							 &dev_count);
	if (ret)
		return ret;

	for (i = 0; i < dev_count; i++) {
		char path[MAX_PATH];
		SCSI_ADDRESS addr = { 0 };
		DWORD bytes = 0;
		HANDLE h;

		snprintf(path, sizeof(path),
			 "\\\\.\\PhysicalDrive%lu", device_numbers[i]);

		h = CreateFileA(path, 0,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL, OPEN_EXISTING, 0, NULL);
		if (h == INVALID_HANDLE_VALUE)
			continue;

		addr.Length = sizeof(addr);
		if (!DeviceIoControl(h, IOCTL_SCSI_GET_ADDRESS,
				     NULL, 0, &addr, sizeof(addr),
				     &bytes, NULL)) {
			CloseHandle(h);
			continue;
		}
		CloseHandle(h);

		if ((__u32)(addr.Lun + 1) == nsid) {
			*drive_path = strdup(path);
			free(device_numbers);
			if (!*drive_path)
				return -ENOMEM;
			return 0;
		}
	}

	free(device_numbers);
	return -ENODEV;
}

char *libnvme_ctrl_map_entry_get_subsys_name(
		const struct ctrl_map_entry *entry)
{
	char *subsysname;

	if (!entry || !entry->subsys_name)
		return NULL;

	subsysname = strdup(entry->subsys_name);
	if (!subsysname)
		return NULL;

	return subsysname;
}

static char *copy_and_rtrim(const char *src, size_t src_size)
{
	char *dst;
	size_t len = src_size;

	if (!src)
		return NULL;

	while (len > 0 && isspace((unsigned char)src[len - 1]))
		len--;

	dst = malloc(len + 1);
	if (!dst)
		return NULL;

	memcpy(dst, src, len);
	dst[len] = '\0';

	return dst;
}

char *libnvme_ctrl_map_entry_get_subnqn(const struct ctrl_map_entry *entry)
{
	if (!entry)
		return NULL;
	return copy_and_rtrim(entry->id_ctrl.subnqn,
			      sizeof(entry->id_ctrl.subnqn));
}

char *libnvme_ctrl_map_entry_get_serial(const struct ctrl_map_entry *entry)
{
	if (!entry)
		return NULL;
	return copy_and_rtrim(entry->id_ctrl.sn, sizeof(entry->id_ctrl.sn));
}

char *libnvme_ctrl_map_entry_get_model(const struct ctrl_map_entry *entry)
{
	if (!entry)
		return NULL;
	return copy_and_rtrim(entry->id_ctrl.mn, sizeof(entry->id_ctrl.mn));
}

char *libnvme_ctrl_map_entry_get_firmware(const struct ctrl_map_entry *entry)
{
	if (!entry)
		return NULL;
	return copy_and_rtrim(entry->id_ctrl.fr, sizeof(entry->id_ctrl.fr));
}

HDEVINFO libnvme_ctrl_map_entry_get_devinfo(
	const struct ctrl_map_entry *entry,
	SP_DEVINFO_DATA *dev_info_data)
{
	HDEVINFO hdev;
	DWORD index;
	PWSTR ctrl_path = NULL;

	if (!dev_info_data || !entry || !entry->ctrl_path)
		return INVALID_HANDLE_VALUE;

	dev_info_data->cbSize = sizeof(*dev_info_data);

	hdev = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_STORAGEPORT, NULL, NULL,
				    DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (hdev == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;

	for (index = 0;; index++) {
		get_device_interface_path(hdev, index, &ctrl_path,
			dev_info_data);

		if (_wcsicmp(ctrl_path, entry->ctrl_path) == 0) {
			free(ctrl_path);
			return hdev;
		}
		free(ctrl_path);
		ctrl_path = NULL;
	}

	SetupDiDestroyDeviceInfoList(hdev);
	return INVALID_HANDLE_VALUE;
}

void libnvme_ctrl_map_entry_free_devinfo(HDEVINFO hdev)
{
	if (hdev != INVALID_HANDLE_VALUE)
		SetupDiDestroyDeviceInfoList(hdev);
}
