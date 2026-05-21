// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "private-storageport.h"

#include <cfgmgr32.h>
#include <setupapi.h>
#include <winioctl.h>
#include <ntddscsi.h>

#include <libnvme.h>

#include "private.h"
#include "compiler-attributes.h"

#include <initguid.h>
#include <devpkey.h>

static struct {
	struct storageport_map_entry *entries;
	size_t count;
	size_t capacity;
} sp_map;

size_t libnvme_storageport_map_get_count(void)
{
	return sp_map.count;
}

const char *libnvme_storageport_map_get_name(size_t index)
{
	if (index >= sp_map.count)
		return NULL;
	return sp_map.entries[index].storageport_name;
}

void libnvme_storageport_map_clear(void)
{
	size_t i;

	for (i = 0; i < sp_map.count; i++) {
		free(sp_map.entries[i].storageport_name);
		free(sp_map.entries[i].device_path);
		free(sp_map.entries[i].subsys_name);
	}

	free(sp_map.entries);
	sp_map.entries = NULL;
	sp_map.count = 0;
	sp_map.capacity = 0;
}

static int find_or_create_subsys_index(const struct nvme_id_ctrl *id_ctrl)
{
	int max_subsys_index = -1;
	size_t i;

	for (i = 0; i < sp_map.count; i++) {
		if (!memcmp(sp_map.entries[i].id_ctrl.subnqn,
			    id_ctrl->subnqn, NVME_NQN_LENGTH))
			return sp_map.entries[i].subsys_index;
		if (sp_map.entries[i].subsys_index > max_subsys_index)
			max_subsys_index = sp_map.entries[i].subsys_index;
	}

	return max_subsys_index + 1;
}

static int libnvme_storageport_map_add(const char *storageport_name,
				       const WCHAR *device_path_w,
				       const struct nvme_id_ctrl *id_ctrl)
{
	char *name_copy;
	WCHAR *path_copy;
	int subsys_index;
	char *subsys_name;

	if (!storageport_name || !device_path_w)
		return -EINVAL;

	if (sp_map.count == sp_map.capacity) {
		size_t new_capacity = sp_map.capacity ?
			sp_map.capacity * 2 : 8;
		struct storageport_map_entry *new_map;

		new_map = realloc(sp_map.entries,
				  new_capacity * sizeof(*sp_map.entries));
		if (!new_map)
			return -ENOMEM;

		sp_map.entries = new_map;
		sp_map.capacity = new_capacity;
	}

	name_copy = strdup(storageport_name);
	if (!name_copy)
		return -ENOMEM;

	path_copy = _wcsdup(device_path_w);
	if (!path_copy) {
		free(name_copy);
		return -ENOMEM;
	}

	subsys_index = find_or_create_subsys_index(id_ctrl);

	if (asprintf(&subsys_name, "nvme-subsys%d", subsys_index) < 0) {
		free(name_copy);
		free(path_copy);
		return -ENOMEM;
	}

	sp_map.entries[sp_map.count].storageport_name = name_copy;
	sp_map.entries[sp_map.count].device_path = path_copy;
	sp_map.entries[sp_map.count].id_ctrl = *id_ctrl;
	sp_map.entries[sp_map.count].subsys_index = subsys_index;
	sp_map.entries[sp_map.count].subsys_name = subsys_name;
	sp_map.count++;

	return 0;
}

static int storageport_find_index(const char *storageport_name)
{
	size_t i;
	size_t sp_len;
	char next_ch;

	for (i = 0; i < sp_map.count; i++) {
		sp_len = strlen(sp_map.entries[i].storageport_name);

		/* Skip entry if name does not start with nvmeX format */
		if (strncmp(sp_map.entries[i].storageport_name,
			    storageport_name, sp_len))
			continue;

		next_ch = storageport_name[sp_len];
		/* Matches either nvmeX or nvmeXnY format */
		if (next_ch == '\0' || next_ch == 'n')
			return (int)i;
	}

	return -1;
}

/*
 * Issue an Identify Controller command on the given handle.
 * Creates a temporary transport context and handle internally.
 * Returns 0 on success with id_ctrl filled in, negative errno on failure.
 */
static int identify_ctrl_from_handle(HANDLE h, struct nvme_id_ctrl *id_ctrl)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int ret;

	ctx = libnvme_create_global_ctx(NULL, LIBNVME_DEFAULT_LOGLEVEL);
	if (!ctx)
		return -ENOMEM;

	hdl = __libnvme_create_transport_handle(ctx);
	if (!hdl) {
		libnvme_free_global_ctx(ctx);
		return -ENOMEM;
	}

	hdl->fd = h;
	hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_DIRECT;

	memset(id_ctrl, 0, sizeof(*id_ctrl));
	nvme_init_identify_ctrl(&cmd, id_ctrl);
	ret = libnvme_submit_admin_passthru(hdl, &cmd);

	/*
	 * Detach the handle before freeing the transport
	 * handle so the caller retains ownership of the handle.
	 */
	hdl->fd = INVALID_HANDLE_VALUE;
	free(hdl);
	libnvme_free_global_ctx(ctx);

	return ret;
}

/*
 * Query adapter BusType via IOCTL_STORAGE_QUERY_PROPERTY /
 * StorageAdapterProperty.
 * Returns 1 on success (bus type written to *out_bus_type), 0 on failure.
 */
static int query_adapter_bustype(HANDLE h, STORAGE_BUS_TYPE *out_bus_type)
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
		return 0;

	buf = calloc(1, hdr.Size);
	if (!buf)
		return 0;

	if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
			     &q, sizeof(q),
			     buf, hdr.Size,
			     &bytes, NULL)) {
		free(buf);
		return 0;
	}

	ad = (STORAGE_ADAPTER_DESCRIPTOR *)buf;
	*out_bus_type = (STORAGE_BUS_TYPE)ad->BusType;
	free(buf);
	return 1;
}

/*
 * Enumerate the next device interface and return a wide-string
 * copy of the device path.  Returns:
 *   1  success  (*device_path set, caller must free)
 *   0  non-fatal failure (skip this interface)
 *   ERROR_NOT_ENOUGH_MEMORY  allocation failure
 *   ERROR_NO_MORE_ITEMS  no more items (enumeration complete)
 */
static int get_device_interface_path(HDEVINFO hdev,
				     DWORD index,
				     WCHAR **device_path)
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
			return ERROR_NO_MORE_ITEMS;
		return 0;
	}

	SetupDiGetDeviceInterfaceDetailW(hdev, &if_data, NULL, 0,
					 &required_size, NULL);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !required_size)
		return 0;

	detail = calloc(1, required_size);
	if (!detail)
		return ERROR_NOT_ENOUGH_MEMORY;

	detail->cbSize = sizeof(*detail);
	if (!SetupDiGetDeviceInterfaceDetailW(hdev, &if_data, detail,
					      required_size,
					      NULL, &dev_info_data)) {
		free(detail);
		return 0;
	}

	*device_path = _wcsdup(detail->DevicePath);
	free(detail);
	if (!*device_path)
		return ERROR_NOT_ENOUGH_MEMORY;

	return 1;
}

int libnvme_storageport_map_init(void)
{
	HDEVINFO hdev;
	PWSTR device_path_copy = NULL;
	HANDLE h = INVALID_HANDLE_VALUE;
	int ret;
	DWORD index;
	DWORD nvme_ctrl_index = 0;
	STORAGE_BUS_TYPE bus_type;

	if (sp_map.count > 0)
		/* map already initialized */
		return 0;

	hdev = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_STORAGEPORT, NULL, NULL,
				    DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (hdev == INVALID_HANDLE_VALUE)
		return 0;

	for (index = 0;; index++) {
		struct nvme_id_ctrl id_ctrl;
		char *ctrl_name = NULL;

		h = INVALID_HANDLE_VALUE;
		device_path_copy = NULL;

		ret = get_device_interface_path(hdev, index, &device_path_copy);
		if (ret == ERROR_NO_MORE_ITEMS)
			break;
		if (ret == ERROR_NOT_ENOUGH_MEMORY)
			goto enomem;
		if (!ret)
			continue;

		h = CreateFileW(device_path_copy, 0,
				   FILE_SHARE_READ | FILE_SHARE_WRITE |
				   FILE_SHARE_DELETE,
				   NULL, OPEN_EXISTING, 0, NULL);

		if (h == INVALID_HANDLE_VALUE)
			goto next_entry;

		if (!query_adapter_bustype(h, &bus_type) ||
		    bus_type != BusTypeNvme)
			goto next_entry;

		ret = identify_ctrl_from_handle(h, &id_ctrl);
		if (ret)
			goto next_entry;

		if (asprintf(&ctrl_name, "nvme%lu", nvme_ctrl_index) < 0)
			goto enomem;

		ret = libnvme_storageport_map_add(ctrl_name,
						  device_path_copy,
						  &id_ctrl);
		free(ctrl_name);
		ctrl_name = NULL;
		if (ret < 0)
			goto enomem;
		nvme_ctrl_index++;

next_entry:
		free(device_path_copy);
		device_path_copy = NULL;
		if (h != INVALID_HANDLE_VALUE)
			CloseHandle(h);
	}

	SetupDiDestroyDeviceInfoList(hdev);
	return 0;

enomem:
	free(device_path_copy);
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
	SetupDiDestroyDeviceInfoList(hdev);
	libnvme_storageport_map_clear();
	return -ENOMEM;
}

const struct storageport_map_entry *libnvme_storageport_lookup_entry(
	const char *storageport_name)
{
	int idx;

	if (!storageport_name)
		return NULL;

	if (libnvme_storageport_map_init())
		return NULL;

	idx = storageport_find_index(storageport_name);
	if (idx < 0)
		return NULL;

	return &sp_map.entries[idx];
}

const struct storageport_map_entry *
libnvme_storageport_lookup_by_physdrive(const char *drive_path)
{
	DWORD target_num;
	char *endptr;
	const char *num_str;
	size_t i;

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

	if (libnvme_storageport_map_init())
		return NULL;

	for (i = 0; i < sp_map.count; i++) {
		DWORD *device_numbers = NULL;
		int dev_count = 0;
		int ret;
		int j;

		ret = libnvme_storageport_scan_device_numbers(
			&sp_map.entries[i],
			&device_numbers, &dev_count);
		if (ret)
			continue;

		for (j = 0; j < dev_count; j++) {
			if (device_numbers[j] == target_num) {
				free(device_numbers);
				return &sp_map.entries[i];
			}
		}

		free(device_numbers);
	}

	return NULL;
}

int libnvme_storageport_update_id_ctrl(const char *storageport_name,
				       const struct nvme_id_ctrl *id)
{
	int idx;

	if (!storageport_name || !id)
		return -EINVAL;

	idx = storageport_find_index(storageport_name);
	if (idx < 0)
		return -ENOENT;

	sp_map.entries[idx].id_ctrl = *id;
	return 0;
}

int libnvme_storageport_entry_get_ctrl_path(
	const struct storageport_map_entry *sp_entry,
	char **device_path)
{
	int path_len;
	char *path_copy;

	if (!sp_entry || !device_path || !sp_entry->device_path)
		return -EINVAL;

	*device_path = NULL;

	path_len = WideCharToMultiByte(CP_UTF8, 0, sp_entry->device_path, -1,
				       NULL, 0, NULL, NULL);
	if (path_len <= 0)
		return -EINVAL;

	path_copy = malloc(path_len);
	if (!path_copy)
		return -ENOMEM;

	if (!WideCharToMultiByte(CP_UTF8, 0, sp_entry->device_path, -1,
				 path_copy, path_len, NULL, NULL)) {
		free(path_copy);
		return -EINVAL;
	}

	*device_path = path_copy;
	return 0;
}

int libnvme_storageport_get_pci_address(
	const struct storageport_map_entry *sp_entry,
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

	if (!sp_entry || !address || !sp_entry->device_path)
		return -EINVAL;

	*address = NULL;

	/* Get the device instance ID from the interface path */
	size = sizeof(instance_id);
	cr = CM_Get_Device_Interface_PropertyW(
		sp_entry->device_path,
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


static int get_device_number(HANDLE h, DWORD *device_number)
{
	STORAGE_DEVICE_NUMBER info = { 0 };
	DWORD bytes_returned = 0;

	if (!device_number)
		return 0;

	*device_number = 0;
	if (h == INVALID_HANDLE_VALUE)
		return 0;

	if (!DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER,
				     NULL, 0, &info, sizeof(info),
				     &bytes_returned, NULL))
		return 0;

	*device_number = info.DeviceNumber;
	return 1;
}

int libnvme_storageport_scan_device_numbers(
	const struct storageport_map_entry *sp_entry,
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

	if (!sp_entry || !device_numbers || !count)
		return -EINVAL;

	*device_numbers = NULL;
	*count = 0;

	cr = CM_Get_Device_Interface_PropertyW(
		sp_entry->device_path,
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
			if (!get_device_number(h, &device_number)) {
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

int libnvme_storageport_nsid_to_drive_path(
	const struct storageport_map_entry *sp_entry,
	__u32 nsid,
	char **drive_path)
{
	DWORD *device_numbers = NULL;
	int dev_count = 0;
	int ret;
	int i;

	if (!sp_entry || !drive_path || nsid == 0)
		return -EINVAL;

	*drive_path = NULL;

	ret = libnvme_storageport_scan_device_numbers(sp_entry,
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
