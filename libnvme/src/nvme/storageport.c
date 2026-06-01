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

struct storageport_map_entry {
	char *ctrl_name;   /* format "nvmeX" */
	WCHAR *ctrl_path;  /* format "\\?\pci..." */
	struct nvme_id_ctrl id_ctrl;
	int subsys_index;
	char *subsys_name;
};

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
	return sp_map.entries[index].ctrl_name;
}

void libnvme_storageport_map_clear(void)
{
	size_t i;

	for (i = 0; i < sp_map.count; i++) {
		free(sp_map.entries[i].ctrl_name);
		free(sp_map.entries[i].ctrl_path);
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

static int libnvme_storageport_map_add(const char *ctrl_name,
				       const WCHAR *ctrl_path,
				       const struct nvme_id_ctrl *id_ctrl)
{
	char *ctrl_name_copy;
	WCHAR *ctrl_path_copy;
	int subsys_index;
	char *subsys_name;

	if (!ctrl_name || !ctrl_path)
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

	ctrl_name_copy = strdup(ctrl_name);
	if (!ctrl_name_copy)
		return -ENOMEM;

	ctrl_path_copy = _wcsdup(ctrl_path);
	if (!ctrl_path_copy) {
		free(ctrl_name_copy);
		return -ENOMEM;
	}

	subsys_index = find_or_create_subsys_index(id_ctrl);

	if (asprintf(&subsys_name, "nvme-subsys%d", subsys_index) < 0) {
		free(ctrl_name_copy);
		free(ctrl_path_copy);
		return -ENOMEM;
	}

	sp_map.entries[sp_map.count].ctrl_name = ctrl_name_copy;
	sp_map.entries[sp_map.count].ctrl_path = ctrl_path_copy;
	sp_map.entries[sp_map.count].id_ctrl = *id_ctrl;
	sp_map.entries[sp_map.count].subsys_index = subsys_index;
	sp_map.entries[sp_map.count].subsys_name = subsys_name;
	sp_map.count++;

	return 0;
}

static int storageport_find_index(const char *ctrl_name)
{
	size_t i;

	for (i = 0; i < sp_map.count; i++) {
		size_t sp_len = strlen(sp_map.entries[i].ctrl_name);
		const char *suffix;

		/* Skip entry if name does not start with nvmeX format */
		if (strncmp(sp_map.entries[i].ctrl_name,
			    ctrl_name, sp_len))
			continue;

		suffix = ctrl_name + sp_len;

		/* Exact match: nvmeX */
		if (*suffix == '\0')
			return (int)i;

		/* Namespace match: nvmeXnY (Y is a positive integer) */
		if (*suffix != 'n' || suffix[1] < '1' || suffix[1] > '9')
			continue;

		suffix += 2;
		while (*suffix >= '0' && *suffix <= '9')
			suffix++;
		if (*suffix == '\0')
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
 * Returns 0 on success (bus type written to *out_bus_type).
 */
static int get_adapter_bus_type(HANDLE h, STORAGE_BUS_TYPE *out_bus_type)
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
				     WCHAR **device_interface_path)
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

	return 0;
}

int libnvme_storageport_map_init(void)
{
	HDEVINFO hdev;
	PWSTR ctrl_path = NULL;
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
		ctrl_path = NULL;

		ret = get_device_interface_path(hdev, index, &ctrl_path);
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

		ret = identify_ctrl_from_handle(h, &id_ctrl);
		if (ret)
			goto next_entry;

		if (asprintf(&ctrl_name, "nvme%lu", nvme_ctrl_index) < 0)
			goto enomem;

		ret = libnvme_storageport_map_add(ctrl_name,
						  ctrl_path,
						  &id_ctrl);
		free(ctrl_name);
		ctrl_name = NULL;
		if (ret < 0)
			goto enomem;
		nvme_ctrl_index++;

next_entry:
		free(ctrl_path);
		ctrl_path = NULL;
		if (h != INVALID_HANDLE_VALUE)
			CloseHandle(h);
	}

	SetupDiDestroyDeviceInfoList(hdev);
	return 0;

enomem:
	free(ctrl_path);
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
	SetupDiDestroyDeviceInfoList(hdev);
	libnvme_storageport_map_clear();
	return -ENOMEM;
}

struct storageport_map_entry *libnvme_storageport_map_lookup(
	const char *ctrl_name)
{
	int idx;

	if (!ctrl_name)
		return NULL;

	if (libnvme_storageport_map_init())
		return NULL;

	idx = storageport_find_index(ctrl_name);
	if (idx < 0)
		return NULL;

	return &sp_map.entries[idx];
}

const struct storageport_map_entry *
libnvme_storageport_map_lookup_by_physdrive(const char *drive_path)
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

		ret = libnvme_storageport_entry_scan_device_numbers(
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

int libnvme_storageport_entry_set_id_ctrl(
	struct storageport_map_entry *sp_entry,
	const struct nvme_id_ctrl *id)
{
	if (!sp_entry || !id)
		return -EINVAL;

	sp_entry->id_ctrl = *id;
	return 0;
}

const char *libnvme_storageport_entry_get_ctrl_name(
	const struct storageport_map_entry *sp_entry)
{
	if (!sp_entry || !sp_entry->ctrl_name)
		return NULL;

	return sp_entry->ctrl_name;
}

int libnvme_storageport_entry_get_ctrl_path(
	const struct storageport_map_entry *sp_entry, char **ctrl_path)
{
	int path_len;
	char *ctrl_path_copy;

	if (!sp_entry || !ctrl_path || !sp_entry->ctrl_path)
		return -EINVAL;

	*ctrl_path = NULL;

	path_len = WideCharToMultiByte(CP_UTF8, 0, sp_entry->ctrl_path, -1,
				       NULL, 0, NULL, NULL);
	if (path_len <= 0)
		return -EINVAL;

	ctrl_path_copy = malloc(path_len);
	if (!ctrl_path_copy)
		return -ENOMEM;

	if (!WideCharToMultiByte(CP_UTF8, 0, sp_entry->ctrl_path, -1,
				 ctrl_path_copy, path_len, NULL, NULL)) {
		free(ctrl_path_copy);
		return -EINVAL;
	}

	*ctrl_path = ctrl_path_copy;
	return 0;
}

int libnvme_storageport_entry_get_pci_address(
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

	if (!sp_entry || !address || !sp_entry->ctrl_path)
		return -EINVAL;

	*address = NULL;

	/* Get the device instance ID from the interface path */
	size = sizeof(instance_id);
	cr = CM_Get_Device_Interface_PropertyW(
		sp_entry->ctrl_path,
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

int libnvme_storageport_entry_scan_device_numbers(
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
		sp_entry->ctrl_path,
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

int libnvme_storageport_entry_map_nsid_to_drive_path(
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

	ret = libnvme_storageport_entry_scan_device_numbers(sp_entry,
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

char *libnvme_storageport_entry_get_subsys_name(
	const struct storageport_map_entry *sp_entry)
{
	char *subsysname;

	if (!sp_entry || !sp_entry->subsys_name)
		return NULL;

	subsysname = strdup(sp_entry->subsys_name);
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

char *libnvme_storageport_entry_get_subnqn(
	const struct storageport_map_entry *sp_entry)
{
	if (!sp_entry)
		return NULL;
	return copy_and_rtrim(sp_entry->id_ctrl.subnqn,
			      sizeof(sp_entry->id_ctrl.subnqn));
}

char *libnvme_storageport_entry_get_serial(
	const struct storageport_map_entry *sp_entry)
{
	if (!sp_entry)
		return NULL;
	return copy_and_rtrim(sp_entry->id_ctrl.sn,
			      sizeof(sp_entry->id_ctrl.sn));
}

char *libnvme_storageport_entry_get_model(
	const struct storageport_map_entry *sp_entry)
{
	if (!sp_entry)
		return NULL;
	return copy_and_rtrim(sp_entry->id_ctrl.mn,
			      sizeof(sp_entry->id_ctrl.mn));
}

char *libnvme_storageport_entry_get_firmware(
	const struct storageport_map_entry *sp_entry)
{
	if (!sp_entry)
		return NULL;
	return copy_and_rtrim(sp_entry->id_ctrl.fr,
			      sizeof(sp_entry->id_ctrl.fr));
}
