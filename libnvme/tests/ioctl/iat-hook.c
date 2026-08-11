// SPDX-License-Identifier: LGPL-2.1-or-later

#include <string.h>

#include "iat-hook.h"
#include "util.h"

bool iat_patch(HMODULE module, const char *symbol, void *replacement,
	       void **saved)
{
	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)module;
	IMAGE_NT_HEADERS *nt;
	IMAGE_DATA_DIRECTORY *dir;
	IMAGE_IMPORT_DESCRIPTOR *desc;
	BYTE *base = (BYTE *)module;

	check(dos->e_magic == IMAGE_DOS_SIGNATURE, "not a PE image");
	nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
	check(nt->Signature == IMAGE_NT_SIGNATURE, "bad PE signature");

	/*
	 * Resolve the import directory by hand rather than with
	 * ImageDirectoryEntryToData() so the mock doesn't need dbghelp.
	 */
	dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (!dir->VirtualAddress || !dir->Size)
		return false;

	desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + dir->VirtualAddress);

	for (; desc->Name; desc++) {
		IMAGE_THUNK_DATA *name_thunk, *addr_thunk;

		/*
		 * OriginalFirstThunk holds the import names; FirstThunk is the
		 * live slot the call jumps through. Walk them in lockstep and
		 * patch the address whose name matches. A bound import can
		 * lack OriginalFirstThunk, in which case the names are gone
		 * and this entry can't be matched by name.
		 */
		if (!desc->OriginalFirstThunk || !desc->FirstThunk)
			continue;

		name_thunk = (IMAGE_THUNK_DATA *)
			(base + desc->OriginalFirstThunk);
		addr_thunk = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);

		for (; name_thunk->u1.Function; name_thunk++, addr_thunk++) {
			IMAGE_IMPORT_BY_NAME *by_name;
			DWORD old_prot;

			/* Imports by ordinal carry no name to compare. */
			if (IMAGE_SNAP_BY_ORDINAL(name_thunk->u1.Ordinal))
				continue;

			by_name = (IMAGE_IMPORT_BY_NAME *)
				(base + name_thunk->u1.AddressOfData);
			if (strcmp((const char *)by_name->Name, symbol))
				continue;

			/* The IAT is read-only once the loader has bound it. */
			if (!VirtualProtect(&addr_thunk->u1.Function,
					    sizeof(addr_thunk->u1.Function),
					    PAGE_READWRITE, &old_prot))
				fail("VirtualProtect failed for %s: %lu",
				     symbol, GetLastError());

			if (saved)
				*saved = (void *)(uintptr_t)
					addr_thunk->u1.Function;
			addr_thunk->u1.Function = (uintptr_t)replacement;

			VirtualProtect(&addr_thunk->u1.Function,
				       sizeof(addr_thunk->u1.Function),
				       old_prot, &old_prot);
			return true;
		}
	}

	return false;
}
