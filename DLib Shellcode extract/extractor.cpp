#include "stdafx.h"
#include "../DLib Attacher/PEManager.h"

#include <TlHelp32.h>

bool MakeShell(PWCHAR filename, PWCHAR out_shell, PWCHAR out_relocs) 
{
	CPEFileManager pe;
	PBYTE pshell, preloc, pnew_rel, pshell_new;
	UINT shell_size;
	DWORD written, rel_addr, rel_size, imgbase, exp_header;
	HANDLE hfile;

	if (!pe.Open(filename, false)) {
		printf("Error, cant open file\n");
		return false;
	}

	PIMAGE_SECTION_HEADER psect = pe.GetSectorPtr(".shell");
	if (!psect) {
		printf("Error, not found .shell section\n");
		return false;
	}

	pshell = (PBYTE)malloc(psect->SizeOfRawData + (sizeof(DWORD) * 3));

	//Load export offsets and other
	if (pe.GetArch() == PE_X86) {
		PIMAGE_OPTIONAL_HEADER32 popt = pe.GetHOpt32();
		rel_addr = popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		rel_size = popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		imgbase = popt->ImageBase;
		exp_header = popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	} else {
		PIMAGE_OPTIONAL_HEADER64 popt = pe.GetHOpt64();
		rel_addr = popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		rel_size = popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		imgbase = popt->ImageBase;
		exp_header = popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}

	//Export offsets
	IMAGE_EXPORT_DIRECTORY exprt;
	DWORD *paddresses;

	if (!pe.ReadVirtualData(exp_header, &exprt, sizeof(IMAGE_EXPORT_DIRECTORY), 0)) {
		printf("Error, can't read export data\n");
		free(pshell); return false;
	}

	paddresses = (PDWORD)malloc(exprt.NumberOfFunctions * sizeof(DWORD));
	if (!pe.ReadVirtualData(exprt.AddressOfFunctions, paddresses, exprt.NumberOfFunctions * sizeof(DWORD), 0)) {
		printf("Error, can't read export functions list\n");
		free(paddresses); free(pshell); return false;
	}

	((DWORD *)pshell)[0] = (paddresses[2] - psect->VirtualAddress);//TLSEntry
	((DWORD *)pshell)[1] = (paddresses[1] - psect->VirtualAddress);//EntryPoint
	((DWORD *)pshell)[2] = (paddresses[0] - psect->VirtualAddress);//DllEntry

	pshell_new = (BYTE *)((DWORD)pshell + (sizeof(DWORD) * 3));
	free(paddresses);

	//Read shellcode
	if (!pe.ReadRawData(psect->PointerToRawData, pshell_new, psect->SizeOfRawData)) {
		printf("Error, can't read section data\n");
		free(pshell); return false;
	}

	hfile = CreateFileW(out_shell, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("Error, can't save section data\n");
		free(pshell); return false;
	}

	if (!WriteFile(hfile, pshell, psect->SizeOfRawData, &written, NULL)) {
		printf("Error, can't write section data\n");
		CloseHandle(hfile);
		free(pshell); return false;
	}
	printf("OK. Shell code successful saved!\n");
	free(pshell);
	CloseHandle(hfile);

	if (!rel_addr) {
		printf("Error, can't find relocs table\n");
		return false;
	}

	preloc = (PBYTE)malloc(rel_size);
	pnew_rel = (PBYTE)malloc(rel_size + (sizeof(DWORD) * 2));

	if (!pe.ReadVirtualData(rel_addr, preloc, rel_size, 0)) {
		printf("Error, can't read section data\n");
		free(preloc); return false;
	}

	bool found = false, first = true;
	unsigned int i = 0, a = 0;
	PIMAGE_BASE_RELOCATION prel;

	//imagebase
	*(DWORD *)pnew_rel = imgbase; a += sizeof(DWORD);

	while (i < rel_size) {
		prel = (PIMAGE_BASE_RELOCATION)(preloc + i);
		i += prel->SizeOfBlock;

		if (!prel->VirtualAddress && !prel->SizeOfBlock) {
			break;
		}

		if (prel->VirtualAddress >= psect->VirtualAddress) {
			if (first) {
				*(DWORD *)((DWORD)pnew_rel + a) = prel->VirtualAddress;
				a += sizeof(DWORD);
				first = false;
			}
			prel->VirtualAddress -= psect->VirtualAddress;
			memcpy((PVOID)((DWORD)pnew_rel + a), prel, prel->SizeOfBlock);
			a += prel->SizeOfBlock;
			found = true;
		}
	}
	if (!found) {
		printf("Error, reloc table element not found\n");
		free(preloc); free(pnew_rel); return false;
	}

	hfile = CreateFileW(out_relocs, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("Error, can't save reloc data\n");
		free(preloc); free(pnew_rel); return false;
	}
	if (!WriteFile(hfile, pnew_rel, a, &written, NULL)) {
		printf("Error, can't write reloc data\n");
		CloseHandle(hfile);
		free(preloc); free(pnew_rel); return false;
	}

	printf("OK. Reloc table successful saved!\n");
	free(preloc);
	free(pnew_rel);
	CloseHandle(hfile);

	return true;
}

bool GetModuleName(DWORD virt_addr, PVOID buffer, UINT size)
{
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(NULL));
	MODULEENTRY32W mod;
	int len;

	if (hsnap == INVALID_HANDLE_VALUE) {
		return false;
	}

	mod.dwSize = sizeof(MODULEENTRY32W);
	if (!Module32FirstW(hsnap, &mod)) {
		return false;
	}

	do {
		if (virt_addr >= (DWORD)mod.modBaseAddr && (virt_addr - (DWORD)mod.modBaseAddr) <= mod.modBaseSize) {
			len = wcslen(mod.szModule) * 2;
			if (len >= size - 2) {
				len = size - 2;
			}

			memset(buffer, 0, size);
			memcpy(buffer, mod.szModule, len);

			return true;
		}
	} while (Module32NextW(hsnap, &mod));

	wcscpy((PWCHAR)buffer, L"[Unknown]");
	return true;
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (!MakeShell(L"DLib Shellcode.exe", 
		L"../DLib Attacher/res/shellcode32.bin", 
		L"../DLib Attacher/res/shellcode32rel.bin")) {
		printf("Make shell failed\n");
	} else {
		printf("Complite\n");
	}

	getchar();
	return 0;
}

