#include "stdafx.h"
#include "DLibAttach.h"
#include "resource.h"

// ======================= CDLibShellAttach :: PUBLIC =======================

CDLibShellAttach::CDLibShellAttach() : _shell_open(false), _pshell(NULL), _tls_data(NULL), _rel_data(NULL), _is_att(false)
{

}

CDLibShellAttach::~CDLibShellAttach()
{
	ClosePE();
}

bool CDLibShellAttach::OpenPE(LPVOID wpath)
{
	PIMAGE_SECTION_HEADER psect;
	PBYTE buff;
	bool load_dlib = false;
	ULONGLONG tls_addr64;
	PBYTE opcode, relocs;
	UINT opc_size, rel_size;

	PVOID virt_buff;
	UINT virt_size, virt_size_max, tls_count;
	IMAGE_TLS_DIRECTORY32 tls_dir;
	/*IMAGE_TLS_DIRECTORY64 tls_dir64;*/
	DWORD virt_addr;
	PDWORD tsl_table;

	if (_shell_open) {
		return SetError(E_STATE_ALLREADY, __LINE__);
	}

	Close();
	if (!Open((LPWSTR)wpath, true)) {
		return SetError(E_INHERIT);
	}

	if (GetArch() == PE_X86) {
		_pshell = new CDLibShellMain();
	} else if (GetArch() == PE_X64) {
		//_pshell = new CDLibShell64();
		return SetError(E_UNKNOWN, __LINE__);//TODO x64
	} else {
		return SetError(E_UNKNOWN, __LINE__);
	}

	//Load resources
	DWORD test = IDR_SHELLCODE32;
	if (!GetResourcePtr(&opcode, &opc_size, IDR_SHELLCODE32)) {
		return SetError(E_ALLOC_FAIL, GetLastError());
	}
	if (!GetResourcePtr(&relocs, &rel_size, IDR_SHELLCODE32REL)) {
		return SetError(E_ALLOC_FAIL, __LINE__);
	}

	psect = GetSectorPtr(DLIB_SECTION);
	if (psect) {//PE have dlib, try to load
		buff = (PBYTE)malloc(psect->SizeOfRawData);
		if (!buff) {
			return SetError(E_ALLOC_FAIL, __LINE__);
		}

		if (!ReadVirtualData(psect->VirtualAddress, buff, psect->SizeOfRawData, NULL, false) 
			|| !_pshell->Load(buff, psect->SizeOfRawData)) {
			load_dlib = false;
		} else {
			load_dlib = true;
		}
		free(buff);

		if (!_pshell->LoadOpcode(opcode, opc_size, relocs, rel_size)) {
			return SetError(E_INHERIT, __LINE__);
		}
	}

	if (!load_dlib) {//Create new shell
		if (!_pshell->Create(opcode, opc_size, relocs, rel_size)) {
			return SetError(E_INHERIT, __LINE__);
		}

		// Loading TLS
		virt_size_max = 0;
		virt_addr = NULL;
		if (GetArch() == PE_X86) {
			if (_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0) {
				virt_addr = _popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
				virt_buff = &tls_dir;
				virt_size = sizeof(IMAGE_TLS_DIRECTORY32);
			}
		} else {
			//TODO x64
		}

		if (virt_addr) {
			if (!ReadVirtualData(virt_addr, virt_buff, virt_size, NULL, 0)) {
				return SetError(E_UNKNOWN, __LINE__);
			}
			if (tls_dir.AddressOfCallBacks) {//if isset TLS callback table
				if (!ReadTLSCallbackTable(tls_dir.AddressOfCallBacks, tsl_table, &tls_count)) {
					return SetError(E_UNKNOWN, __LINE__);
				}
				if (!_pshell->LoadTLSCallbackTable(tsl_table, tls_count)) {
					return SetError(E_UNKNOWN, __LINE__);
				}
			} else {
				_pshell->LoadTLSCallbackTable(NULL, 0, true, &tls_dir);
			}
		} else {
			_pshell->LoadTLSCallbackTable(NULL, 0, true, NULL);
		}
	}

	PE_Type type = GetType();
	if (type == PE_DLL) {
		_pshell->SetFlag(SF_DLL, true);
	} else if (type == PE_EXE) {
		_pshell->SetFlag(SF_DLL, false);
	} else {
		return SetError(E_NOT_SUPPORTED, __LINE__);
	}

	_pshell->ClearScanOffsets();

	//Load relocs
	virt_size_max = 0;
	virt_addr = NULL;
	if (GetArch() == PE_X86) {
		if (_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
			virt_addr = _popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
			virt_size = _popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		}
	} /*else {
	}*/
	if (virt_addr) {
		virt_size_max = CalcInSectionFreeSpace(virt_addr, NULL);
		virt_buff = ReadRelocsBlocks(virt_addr, virt_size, virt_size_max, &rel_size);
		if (!virt_buff) {
			return SetError(E_UNKNOWN, __LINE__);
		}

		if (!_pshell->LoadRelocsTable(virt_buff, rel_size, 
			(load_dlib ? psect->VirtualAddress : NULL), 
			(load_dlib ? psect->Misc.VirtualSize : NULL))) {
			return SetError(E_UNKNOWN, __LINE__);
		}
	}

	_is_att = (load_dlib ? true : false);
	_shell_open = true;
	return SetError(E_OK);
}

void CDLibShellAttach::ClosePE()
{
	if (_shell_open) {
		Close();
		if (_pshell) {
			delete _pshell;
			_pshell = NULL;
		}
		if (_tls_data) {
			free(_tls_data);
			_tls_data = NULL;
		}
		if (_rel_data) {
			free(_rel_data);
			_rel_data = NULL;
		}
		_is_att = false;
		_shell_open = false;
	}
}

bool CDLibShellAttach::AttachShell()
{
	Shell_Build_Result res = {0};
	PIMAGE_SECTION_HEADER psect, psectors;
	IMAGE_TLS_DIRECTORY32 tls_dir;
	//IMAGE_TLS_DIRECTORY64 tls_dir64;
	int id, entry_id;
	UINT count, size;
	PBYTE ptramp, pbuff;
	DWORD offset;

	if (!_shell_open) {
		return SetError(E_NOT_FOUND, __LINE__);
	}

	psect = GetSectorPtr(DLIB_SECTION);
	id = GetSectorNum(DLIB_SECTION);
	/*if (psect && psect->Misc.VirtualSize < DLIB_SECTION_MIN_SIZE) {//recreate
		/ *if (!RemoveSection(id)) {
			return SetError(E_INHERIT, __LINE__);
		}
		if (!AddSection(DLIB_SECTION, -1, NULL, 0, DLIB_SECTION_MIN_SIZE)) {
			return SetError(E_INHERIT, __LINE__);
		}
		psect = NULL;* /
	} else*/ if (!psect) {
		if (!AddSection(DLIB_SECTION, -1, NULL, 0, DLIB_SECTION_MIN_SIZE)) {
			return SetError(E_INHERIT, __LINE__);
		}
		id = GetSectorNum(DLIB_SECTION);
		if (id == -1) {
			return SetError(E_UNKNOWN, __LINE__);
		}
		psect = GetSectorPtr(DLIB_SECTION);
		if (!psect) {
			return SetError(E_NOT_FOUND, __LINE__);
		}
	}

	if (GetArch() == PE_X86) {
		if (_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) {
			if (!ReadVirtualData(_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, 
				&tls_dir, sizeof(IMAGE_TLS_DIRECTORY32), 0, 0)) {
				return SetError(E_INHERIT, __LINE__);
			}
			res.ori_tls_clbk_addr = tls_dir.AddressOfCallBacks;
		} else {
			res.ori_tls_clbk_addr = 0;
		}
	} else {
		//TODO x64
	}

	res.imagebase = (GetArch() == PE_X86 ? _popt32->ImageBase : _popt64->ImageBase);
	res.sect_offst = psect->VirtualAddress;
	res.ori_relocs_addr = (GetArch() == PE_X86 ? _popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress 
							: _popt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	res.ori_relocs_size = (GetArch() == PE_X86 ? _popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size 
							: _popt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	res.ori_tls_dir_addr = (GetArch() == PE_X86 ? _popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress 
							: _popt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
	res.ori_tls_size = (GetArch() == PE_X86 ? _popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size 
							: _popt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
	res.ori_entrypoint = (GetArch() == PE_X86 ? _popt32->AddressOfEntryPoint : _popt64->AddressOfEntryPoint);
	res.ori_sec_id = res.ori_sec_raw_size = 0;
	if (_pshell->GetFlag(SF_USE_EP)) {
		if (GetArch() == PE_X86) {
			psectors = GetSectsPtr(&count);
			entry_id = -1;
			for (int i = 0; i < count; i++) {
				if (psectors[i].VirtualAddress <= _popt32->AddressOfEntryPoint 
				&& psectors[i].VirtualAddress + psectors[i].Misc.VirtualSize > _popt32->AddressOfEntryPoint) {
					entry_id = i;
					break;
				}
			}
			if (entry_id == -1) {
				return SetError(E_UNKNOWN, __LINE__);
			}
			res.ori_sec_id = entry_id;
			res.ori_sec_raw_size = psectors[entry_id].SizeOfRawData;
		} else {
			//TODO x64
		}
	}

	//Advance
	if (_pshell->GetFlag(SF_ADVANCE)) {
		DWORD mask;
		mask = _pshell->GetSectorProtMask();
		psectors = GetSectsPtr(&count);
		for (int i = 0; i < count + 1; i++) {
			if (mask & _BIT(i)) {
				if (i == 0) {
					_pshell->AddScanOffset(0, PE_DEFAULT_VIRTUAL_ALIGMENT);
				} else {
					_pshell->AddScanOffset(psectors[i - 1].VirtualAddress, psectors[i - 1].Misc.VirtualSize);
				}
			}
		}
	}

	if (!_pshell->BuildShell(&res)) {
		return SetError(E_INHERIT, __LINE__);
	}

//Save inject
	if (res.reloc_table) {
		if (GetArch() == PE_X86) {
			_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = res.reloc_table;
			_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = res.reloc_size;
		}/* else {
			_popt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = res.reloc_table;
			_popt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = res.reloc_size;
		}*/
	}

	//Inject setup
	if (_pshell->GetFlag(SF_TLS)) {
		if (GetArch() == PE_X86) {
			//Если TLS callback используется то не меняем его заголовок
			if (_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) {
				tls_dir.AddressOfCallBacks = res.tls_table + _popt32->ImageBase;
				if (!WriteVirtualData(_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, 
					&tls_dir, sizeof(IMAGE_TLS_DIRECTORY32))) {
					return SetError(E_INHERIT, __LINE__);
				}
			} else {
			//Если TLS callback не используется, то меняем на свой
				_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = res.tls_header;
				_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY32);
			}
		} else {
			//TODO x64
		}
	} else if (_pshell->GetFlag(SF_USE_EP)) {
		if (GetArch() == PE_X86) {
			//make tramplin
			offset = psectors[entry_id].VirtualAddress + psectors[entry_id].SizeOfRawData;
			ptramp = _pshell->BuildTramplin(offset, res.entry_offst, &size);
			if (!ptramp) {
				return SetError(E_UNKNOWN, __LINE__);
			}

			pbuff = (PBYTE)malloc(size);
			if (!ReadRawData(psectors[entry_id].PointerToRawData + psectors[entry_id].SizeOfRawData - size, pbuff, size)) {
				free(pbuff); return SetError(E_INHERIT, __LINE__);
			}
			bool is_clear = true;
			for (int i = 0; i < size; i++) {
				if (pbuff[i] != 0x00) {
					//TODO выполнить попытку расширения raw данных
					//free(pbuff); return SetError(E_UNKNOWN, __LINE__);
					is_clear = false;
					break;
				}
			}
			free(pbuff);
			if (!is_clear) {//Пробуем расширить raw данные
				if (offset + size > Aligment(psectors[entry_id].VirtualAddress + psectors[entry_id].Misc.VirtualSize)) {
					return SetError(E_UNKNOWN, __LINE__);
				}
				if (!ChangeSectionRawSize(entry_id, Aligment(psectors[entry_id].SizeOfRawData + size, PE_DEFAULT_FILE_ALIGMENT))) {
					return SetError(E_INHERIT, __LINE__);
				}
			}

			ptramp = _pshell->BuildTramplin(offset - size, res.entry_offst, &size);
			if (!ptramp) {
				return SetError(E_UNKNOWN, __LINE__);
			}
			if (!WriteVirtualData(offset - size, ptramp, size)) {
				return SetError(E_INHERIT, __LINE__);
			}
			_popt32->AddressOfEntryPoint = offset - size;
		} else {
			//TODO x64
		}
	}

	if (!EditSection(id, res.buffer, res.size, Aligment(res.size))) {
		return SetError(E_INHERIT, __LINE__);
	}

	return SetError(E_OK);
}

bool CDLibShellAttach::DetachShell()
{
	PIMAGE_SECTION_HEADER psect;
	IMAGE_TLS_DIRECTORY32 tls_dir;
	int id;
	if (!_shell_open) {
		return SetError(E_NOT_FOUND, __LINE__);
	}

	psect = GetSectorPtr(DLIB_SECTION);
	id = GetSectorNum(DLIB_SECTION);
	if (!psect) {
		return SetError(E_NOT_FOUND, __LINE__);
	}

	//recover headers
	PShell_Header phead = (PShell_Header)_pshell->GetHeaderStruct();
	if (!phead) {
		return SetError(E_UNKNOWN, __LINE__);
	}

	if (GetArch() == PE_X86) {
		_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = phead->rec_relocs_addr;
		_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = phead->rec_relocs_size;
		_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = phead->rec_tls_dir_addr;
		_popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = phead->rec_tls_size;
		if (phead->rec_tls_dir_addr) {
			if (!ReadVirtualData(phead->rec_tls_dir_addr, &tls_dir, sizeof(IMAGE_TLS_DIRECTORY32), 0, 0)) {
				return SetError(E_INHERIT, __LINE__);
			}
			tls_dir.AddressOfCallBacks = phead->rec_tls_clbk_addr;
			if (!WriteVirtualData(phead->rec_tls_dir_addr, &tls_dir, sizeof(IMAGE_TLS_DIRECTORY32))) {
				return SetError(E_INHERIT, __LINE__);
			}
		}

		BYTE sign[SHELL_TRAMP_SIZE];
		if (!ReadVirtualData(_popt32->AddressOfEntryPoint, sign, SHELL_TRAMP_SIZE, 0, 0)) {
			return SetError(E_INHERIT, __LINE__);
		}
		if (!memcmp(&sign[5], SHELL_TRAMP_SIGNATURE, SHELL_TRAMP_SIGN_SIZE)) {
			memset(sign, 0, SHELL_TRAMP_SIZE);
			if (!WriteVirtualData(_popt32->AddressOfEntryPoint, &sign, SHELL_TRAMP_SIZE)) {
				return SetError(E_INHERIT, __LINE__);
			}
		}
		_popt32->AddressOfEntryPoint = phead->rec_entrypoint;
	} else {
		//TODO x64
	}

	if (phead->rec_sec_raw_size) {
		if (!ChangeSectionRawSize(phead->rec_sec_id, phead->rec_sec_raw_size)) {
			return SetError(E_INHERIT, __LINE__);
		}
	}

	if (!RemoveSection(id)) {
		return SetError(E_INHERIT, __LINE__);
	}
	
	return SetError(E_OK);
}

void CDLibShellAttach::AddDll(LPVOID dllname, LPVOID dllproc, bool check_retn)
{
	_pshell->AddDll(dllname, dllproc, -1, check_retn);
}

void CDLibShellAttach::RemoveDLL(LPVOID dllname)
{
	_pshell->RemoveDll(dllname);
}

void CDLibShellAttach::RemoveAllDll()
{
	_pshell->RemoveAllDll();
}

bool CDLibShellAttach::GetDllList(PShell_DllFrame &plist, int max_count, int *readed)
{
	return _pshell->GetDllList(plist, max_count, readed);
}

bool CDLibShellAttach::EnableAdvance(PVOID dll_name, PVOID dll_proc)
{
	if (_pshell->SetAnticheatDll(dll_name, dll_proc)) {
		_pshell->SetFlag(SF_ADVANCE, true);
		return true;
	}
	return false;	
}

void CDLibShellAttach::AddIgnoreOffset(DWORD offset, UINT size)
{
	if (!_pshell->GetFlag(SF_ADVANCE)) {
		return;
	}
	_pshell->AddOffset(offset, size);
}

void CDLibShellAttach::RemoveIgnoreOffset(DWORD offset)
{
	if (!_pshell->GetFlag(SF_ADVANCE)) {
		return;
	}
	_pshell->RemoveOffset(offset);
}

bool CDLibShellAttach::GetIgnoreList(PShell_IgnoreFrame &plist, int max_count, int *readed)
{
	if (_pshell->GetFlag(SF_ADVANCE)) {
		return false;
	}
	return _pshell->GetOffsets(plist, max_count, readed);
}

UINT CDLibShellAttach::GetIgnoreListCount()
{
	return _pshell->GetOffsetsCount();
}

PIMAGE_SECTION_HEADER CDLibShellAttach::GetSectorList(PUINT pcount)
{
	return GetSectsPtr(pcount);
}

DWORD CDLibShellAttach::GetImgbase()
{
	return GetImagebase();
}

DWORD CDLibShellAttach::GetProtMask()
{
	/*if (!_pshell->GetFlag(SF_ADVANCE)) {
		return 0;
	}*/
	return _pshell->GetSectorProtMask();
}

void CDLibShellAttach::SetProtMask(DWORD mask)
{
	/*if (!_pshell->GetFlag(SF_ADVANCE)) {
		return;
	}*/
	_pshell->SetSectorProtMask(mask);
}

void CDLibShellAttach::SearchProtectSects()
{
	PIMAGE_SECTION_HEADER psect;
	UINT sect_count, num;
	DWORD entrypoint;
	DWORD mask = 0;
	BYTE buff[9];
	psect = GetSectorList(&sect_count);

	//Header section
	mask |= _BIT(0);
	//Search .text section
	for (int i = 0; i < sect_count; i++) {
		memset(buff, 0, 9);
		memcpy(buff, &psect[i].Name, 8);
		if (!strcmp((LPCSTR)buff, ".text")) {
			mask |= _BIT(i + 1);
			break;
		}
	}

	//Add EP sector
	if (GetArch() == PE_X86) {
		entrypoint = GetHOpt32()->AddressOfEntryPoint;
		num = GetSectorNum(entrypoint);
		mask |= _BIT(num);
	} else {
		//TODO x64
	}

	SetProtMask(mask);
}

void CDLibShellAttach::SetErrorMessage(Shell_Error_Msg type, PVOID message)
{
	_pshell->SetErrorMessage(type, message);
}

LPSTR CDLibShellAttach::GetErrorMessage(Shell_Error_Msg type)
{
	return _pshell->GetErrorMessage(type);
}

bool CDLibShellAttach::IsAttached()
{
	if (!_shell_open) {
		return false;
	}
	return _is_att;
}

PVOID CDLibShellAttach::GetShellResPtr(UINT id, PUINT psize)
{
	return _pshell->GetShellResPtr(id, psize);
}

bool CDLibShellAttach::IsShellOpen()
{
	return _shell_open;
}

void CDLibShellAttach::SetFlag(Shell_Flags flag, bool state)
{
	_pshell->SetFlag(flag, state);
}

bool CDLibShellAttach::GetFlag(Shell_Flags flag)
{
	return _pshell->GetFlag(flag);
}

// ======================= CDLibShellAttach :: PRIVATE =======================

bool CDLibShellAttach::GetResourcePtr(PVOID pout, PUINT psize, int res)
{
	HRSRC hres;
	HGLOBAL hresdata;

	hres = FindResource(NULL, MAKEINTRESOURCE(res), RT_RCDATA);
	hresdata = LoadResource(NULL, hres);
	*(PBYTE *)pout = (PBYTE)LockResource(hresdata);
	*psize = SizeofResource(NULL, hres);
	if (!*(PBYTE *)pout) {
		return false;
	}

	return true;
}

bool CDLibShellAttach::ReadTLSCallbackTable(DWORD voffset, PDWORD &ptbl, UINT *pcount)
{//TODO add max size
	PDWORD ptable;
	UINT count = 15, size, inx = 0;

	if (_tls_data) {
		free(_tls_data);
	}

	//x64 not supported
	voffset -= _popt32->ImageBase;

	size = sizeof(DWORD) * count;
	ptable = (PDWORD)malloc(size);
	_tls_data = (PBYTE)ptable;
	if (!ptable) {
		return SetError(E_ALLOC_FAIL, __LINE__);
	}
	do {
		if (!ReadVirtualData(voffset, ptable, size, NULL, false)) {
			return SetError(E_INHERIT, __LINE__);
		}

		while (inx < count) {
			if (ptable[inx] == NULL) {
				ptbl = ptable;
				if (pcount) {
					*pcount = inx;
				}
				return SetError(E_OK);
			}
			inx++;
		}

		count *= 2;
		size = sizeof(DWORD) * count;
		ptable = (PDWORD)realloc(ptable, size);
		_tls_data = (PBYTE)ptable;
		if (!ptable) {
			return SetError(E_ALLOC_FAIL, __LINE__);
		}
	} while (true);

	return SetError(E_OK);
}

PVOID CDLibShellAttach::ReadRelocsBlocks(DWORD voffset, UINT rel_size, UINT max_size, UINT *psize)
{
	PBYTE pbuffer;
	DWORD offset;
	PIMAGE_BASE_RELOCATION prel;
	if (!rel_size) {
		rel_size = sizeof(ULONGLONG) * 32;
	}
	if (rel_size > max_size) {
		return NULL;
	}
	pbuffer = (PBYTE)malloc(rel_size);
	if (!pbuffer) {
		return NULL;
	}

	offset = 0;
	do {
		if (!ReadVirtualData(voffset, pbuffer, rel_size, NULL, false)) {
			return NULL;
		}

		prel = (PIMAGE_BASE_RELOCATION)((DWORD)pbuffer + offset);
		while (offset + prel->SizeOfBlock + sizeof(IMAGE_BASE_RELOCATION) <= rel_size) {
			if (!prel->SizeOfBlock) {
				break;
			}
			offset += prel->SizeOfBlock;
			prel = (PIMAGE_BASE_RELOCATION)((DWORD)pbuffer + offset);
		}
		offset += prel->SizeOfBlock;

		if (offset /*+ prel->SizeOfBlock + sizeof(IMAGE_BASE_RELOCATION)*/ <= rel_size) {
			//prel = (PIMAGE_BASE_RELOCATION)((DWORD)pbuffer + offset + prel->SizeOfBlock);
			//if (prel->VirtualAddress == NULL && prel->SizeOfBlock == NULL) {
				_rel_data = pbuffer;
				_rel_size = rel_size;
				if (psize) {
					*psize = offset;
				}
				return _rel_data;
			//}
		}

		if (rel_size == max_size) {
			break;
		}

		rel_size = 2 * rel_size;
		if (rel_size > max_size) {
			rel_size = max_size;
		}
		pbuffer = (PBYTE)realloc(pbuffer, rel_size);
		if (!pbuffer) {
			return NULL;
		}
	} while (true);

	return NULL;
}
