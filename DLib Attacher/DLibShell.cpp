#include "stdafx.h"
#include "DLibShell.h"
#include "resource.h"

#include <stddef.h>
#include <stdint.h>

uint_least32_t Crc32(unsigned char *buf, size_t len);

// ======================= CDLibShellMain :: PUBLIC =======================

CDLibShellMain::CDLibShellMain() : _opened(false), _shell(NULL), _shell_size(0), _opcode(NULL), _opc_rel(NULL), _tramplin(NULL)
{
}

CDLibShellMain::~CDLibShellMain()
{
	Close();
}

bool CDLibShellMain::Load(PVOID buffer, UINT size)
{
	UINT res_size;

	if (_opened) {
		return SetError(E_STATE_ALLREADY, __LINE__);
	}

/* Load header */
	//main header load
	if (sizeof(Shell_MainHeader) > size) {
		return SetError(E_OVERFLOW, __LINE__);
	}
	memcpy(&_main, buffer, sizeof(Shell_MainHeader));
	if (_main.signature != SHELL_SIGNATURE) {
		return SetError(E_UNKNOWN, __LINE__);
	} else if (_main.version < SHELL_MINOR_VER || _main.version > SHELL_FORMAT_VER) {
		return SetError(E_UNKNOWN, __LINE__);
	} else if (_main.size > size) {
		return SetError(E_OVERFLOW, __LINE__);
	}

	//load header
	if (_main.header + sizeof(Shell_Header) > size) {
		return SetError(E_OVERFLOW, __LINE__);
	}
	if (_main.version == 1) {//old version
		memcpy(&_header, (PVOID)((DWORD)buffer + _main.header), sizeof(Shell_Header_v1));
	} else {
		memcpy(&_header, (PVOID)((DWORD)buffer + _main.header), sizeof(Shell_Header));
	}

	//load advance header
	if (_main.adv_header + sizeof(Shell_AdvHeader) > size) {
		return SetError(E_OVERFLOW, __LINE__);
	}
	memcpy(&_advance, (PVOID)((DWORD)buffer + _main.adv_header), sizeof(Shell_AdvHeader));

	//load resources
	_res.Clear();
	if (!_res.Decompile((PVOID)((DWORD)buffer + _main.res_table), (size - _main.res_table), &res_size)) {
		return SetError(E_UNKNOWN, __LINE__);
	}
	_main.res_count = _res.Count();

	if (_header.code_id >= _main.res_count || _header.tls_id >= _main.res_count
		 || _header.tls_head_id >= _main.res_count || _header.relocs_id >= _main.res_count
		 || _header.dll_table_id >= _main.res_count) {
		return SetError(E_UNKNOWN, __LINE__);
	}

	if (GetFlag(SF_ADVANCE) && _main.adv_header) {
		if (_main.version < 0x02) {
			_advance.sect_id = RES_INVALID_ID;
			_advance.sect_prot = 0;
		}
		if (_advance.ignore_id >= _main.res_count || (_advance.dll_id && _advance.dll_id >= _main.res_count)
			|| (_advance.dll_id && _advance.proc_id && _advance.proc_id >= _main.res_count)) {
			return SetError(E_UNKNOWN, __LINE__);
		}
	} else {
		SetFlag(SF_ADVANCE, false);
	}

	_tls_offset = _res.GetResOffset(_header.code_id);

	//load ignores
	_ignores.clear();
	if (GetFlag(SF_ADVANCE)) {
		PShell_IgnoreFrame pignor = (PShell_IgnoreFrame)_res.GetDataPtr(_advance.ignore_id, &res_size);
		_advance.ignore_count = res_size / sizeof(Shell_IgnoreFrame);
		for (int i = 0; i < _advance.ignore_count; i++) {
			_ignores.push_back(pignor[i]);
		}
		_advance.ignore_count = _ignores.size();
	}

	//load dlls
	_dlls.clear();
	PShell_DllFrame pdll = (PShell_DllFrame)_res.GetDataPtr(_header.dll_table_id, &res_size);
	_header.dll_count = res_size / sizeof(Shell_DllFrame);
	for (int i = 0; i < _header.dll_count; i++) {
		_dlls.push_back(pdll[i]);
	}
	_header.dll_count = _dlls.size();

	_opened = true;
	return SetError(E_OK);
}

bool CDLibShellMain::Create(PVOID opcode, UINT opc_size, PVOID relocs, UINT rel_size)
{
	DWORD reserved = 0;

	if (_opened) {
		return SetError(E_STATE_ALLREADY, __LINE__);
	}

	//Clear structures
	memset(&_main, 0, sizeof(Shell_MainHeader));
	memset(&_header, 0, sizeof(Shell_Header));
	memset(&_advance, 0, sizeof(Shell_AdvHeader));

	//Researve resources
	_header.code_id = _res.Add(&reserved, sizeof(DWORD)); /* Warning, 1:code, 2:tls, 3:relocs; it's require this order */
	_header.tls_id = _res.Add(&reserved, sizeof(DWORD));
	_header.tls_head_id = _res.Add(&reserved, sizeof(DWORD));
	_header.relocs_id = _res.Add(&reserved, sizeof(DWORD));
	_header.dll_table_id = _res.Add(&reserved, sizeof(DWORD));

//	_header.relocs_table_id = _res.Add(&reserved, sizeof(DWORD));
	_advance.ignore_id = _res.Add(&reserved, sizeof(DWORD));
/*	_advance.dll_id = _res.Add(&reserved, sizeof(DWORD));
	_advance.proc_id = _res.Add(&reserved, sizeof(DWORD));*/
	if (_header.dll_table_id == RES_INVALID_ID || _header.code_id == RES_INVALID_ID/* || _header.relocs_table_id == RES_INVALID_ID*/
		|| _header.tls_id == RES_INVALID_ID || _header.relocs_id == RES_INVALID_ID
		|| _advance.ignore_id == RES_INVALID_ID || _header.tls_head_id == RES_INVALID_ID
		/* || _advance.dll_id == RES_INVALID_ID || _advance.proc_id == RES_INVALID_ID*/) {
		return SetError(E_UNKNOWN, __LINE__);
	}

	for (int i = 0; i < PHRASE_ERROR_COUNT; i++) {
		_header.phr_error_id[i] = _res.Add(&reserved, sizeof(DWORD));
		if (_header.phr_error_id[i] == RES_INVALID_ID) {
			return SetError(E_INHERIT, __LINE__);
		}
	}

	if (!LoadOpcode(opcode, opc_size, relocs, rel_size)) {
		return SetError(E_INHERIT, __LINE__);
	}

	_main.signature = SHELL_SIGNATURE;
	_main.version = SHELL_FORMAT_VER;
	_advance.dll_id = RES_INVALID_ID;
	_advance.proc_id = RES_INVALID_ID;
	_advance.sect_id = RES_INVALID_ID;//v3
	_tls_offset = SHELL_VALUE_NONE;
	_header.rec_relocs_addr = SHELL_VALUE_NONE;
	_header.rec_relocs_size = SHELL_VALUE_NONE;
	_header.rec_tls_clbk_addr = SHELL_VALUE_NONE;
	_header.rec_tls_dir_addr = SHELL_VALUE_NONE;
	_header.rec_tls_size = SHELL_VALUE_NONE;

	//create shell

	_opened = true;
	return SetError(E_OK);
}

void CDLibShellMain::Close()
{
	if (_opened) {
		if (_shell) {
			free(_shell);
			_shell = NULL;
			_shell_size = 0;
		}
		if (_tramplin) {
			free(_tramplin);
			_tramplin = NULL;
		}
		ClearOpcode();
		_res.Clear();
		_dlls.clear();
		_ignores.clear();
		_prots.clear();
		_opened = false;
	}
}

bool CDLibShellMain::LoadOpcode(PVOID opcode, UINT opc_size, PVOID relocs, UINT rel_size)
{
	PBYTE opc, rel;
	PShell_Opcode_Header prelhead = (PShell_Opcode_Header)relocs;

	relocs = (PVOID)((DWORD)relocs + sizeof(Shell_Opcode_Header));
	rel_size -= sizeof(Shell_Opcode_Header);

	if (_opcode) {
		ClearOpcode();
	}

	memcpy(&_shell_addr, (PShell_Opcode_Export)opcode, sizeof(Shell_Opcode_Export));
	opcode = (PVOID)((DWORD)opcode + sizeof(Shell_Opcode_Export));
	opc_size -= sizeof(Shell_Opcode_Export);

	//Opcode
	opc = (PBYTE)malloc(opc_size);
	if (!opc) {
		return SetError(E_ALLOC_FAIL, __LINE__);
	}
	memcpy(opc, opcode, opc_size);

	//Relocs
	if (relocs) {
		rel = (PBYTE)malloc(rel_size);
		if (!rel) {
			free(opc);
			return SetError(E_ALLOC_FAIL, __LINE__);
		}
		memcpy(rel, relocs, rel_size);
	} else {
		rel = NULL;
		rel_size = 0;
	}

	_opcode = opc;
	_opc_size = opc_size;
	_opc_rel = rel;
	_opc_rel_size = rel_size;
	_opc_imgbase = prelhead->imgbase;
	_opc_relbase = prelhead->relbase;

	return SetError(E_OK);
}

bool CDLibShellMain::LoadTLSCallbackTable(PVOID ptable, UINT count, bool new_header, PVOID pdir)
{
	if (!_opened) {
		return SetError(E_NOT_FOUND, __LINE__);
	}

	UINT new_count = count + 2;
	PDWORD new_table = new DWORD[new_count];

	memset(new_table, 0, sizeof(DWORD) * new_count);
	if (ptable) {
		memcpy((DWORD *)((DWORD)new_table + sizeof(DWORD)), ptable, sizeof(DWORD) * count);
	}

	if (!_res.Edit(_header.tls_id, new_table, sizeof(DWORD) * new_count)) {
		delete[] new_table;
		return SetError(E_UNKNOWN, __LINE__);
	}
	delete[] new_table;

	if (new_header) {
		IMAGE_TLS_DIRECTORY32 dir = {0};
		if (pdir) {
			memcpy(&dir, pdir, sizeof(IMAGE_TLS_DIRECTORY32));
		}
		if (!_res.Edit(_header.tls_head_id, &dir, sizeof(IMAGE_TLS_DIRECTORY32))) {
			return SetError(E_UNKNOWN, __LINE__);
		}
		SetFlag(SF_TLS_DIR, true);
	}

	SetFlag(SF_TLS, true);
	return SetError(E_OK);
}

bool CDLibShellMain::LoadRelocsTable(PVOID ptable, UINT size, DWORD ign_offst, UINT ign_size)
{
	DWORD offset, new_size;
	PIMAGE_BASE_RELOCATION prel;

	if (!_opened) {
		return SetError(E_NOT_FOUND, __LINE__);
	}

	if (size == 0) {
		SetFlag(SF_RELOCS, false);
		return SetError(E_OK);
	}

	// check current size
	offset = 0;
	new_size = 0;
	/*while (offset <= size) {
		prel = (PIMAGE_BASE_RELOCATION)((DWORD)ptable + offset);
		new_size = offset;
		if (offset + sizeof(IMAGE_BASE_RELOCATION) >= size) {
			break;
		} 
		offset += prel->SizeOfBlock;
	}*/
	if (!_relocs.LoadTable(ptable, size)) {
		return SetError(E_UNKNOWN, __LINE__);
	}
	if (ign_offst) {
		_relocs.RemoveRange(ign_offst, ign_size);
	}
	new_size = _relocs.CalcCompileSize();
	if (new_size == 0) {
		SetFlag(SF_RELOCS, false);
		return SetError(E_OK);
	}

	if (!_res.Edit(_header.relocs_id, ptable, new_size)) {
		return SetError(E_INHERIT, __LINE__);
	}

	SetFlag(SF_RELOCS, true);
	return SetError(E_OK);
}

int CDLibShellMain::AddDll(PVOID dll_name, PVOID proc_name, int pos, bool check_retn)
{
	Shell_DllFrame frame;
	frame.name_id = _res.Add(dll_name, strlen((LPSTR)dll_name) + 1);
	if (proc_name) {
		frame.func_id = _res.Add(proc_name, strlen((LPSTR)proc_name) + 1) | (check_retn ? SHELL_EXP_PROC_USE_RETN : 0);
	} else {
		frame.func_id = RES_INVALID_ID;
	}

	if (pos >= _dlls.size() || pos < 0) {
		pos = _dlls.size();
		_dlls.push_back(frame);
	} else {
		std::list<Shell_DllFrame>::iterator it = _dlls.begin();
		int i = 0;
		while (it != _dlls.end()) {
			if (i == pos) {
				_dlls.insert(it, frame);
				break;
			}
			i++; it++;
		}
	}

	return pos;
}

void CDLibShellMain::RemoveDll(PVOID dll_name)
{
	std::list<Shell_DllFrame>::iterator it = _dlls.begin();
	PBYTE pname;
	while (it != _dlls.end()) {
		pname = (PBYTE)_res.GetDataPtr(it->name_id, NULL);
		if (pname && !strcmp((char *)pname, (char *)dll_name)) {
			_res.Delete(_CLEAR(it->func_id, 1));
			_res.Delete(it->name_id);
			_dlls.erase(it);
		}
		it++;
	}
}

void CDLibShellMain::RemoveAllDll() 
{
	std::list<Shell_DllFrame>::iterator it = _dlls.begin();
	PBYTE pname;
	while (it != _dlls.end()) {
		_res.Delete(_CLEAR(it->func_id, 1));
		_res.Delete(it->name_id);
		it++;
	}
	_dlls.clear();
}


bool CDLibShellMain::GetDllList(PShell_DllFrame &plist, int max_count, int *readed)
{
	std::list<Shell_DllFrame>::iterator it;
	int i = 0;
	if (max_count < _dlls.size()) {
		if (readed) {
			*readed = _dlls.size();
		}
		return false;
	}
	if (readed) {
		*readed = 0;
	}

	it = _dlls.begin();
	while (it != _dlls.end() && i < max_count) {
		plist[i].func_id = it->func_id;
		plist[i].name_id = it->name_id;
		i++;
		it++;
	}
	if (readed) {
		*readed = i;
	}

	return true;
}

void CDLibShellMain::AddOffset(DWORD offset, UINT size)
{//TODO можно прикрутить алгоритм обьеденения пересекающихся блоков
	Shell_IgnoreFrame frame;
	frame.offset = offset;
	frame.size = size;
	_ignores.push_back(frame);
}

void CDLibShellMain::RemoveOffset(DWORD offset)
{
	std::list<Shell_IgnoreFrame>::iterator it = _ignores.begin();
	while (it != _ignores.end()) {
		if (it->offset == offset) {
			_ignores.erase(it);
			break;
		}
		it++;
	}
}

void CDLibShellMain::ClearOffsets()
{
	_ignores.clear();
}

bool CDLibShellMain::GetOffsets(PShell_IgnoreFrame &plist, int max_count, int *readed)
{
	std::list<Shell_IgnoreFrame>::iterator it;
	int i = 0;
	if (max_count < _ignores.size()) {
		if (readed) {
			*readed = _ignores.size();
		}
		return false;
	}
	if (readed) {
		*readed = 0;
	}

	it = _ignores.begin();
	while (it != _ignores.end() && i < max_count) {
		plist[i].offset = it->offset;
		plist[i].size = it->size;
		i++;
		it++;
	}
	if (readed) {
		*readed = i;
	}

	return true;
}

UINT CDLibShellMain::GetOffsetsCount()
{
	return _ignores.size();
}

bool CDLibShellMain::SetAnticheatDll(PVOID dll_name, PVOID proc_name)
{
	if (_advance.dll_id == RES_INVALID_ID) {
		_advance.dll_id = _res.Add(dll_name, strlen((LPSTR)dll_name) + 1);
	} else {
		_res.Edit(_advance.dll_id, dll_name, strlen((LPSTR)dll_name) + 1);
	}

	if (_advance.proc_id == RES_INVALID_ID) {
		_advance.proc_id = _res.Add(proc_name, strlen((LPSTR)proc_name) + 1);
	} else {
		_res.Edit(_advance.proc_id, proc_name, strlen((LPSTR)proc_name) + 1);
	}

	if (_advance.dll_id == RES_INVALID_ID && _advance.proc_id == RES_INVALID_ID) {
		return false;
	}
	return true;
}

void CDLibShellMain::SetSectorProtMask(DWORD mask)
{
	_advance.sect_prot = mask;
}

DWORD CDLibShellMain::GetSectorProtMask()
{
	return _advance.sect_prot;
}

void CDLibShellMain::AddScanOffset(DWORD offset, UINT size)
{
	Shell_IgnoreFrame frame;
	frame.offset = offset;
	frame.size = size;
	_prots.push_back(frame);
}

void CDLibShellMain::RemoveScanOffset(DWORD offset)
{
	std::list<Shell_IgnoreFrame>::iterator it = _prots.begin();
	while (it != _prots.end()) {
		if (it->offset == offset) {
			_prots.erase(it);
			break;
		}
		it++;
	}
}

void CDLibShellMain::ClearScanOffsets()
{
	_prots.clear();
}

void CDLibShellMain::SetErrorMessage(Shell_Error_Msg type, PVOID message)
{
	_res.Edit(_header.phr_error_id[type], message, strlen((LPSTR)message) + 1);
}

LPSTR CDLibShellMain::GetErrorMessage(Shell_Error_Msg type)
{
	return (LPSTR)_res.GetDataPtr(_header.phr_error_id[type], NULL);
}

void CDLibShellMain::SetFlag(Shell_Flags flag, bool state)
{
	if (state) {
		_main.flags |= flag;
	} else {
		if (GetFlag(flag)) {
			_main.flags ^= flag;
		}
	}
}

bool CDLibShellMain::GetFlag(Shell_Flags flag)
{
	return (_main.flags & flag);
}

bool CDLibShellMain::BuildShell(PShell_Build_Result result)
{
	PBYTE pbuffer, pres, pcompile;
	DWORD offset, res_size, res_offset, code_offset, rel_offset;
	UINT comp_size, size, i;
	PIMAGE_BASE_RELOCATION prel;

/*	if (_heapchk() != _HEAPOK) {
		MessageBoxA(NULL, "Error, heap corrupt", "Error", NULL);
	}*/
	if (GetFlag(SF_USE_EP) && GetFlag(SF_TLS)) {
		//can't build double attach to EP and TLS
		return false;
	}

/* Setup */
	res_offset = sizeof(Shell_MainHeader) + sizeof(Shell_Header);
	if (GetFlag(SF_ADVANCE)) {
		res_offset += sizeof(Shell_AdvHeader);
	}

	code_offset = _res.GetResOffset(_header.code_id);//get code offset
	if (code_offset == RES_INVALID_ID) {
		return SetError(E_UNKNOWN, __LINE__);
	}

	//Code relocs commit
	i = 0;
/*	pbuffer = (PBYTE)_res.GetDataPtr(_header.code_id, NULL);*/
	while (i < _opc_rel_size) {
		prel = (PIMAGE_BASE_RELOCATION)((DWORD)_opc_rel + i);
		i += prel->SizeOfBlock;
		if (prel->SizeOfBlock == 0) {
			break;
		}

		int count = (prel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD rels = (PWORD)((DWORD)prel + sizeof(IMAGE_BASE_RELOCATION));
		DWORD type;
		for (int a = 0; a < count; a++) {
			type = rels[a] >> 12;
			switch (type) {
			case IMAGE_REL_BASED_HIGHLOW://3
				offset = prel->VirtualAddress + (0x00000FFF & rels[a]);
				if (offset >= _opc_size) {//check unlocate reloc
					break;
				}
				*(DWORD *)((DWORD)_opcode + offset) -= (_opc_imgbase - result->imagebase);
				*(DWORD *)((DWORD)_opcode + offset) += result->sect_offst + res_offset + code_offset  - _opc_relbase;
				//add relocs in list
				if (GetFlag(SF_RELOCS)) {
					_relocs.AddRel(result->sect_offst + res_offset + code_offset + offset);
				}
				break;
			default:
				break;
			}
		}
	}
	_res.Edit(_header.code_id, _opcode, _opc_size);
	SetOpcHeadAddr(result->sect_offst);

	//Used TLS
	if (GetFlag(SF_TLS) && !GetFlag(SF_USE_EP)) {
		UINT tls_size, tls_offset;
		PDWORD ptls = (PDWORD)_res.GetDataPtr(_header.tls_id, &tls_size);
		tls_offset = _res.GetResOffset(_header.tls_id);
		if (!ptls) {
			return SetError(E_UNKNOWN, __LINE__);
		}
		
		tls_size /= sizeof(DWORD);//size to count

		//search and destroy TLS double link
		if (_tls_offset != SHELL_VALUE_NONE) {
			_tls_offset += result->imagebase + result->sect_offst + res_offset;
			for (i = 0; i < tls_size; i++) {
				if (ptls[i] == _tls_offset) {
					for (int a = tls_size - 1; a > i; a--) {
						ptls[a - 1] = ptls[a];
					}
					tls_size--;
					_res.Edit(_header.tls_id, ptls, tls_size * sizeof(DWORD));
				}
			}
		}

		ptls[0] = result->sect_offst + res_offset + code_offset + result->imagebase;

		result->tls_table = _res.GetResOffset(_header.tls_id);
		if (result->tls_table == RES_INVALID_ID) {
			return SetError(E_UNKNOWN, __LINE__);
		}
		result->tls_table += result->sect_offst + res_offset;
		if (GetFlag(SF_RELOCS)) {
			/*tls_size /= sizeof(DWORD);*/
			for (i = 0; i < tls_size; i++) {
				if (!ptls[i]) {
					break;
				}
				_relocs.AddRel(result->sect_offst + res_offset + tls_offset + (sizeof(DWORD) * i));
			}
		}

		//tls dir
		if (GetFlag(SF_TLS_DIR)) {
			PIMAGE_TLS_DIRECTORY32 ptls_dir = (PIMAGE_TLS_DIRECTORY32)_res.GetDataPtr(_header.tls_head_id, NULL);
			if (!ptls_dir) {
				return SetError(E_UNKNOWN, __LINE__);
			}

			DWORD tls_head_offset = _res.GetResOffset(_header.tls_head_id);
			if (tls_head_offset == RES_INVALID_ID) {
				return SetError(E_UNKNOWN, __LINE__);
			}

			if (!ptls_dir->StartAddressOfRawData) {
				ptls_dir->StartAddressOfRawData = result->imagebase + result->sect_offst;
				ptls_dir->EndAddressOfRawData = ptls_dir->StartAddressOfRawData + 1;
			}
			if (!ptls_dir->AddressOfIndex) {
				size = 0;
				_res.GetDataPtr(_header.tls_id, &size);
				ptls_dir->AddressOfIndex = result->imagebase + result->sect_offst + res_offset + tls_head_offset + size - sizeof(DWORD);
			}
			ptls_dir->AddressOfCallBacks = result->imagebase + result->sect_offst + res_offset + tls_offset;
/*			ptls_dir->Characteristics = 0;
			ptls_dir->SizeOfZeroFill = 0;*/

			//add tls dir relocs
			if (GetFlag(SF_RELOCS)) {
				tls_offset = _res.GetResOffset(_header.tls_head_id);
				_relocs.AddRel(result->sect_offst + res_offset + tls_offset + (sizeof(DWORD) * 1));
				_relocs.AddRel(result->sect_offst + res_offset + tls_offset + (sizeof(DWORD) * 2));
				_relocs.AddRel(result->sect_offst + res_offset + tls_offset + (sizeof(DWORD) * 3));
				_relocs.AddRel(result->sect_offst + res_offset + tls_offset);
			}
		}
	}

	//Load dlls
	std::list<Shell_DllFrame>::iterator it_dll = _dlls.begin();
	PBYTE pdata;
	i = 0;
	_res.Resize(_header.dll_table_id, _dlls.size() * sizeof(Shell_DllFrame));
	pdata = (PBYTE)_res.GetDataPtr(_header.dll_table_id, NULL);
	while (it_dll != _dlls.end()) {
		memcpy(pdata + i, &*it_dll, sizeof(Shell_DllFrame));
		i += sizeof(Shell_DllFrame);
		it_dll++;
	}
	_header.dll_count = _dlls.size();

	if (GetFlag(SF_ADVANCE)) {
		//Load ignores
		std::list<Shell_IgnoreFrame>::iterator it_ign = _ignores.begin();
		i = 0;
		_res.Resize(_advance.ignore_id, _dlls.size() * sizeof(Shell_IgnoreFrame));
		pdata = (PBYTE)_res.GetDataPtr(_advance.ignore_id, NULL);
		while (it_ign != _ignores.end()) {
			memcpy(pdata + i, &*it_ign, sizeof(Shell_IgnoreFrame));
			i += sizeof(Shell_IgnoreFrame);
			it_ign++;
		}
		_advance.ignore_count = _ignores.size();
		
		//Load protected sections
		UINT sprot_count = 0;
		_advance.sect_id = _res.Add(&sprot_count, sizeof(DWORD));
		//for (int i = 0; i < )
	}

	//compile relocs
	if (GetFlag(SF_RELOCS)) {
		pcompile = (PBYTE)_relocs.Compile(&comp_size);
		if (!pcompile) {
			return SetError(E_UNKNOWN, __LINE__);
		}
		if (!_res.Edit(_header.relocs_id, pcompile, comp_size)) {
			return SetError(E_UNKNOWN, __LINE__);
		}
	}

	RecalcShellSize();

	_main.signature = SHELL_SIGNATURE;
	_main.version = SHELL_FORMAT_VER;
	_main.res_count = _res.Count();

	offset = sizeof(Shell_MainHeader);
	_main.header = offset;
	offset += sizeof(Shell_Header);
	if (GetFlag(SF_ADVANCE)) {
		_main.adv_header = offset;
		offset += sizeof(Shell_AdvHeader);
	}
	_main.res_table = offset;

	//setup original values
	if (_header.rec_relocs_addr == SHELL_VALUE_NONE) {
		_header.rec_relocs_addr = result->ori_relocs_addr;
		_header.rec_relocs_size = result->ori_relocs_size;
	}
	if (_header.rec_tls_dir_addr == SHELL_VALUE_NONE) {
		_header.rec_tls_clbk_addr = result->ori_tls_clbk_addr;
		_header.rec_tls_dir_addr = result->ori_tls_dir_addr;
		_header.rec_tls_size = result->ori_tls_size;
	}
	_header.rec_entrypoint = result->ori_entrypoint;
	_header.rec_sec_id = result->ori_sec_id;
	_header.rec_sec_raw_size = result->ori_sec_raw_size;

/*	if (GetFlag(SF_USE_EP)) {
		//TODO mb
	}*/

	_header.checksum = NULL;

/* Build */
	//headers
	offset = 0;
	pbuffer = (PBYTE)malloc(_main.size);
	if (!pbuffer) {
		return SetError(E_ALLOC_FAIL, __LINE__);
	}
	memcpy(pbuffer, &_main, sizeof(Shell_MainHeader));
	offset += sizeof(Shell_MainHeader);

	memcpy(pbuffer + offset, &_header, sizeof(Shell_Header));
	offset += sizeof(Shell_Header);

	if (GetFlag(SF_ADVANCE)) {
		memcpy(pbuffer + offset, &_advance, sizeof(Shell_AdvHeader));
		offset += sizeof(Shell_AdvHeader);
	}

	//resources
	res_size = _main.size - offset;
	pres = (PBYTE)malloc(res_size);
	if (!pres) {
		free(pbuffer);
		return SetError(E_ALLOC_FAIL, __LINE__);
	}

	if (!_res.Compile(pres, res_size, &comp_size)) {
		free(pbuffer); free(pres);
		return SetError(E_INHERIT, __LINE__);
	}
	memcpy(pbuffer + offset, pres, res_size);
	free(pres);

	//TOTEST !!
	if (GetFlag(SF_CRC32)) {
		PShell_Header phead = (PShell_Header)(pbuffer + sizeof(Shell_MainHeader));
		phead->checksum = Crc32(pbuffer, _main.size);
		//*(DWORD *)(pbuffer + _main.size - sizeof(DWORD)) = Crc32(pbuffer, _main.size - sizeof(DWORD));
	}

	//output
	result->buffer = _shell = pbuffer;
	result->size = _shell_size = _main.size;

	if (GetFlag(SF_TLS)) {
		result->tls_table = result->sect_offst + res_offset + _res.GetResOffset(_header.tls_id);
		result->tls_header = result->sect_offst + res_offset + _res.GetResOffset(_header.tls_head_id);
		result->entry_offst = result->sect_offst + res_offset + _res.GetResOffset(_header.code_id) + _shell_addr.ep_tls;
	} else {
		result->tls_table = NULL;
		result->entry_offst = result->sect_offst + res_offset + _res.GetResOffset(_header.code_id) 
			+ (GetFlag(SF_DLL) ? _shell_addr.ep_dll : _shell_addr.ep_main);
	}

	size = 0;
	_res.GetDataPtr(_header.tls_id, &size);
	result->tls_size = size;

	size = 0;
	if (GetFlag(SF_RELOCS)) {
		result->reloc_table = result->sect_offst + res_offset + _res.GetResOffset(_header.relocs_id);
		_res.GetDataPtr(_header.relocs_id, &size);
		result->reloc_size = size;
	} else {
		result->reloc_table = 0;
		result->reloc_size = 0;
	}

	return SetError(E_OK);
}

PBYTE CDLibShellMain::BuildTramplin(DWORD from, DWORD to, PUINT psize)
{
	enum {OPCODE_SIZE = 5, JMP_OPCODE = 0xE9};
	if (_tramplin) {
		free(_tramplin);
	}
	_tramplin = (PBYTE)malloc(SHELL_TRAMP_SIZE);
	_tramplin[0] = JMP_OPCODE;
	*(DWORD *)(&_tramplin[1]) = to - from - OPCODE_SIZE;
	memcpy(&_tramplin[5], SHELL_TRAMP_SIGNATURE, SHELL_TRAMP_SIGN_SIZE);
	if (psize) {
		*psize = SHELL_TRAMP_SIZE;
	}
	return _tramplin;
}

PVOID CDLibShellMain::GetHeaderStruct()
{
	if (!_opened) {
		return NULL;
	}
	return &_header;
}

PVOID CDLibShellMain::GetShellResPtr(UINT id, PUINT psize)
{
	return _res.GetDataPtr(id, psize);
}

// ======================= CDLibShellMain :: PRIVATE =======================

UINT CDLibShellMain::RecalcShellSize()
{//TODO добавить расчёт таблицы релоков, тлс каллбеков
	UINT size = sizeof(Shell_MainHeader) + sizeof(Shell_Header);
	if (GetFlag(SF_ADVANCE)) {
		size += sizeof(Shell_AdvHeader);
		size += _ignores.size() * sizeof(Shell_IgnoreFrame);
	}
	size += _res.GetTotalSize();
	size += _dlls.size() * sizeof(Shell_DllFrame);
	size += sizeof(DWORD);//checksum
	_main.size = size;
	return size;
}

void CDLibShellMain::ClearOpcode()
{
	if (_opcode) {
		free(_opcode);
		_opcode = NULL;
	}
	if (_opc_rel) {
		free(_opc_rel);
		_opc_rel = NULL;
	}
}

bool CDLibShellMain::SetOpcHeadAddr(BOOL addr)
{
	UINT size, i = 0;
	PBYTE pcode = (PBYTE)_res.GetDataPtr(_header.code_id, &size);
	PShellcode_Struct pstruct;

	if (!pcode) {
		return SetError(E_UNKNOWN, __LINE__);
	}

	while (i + sizeof(Shellcode_Struct) < size) {
		pstruct = (PShellcode_Struct)(pcode + i);
		if (pstruct->signature == SHELL_CODE_SIGNATURE
		 && pstruct->address_of_header == SHELL_CODE_SIGNATURE2
		 && pstruct->signature2 == SHELL_CODE_SIGNATURE3) {	
			pstruct->address_of_header = addr;
			return SetError(E_OK);
		}
		i++;
	}

	return SetError(E_NOT_FOUND, __LINE__);
}


//Wikipedia.org
/*
  Name  : CRC-32
  Poly  : 0x04C11DB7    x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 
                       + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
  Init  : 0xFFFFFFFF
  Revert: true
  XorOut: 0xFFFFFFFF
  Check : 0xCBF43926 ("123456789")
  MaxLen: 268 435 455 байт (2 147 483 647 бит) - обнаружение
   одинарных, двойных, пакетных и всех нечетных ошибок
*/
uint_least32_t Crc32(unsigned char *buf, size_t len)
{
    uint_least32_t crc_table[256];
    uint_least32_t crc; int i, j;
 
    for (i = 0; i < 256; i++)
    {
        crc = i;
        for (j = 0; j < 8; j++)
            crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
 
        crc_table[i] = crc;
    };
 
    crc = 0xFFFFFFFFUL;
 
    while (len--) 
        crc = crc_table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
 
    return crc ^ 0xFFFFFFFFUL;
}
