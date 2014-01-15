#include "stdafx.h"
#include "PEManager.h"
#include <stdlib.h>

// ======================= CPEInfo :: PUBLIC =======================

CPEInfo::CPEInfo() : _loaded_flag(false)
{
	return;
}

CPEInfo::~CPEInfo()
{
	return;
}

BOOL CPEInfo::ParseHeader(PVOID buffer)
{
	PBYTE data = (PBYTE)buffer;
	DWORD offset = 0, arch_size = 0;

	_loaded_flag = false;

	_pdos = (PIMAGE_DOS_HEADER)data;
	if (_pdos->e_magic != IMAGE_DOS_SIGNATURE) {
		return SetError(E_UNKNOWN, __LINE__, NULL);
	}
	offset = _pdos->e_lfanew;

	if (*(DWORD *)(data + offset) != (DWORD)IMAGE_NT_SIGNATURE) {
		return SetError(E_UNKNOWN, __LINE__, NULL);
	}
	offset += 4;

	_pimg = (PIMAGE_FILE_HEADER)(data + offset);
	offset += sizeof(IMAGE_FILE_HEADER);
	_sect_count = _pimg->NumberOfSections;

	// Load PE optional header
	if (GetArch() == PE_X86) {
		_popt32 = (PIMAGE_OPTIONAL_HEADER32)(data + offset);
		_popt64 = NULL;
		arch_size = sizeof(IMAGE_OPTIONAL_HEADER32);
	} else if (GetArch() == PE_X64) {
		_popt32 = NULL;
		_popt64 = (PIMAGE_OPTIONAL_HEADER64)(data + offset);
		arch_size = sizeof(IMAGE_OPTIONAL_HEADER64);
	} else {
		return SetError(E_UNKNOWN, __LINE__, NULL);
	}
	offset += arch_size;

	// Load PE sections
	_psects = (PIMAGE_SECTION_HEADER)(data + offset);
	offset += (sizeof(IMAGE_SECTION_HEADER) * _pimg->NumberOfSections);
	if (offset > 0x1000) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}

	_range = _CalcVirtualRange();
	_loaded_flag = true;
	return SetError(E_OK);
}

BOOL CPEInfo::HeaderIsLoaded()
{
	return _loaded_flag;
}

PE_Architecture CPEInfo::GetArch()
{
	if (_pimg->Machine == IMAGE_FILE_MACHINE_I386) {
		return PE_X86;
	} else if (_pimg->Machine == IMAGE_FILE_MACHINE_AMD64) {
		return PE_X64;
	}
	return PE_UNK;
}

PIMAGE_DOS_HEADER CPEInfo::GetHDos()
{
	return _pdos;
}

PIMAGE_FILE_HEADER CPEInfo::GetHImg()
{
	return _pimg;
}

PIMAGE_OPTIONAL_HEADER32 CPEInfo::GetHOpt32()
{
	return _popt32;
}

PIMAGE_OPTIONAL_HEADER64 CPEInfo::GetHOpt64()
{
	return _popt64;
}

PIMAGE_SECTION_HEADER CPEInfo::GetSectsPtr(PUINT count)
{
	if (count) {
		*count = _sect_count;
	}
	return _psects;
}

PIMAGE_SECTION_HEADER CPEInfo::GetSectorPtr(LPSTR name)
{
	char buffer[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
	for (int i = 0; i < _sect_count; i++) {
		memcpy(buffer, _psects[i].Name, IMAGE_SIZEOF_SHORT_NAME);
		if (!strcpy(buffer, name)) {
			return &_psects[i];
		}
	}
	return NULL;
}

UINT CPEInfo::GetVirtualRange()
{
	return _range;
}

INT CPEInfo::CheckInSectionOffset(DWORD voffset, UINT sector)
{/* Return:
	-1 - out of section
	0 - in raw range
	1 - in virtual range */
	if (sector >= _sect_count) {//not found
		return INSEC_OUT;
	} else if (_psects[sector].VirtualAddress > voffset) {//out of range
		return INSEC_OUT;
	} else if (_psects[sector].VirtualAddress + _psects[sector].SizeOfRawData < voffset) {
		//TODO normal calc virtual size
		if (_psects[sector].VirtualAddress + _psects[sector].Misc.VirtualSize > voffset) {//out of raw but into virtual
			return INSEC_VIRT;
		}
		return INSEC_OUT;
	}
	return INSEC_RAW;
}

UINT CPEInfo::Aligment(UINT size, UINT aligm_base)
{
	UINT new_size = size;
	if (size % aligm_base != 0) {
		new_size += aligm_base - (size % aligm_base);
	}
	return new_size;
}

// ======================= CPEFileManager :: PROTECTED =======================

UINT CPEInfo::_CalcVirtualRange()
{
	UINT diff, sect, 
		range = 0, 
		aligment = (GetArch() == PE_X64 ? GetHOpt64()->SectionAlignment : GetHOpt32()->SectionAlignment);

	for (unsigned int i = 0; i < _sect_count; i++) {
		sect = _psects[i].VirtualAddress + _psects[i].Misc.VirtualSize;
		diff = sect % aligment;
		if (diff > 0) {
			sect += aligment - diff;
		}

		if (range < sect) {
			range = sect;
		}
	}
	return range;
}

INT CPEInfo::_CalcHeaderSize(PVOID buffer, UINT size)
{
#define _HEADER_MIN_SIZE sizeof(IMAGE_DOS_HEADER) + sizeof(PIMAGE_FILE_HEADER) + sizeof(PIMAGE_OPTIONAL_HEADER32) + 4
	DWORD offset = 0;
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_FILE_HEADER pimg;

	if (size < _HEADER_MIN_SIZE) {
		return (- (int(_HEADER_MIN_SIZE)));//header size too small
	}

	pdos = (PIMAGE_DOS_HEADER)buffer;
	offset = pdos->e_lfanew + 4;

	pimg = (PIMAGE_FILE_HEADER)(offset + (DWORD)buffer);
	offset += sizeof(IMAGE_FILE_HEADER);
	if (offset >= size) {
		return (- (int)offset);
	}

	if (pimg->Machine == IMAGE_FILE_MACHINE_I386) {
		offset += sizeof(IMAGE_OPTIONAL_HEADER32);
	} else if (pimg->Machine == IMAGE_FILE_MACHINE_AMD64) {
		offset += sizeof(IMAGE_OPTIONAL_HEADER64);
	} else {
		return 0;
	}

	offset += (sizeof(IMAGE_SECTION_HEADER) * pimg->NumberOfSections);
	if (offset >= size) {
		return (- (int)offset);
	}

	return offset;
}

// ======================= CPEFileManager :: PUBLIC =======================

CPEFileManager::CPEFileManager() : CPEInfo(), _opened(false), _can_write(false), _data_size(0), _data(NULL)
{
}

CPEFileManager::~CPEFileManager()
{
	Close();
}

BOOL CPEFileManager::Open(LPWSTR filename, BOOL write_mode)
{
	DWORD reloc_addr = 0, 
		reloc_size = 0;
	if (_opened) {
		return SetError(E_STATE_ALLREADY, __LINE__, NULL);
	}

	_hfile = CreateFileW(filename, GENERIC_READ | (write_mode ? GENERIC_WRITE : 0), FILE_SHARE_READ, NULL, 
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_hfile == INVALID_HANDLE_VALUE) {
		return SetError(E_ACCESS_DENIED, GetLastError(), NULL);
	}
	_can_write = write_mode;

	/*_data_size = GetFileSize(_hfile, NULL);
	if (_data_size == INVALID_FILE_SIZE) {
		return SetError(E_ACCESS_DENIED, GetLastError(), NULL);
	}*/
	/*_data_size = PE_HEADER_SIZE;
	_data = (PBYTE)malloc(_data_size);
	if (NULL == _data) {
		return SetError(E_ALLOC_FAIL, __LINE__, NULL);
	}

	DWORD readed;
	SetFilePointer(_hfile, 0, 0, FILE_BEGIN);
	if (!ReadFile(_hfile, _data, _data_size, &readed, NULL)) {
		return SetError(E_ACCESS_DENIED, GetLastError(), NULL);
	}*/
	
	if (!ReadHeaderData(&_data, &_data_size)) {
		return false;
	}

	if (!ParseHeader(_data)) {
		free(_data);
		return false;//error already setted
	}

	//Load relocs table if need
	if (GetArch() == PE_X86) {
		reloc_addr = _popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		reloc_size = _popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	} else if (GetArch() == PE_X64) {
		reloc_addr = _popt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		reloc_size = _popt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	}
	if (reloc_addr) {
		if(!LoadRelocsTable(reloc_addr, reloc_size)) {
			free(_data);
			return false;//error already setted
		}
	} else {
		_reloc_data = NULL;
	}

	_opened = true;
	return SetError(E_OK);
}

VOID CPEFileManager::Close()
{
	if (_opened) {
		if (_data) {
			free(_data);
		}
		CloseHandle(_hfile);
		_opened = false;

		if (_reloc_data) {
			free(_reloc_data);
			_reloc_data = NULL;
			//_reloc_size = 0;
		}
	}
}

BOOL CPEFileManager::IsOpened()
{
	return _opened;
}

BOOL CPEFileManager::ReadHeaderData(LPVOID pbuffer, PUINT psize)
{
	PBYTE buff;
	UINT filesize, size;
	DWORD readed;
	bool allocated;
	
	filesize = GetFileSize(_hfile, NULL);
	if (filesize == INVALID_FILE_SIZE) {
		return SetError(E_ACCESS_DENIED, GetLastError(), NULL);
	}

	//Пытаемся выделить необходимый участок памяти для заголовка, хотя 0x1000 должно хватать c первого раза
	size = PE_HEADER_SIZE;
	buff = (PBYTE)malloc(size);
	if (NULL == buff) {
		return SetError(E_ALLOC_FAIL, __LINE__, NULL);
	}
	allocated = false;
	for (int i = 0; i < 2; i++) {
		if (!ReadFile(_hfile, buff, size, &readed, NULL)) {
			free(buff);
			return SetError(E_ACCESS_DENIED, GetLastError(), NULL);
		}

		if (_CalcHeaderSize(buff, size) > 0) {
			allocated = true;
			break;
		}
		size += PE_HEADER_SIZE;
		buff = (PBYTE)realloc(buff, size);
		if (NULL != buff) {
			free(buff);
			return SetError(E_ALLOC_FAIL, __LINE__, NULL);
		}
	}
	if (!allocated) {
		free(buff);
		return SetError(E_ALLOC_FAIL, __LINE__, NULL);
	}

	*(PBYTE *)pbuffer = buff;
	*psize = size;
	return true;
}

BOOL CPEFileManager::ReadVirtualData(DWORD voffset, PVOID buffer, UINT size, DWORD imgbase, BOOL use_relocs)
{//TODO support check raw out of range to virtual space
	DWORD roffset, sect;
	
	if (!FindRawOffset(voffset, &roffset, &sect)) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}
	if (!CheckInSectionOffset(voffset + size, sect) == INSEC_RAW) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}

	if (!ReadRawData(roffset, buffer, size)) {
		return false;//error already setted
	}

	if (use_relocs && !CommitRelocs(voffset, buffer, size, imgbase)) {
		return false;
	}
	return  true;
}

BOOL CPEFileManager::WriteVirtualData(DWORD voffset, PVOID buffer, UINT size)
{
	if (!_can_write) {
		return SetError(E_ACCESS_DENIED, __LINE__, NULL);
	}
//TODO
	return SetError(E_OK);
}

BOOL CPEFileManager::ReadRawData(DWORD roffset, PVOID buffer, UINT size)
{
	DWORD readed;

	SetFilePointer(_hfile, roffset, NULL, FILE_BEGIN);
	if (!ReadFile(_hfile, buffer, size, &readed, NULL)) {
		return SetError(E_ACCESS_DENIED, GetLastError(), NULL);
	}

	return SetError(E_OK);
}

BOOL CPEFileManager::WriteRawData(DWORD roffset, PVOID buffer, UINT size)
{
	DWORD writed;
	OVERLAPPED ovrl;
	if (!_can_write) {
		return SetError(E_ACCESS_DENIED, __LINE__, NULL);
	}

	ovrl.hEvent = NULL;
	ovrl.Internal = 0;
	ovrl.InternalHigh = 0;
	ovrl.Offset = roffset;
	ovrl.OffsetHigh = 0;

	if (!WriteFile(_hfile, buffer, size, &writed, &ovrl)) {
		return SetError(E_ACCESS_DENIED, GetLastError());
	}

	return SetError(E_OK);
}

BOOL CPEFileManager::FindRawOffset(DWORD voffset, PVOID roffset, PVOID sector)
{
	for (int i = 0; i < _sect_count; i++) {
		if (_psects[i].SizeOfRawData > 0 && _psects[i].VirtualAddress <= voffset 
			&& _psects[i].VirtualAddress + _psects[i].Misc.VirtualSize > voffset) {
			if (roffset) {
				*(PDWORD)roffset = _psects[i].PointerToRawData + (voffset - _psects[i].VirtualAddress);
			}
			if (sector) {
				*(PUINT)sector = i;
			}
			return true; 
		}
	}
	return false;
}

BOOL CPEFileManager::AddSection(LPSTR sect_name, INT pos, PVOID buffer, UINT size, DWORD virt_size)
{
	DWORD voffset = 0, roffset = 0, offset;
	IMAGE_SECTION_HEADER sect = {0};
	UINT len = strlen(sect_name);
	if (len > IMAGE_SIZEOF_SHORT_NAME) {
		len = IMAGE_SIZEOF_SHORT_NAME;
	}

	if (virt_size == 0) {
		virt_size = Aligment(size);
	}

	for (int i = 0; i < _sect_count; i++) {
		if (!memcmp(sect_name, _psects[i].Name, len)) {
			return SetError(E_STATE_ALLREADY, 0);
		}

		//find inject offsets
		offset = Aligment(_psects[i].VirtualAddress + _psects[i].Misc.VirtualSize);
		if (voffset <= offset) {
			voffset = offset;
		}
		offset = Aligment(_psects[i].PointerToRawData + _psects[i].SizeOfRawData, PE_DEFAULT_FILE_ALIGMENT);
		if (roffset <= offset) {
			roffset = offset;
		}
	}
	//roffset = GetEOFOffset();

	if (_data_size <= ((UINT)_psects - (UINT)_data + (sizeof(IMAGE_SECTION_HEADER) * _pimg->NumberOfSections))) {//TOTEST
		_data_size = _data_size + sizeof(IMAGE_SECTION_HEADER);
		_data = (PBYTE)realloc(_data, _data_size);
		if (NULL == _data || !ParseHeader(_data)) {
			Close();
			return SetError(E_UNKNOWN, __LINE__);
		}
	}
	
	//Вносим запись в заголовок
	if (pos >= _sect_count || (int)pos < 0) {//add to end
		pos = _sect_count;
	} else {
		memmove(&_psects[pos] + sizeof(IMAGE_SECTION_HEADER), &_psects[pos], sizeof(IMAGE_SECTION_HEADER));
	}
	sect.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	sect.PointerToRawData = roffset;
	sect.SizeOfRawData = size;
	sect.VirtualAddress = voffset;
	sect.Misc.VirtualSize = virt_size;
	sect.PointerToRelocations = 0;
	sect.NumberOfRelocations = 0;
	sect.PointerToLinenumbers = 0;
	sect.PointerToLinenumbers = 0;
	memcpy(sect.Name, sect_name, len + 1);
	memcpy(&_psects[pos], &sect, sizeof(IMAGE_SECTION_HEADER));
	_sect_count++;
	_pimg->NumberOfSections = _sect_count;

	//ZeroMemory(buffer, size);
	if (GetArch() == PE_X86) {
		_popt32->SizeOfImage += size;
	} else {
		_popt64->SizeOfImage += size;
	}

	//Записываем секцию в файл
	if (_can_write && !WriteRawData(0, _data, _data_size)) {
		return SetError(E_UNKNOWN, __LINE__);
	}
	if (_can_write && !WriteRawData(roffset, buffer, size)) {
		return SetError(E_UNKNOWN, __LINE__);
	}

	return SetError(E_OK);
}

BOOL CPEFileManager::RemoveSection(LPSTR sect_name)
{
	//TODO
	return 0;
}

UINT CPEFileManager::GetEOFOffset()
{
	DWORD size = 0;
	size = GetFileSize(_hfile, NULL);
	if (size == INVALID_FILE_SIZE) {
		return 0;
	}
	return size;
}

// ======================= CPEFileManager :: PRIVATE =======================

BOOL CPEFileManager::LoadRelocsTable(DWORD offset, DWORD size)
{
	PBYTE buffer;

	if (size == 0) {
		return SetError(E_NOT_FOUND, __LINE__);
	}

	buffer = (LPBYTE)malloc(size);
	if (!ReadVirtualData(offset, buffer, size, NULL, false)) {
		free(buffer); return false;//error already setted
	}
	/*if (!ReadVirtualData(offset, buffer, size, NULL, false)) {
		free(buffer); return false;//error already setted
	}
	i = 0;
	while (i < size) {
		prel = (PIMAGE_BASE_RELOCATION)(buffer + i);
		i += prel->SizeOfBlock;
		prel->SizeOfBlock = (prel->SizeOfBlock - (sizeof(DWORD) * 2)) / sizeof(DWORD);
		printf("0x%04X 0x%04X\n", prel->VirtualAddress, prel->SizeOfBlock);
	}*/
	_reloc_data = buffer;
	_reloc_size = size;
	return true;
}

BOOL CPEFileManager::CommitRelocs(DWORD voffset, PVOID buffer, UINT size, DWORD imgbase)
{
	DWORD img = 0, diff = 0;
	WORD rtype = 0, rofst = 0;
	unsigned int i = 0, count = 0;
	PIMAGE_BASE_RELOCATION prel;

	if (!_reloc_data) {//relocs not loaded
		return true;
	}

	if (GetArch() == PE_X86) {
		img = _popt32->ImageBase;
	} else if (GetArch() == PE_X64) {
		img = _popt64->ImageBase;
	}
	if (img == imgbase) {//relocs not need
		return true;
	}

	i = 0;
	while (i < _reloc_size) {
		prel = (PIMAGE_BASE_RELOCATION)((PBYTE)_reloc_data + i);
		i += prel->SizeOfBlock;

		if (prel->VirtualAddress > voffset + size || prel->VirtualAddress + 0x0FFF <= voffset) {
			//вне диапозона
			continue;
		}

		count = (prel->SizeOfBlock - (sizeof(DWORD) * 2)) / sizeof(WORD);
		//printf("0x%08X 0x%08X 0x%08X %d\n", imgbase, prel->VirtualAddress, prel->SizeOfBlock, count);

		diff = (DWORD)voffset - prel->VirtualAddress;

		for (int a = 0; a < count; a++) {
			rofst = *(WORD *)((DWORD)prel + (sizeof(DWORD) * 2) + (sizeof(WORD) * a));
			rtype = rofst >> 12;//4 bits of Type
			rofst = ((DWORD)((DWORD)rofst << 20) >> 20);//12 bits of Offset

			//
			if (!(prel->VirtualAddress + rofst >= voffset
				&& prel->VirtualAddress + rofst < voffset + size)) {
				continue;
			}

			//Support only based relocs
			switch (rtype) {
			case IMAGE_REL_BASED_HIGHLOW://3
				*(DWORD *)((DWORD)buffer - diff + rofst) = *(DWORD *)((DWORD)buffer - diff + rofst) - (img - imgbase);
				break;
			case IMAGE_REL_BASED_ABSOLUTE://0
				break;
			case IMAGE_REL_BASED_HIGH://1
			case IMAGE_REL_BASED_LOW://2
			case IMAGE_REL_BASED_HIGHADJ://4
			case IMAGE_REL_BASED_MIPS_JMPADDR://5
			case IMAGE_REL_BASED_MIPS_JMPADDR16://9 IMAGE_REL_BASED_IA64_IMM64 too
			case IMAGE_REL_BASED_DIR64://10
			default:
				return false;//not supported
			}
		}
	}

	return true;
}
