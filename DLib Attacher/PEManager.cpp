#include "stdafx.h"
#include "PEManager.h"
#include <stdlib.h>
#include <TlHelp32.h>
#include <Psapi.h>

#if (PSAPI_VERSION == 1)
#pragma comment(lib, "psapi.lib")
#else
#pragma comment(lib, "kernel32.lib")
#endif

// ======================= CPEInfo :: PUBLIC =======================

CPEInfo::CPEInfo() : _loaded_flag(false)
{
	return;
}

CPEInfo::~CPEInfo()
{
	return;
}

CPEInfo *CPEInfo::Instance()
{
	return this;
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

PE_Type CPEInfo::GetType()
{//Warning! Maybe low level heuristic
	PE_Type type;
	if (_pimg->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		type = PE_EXE;
	} else {
		return PE_NOEXEC;
	}
	if (_pimg->Characteristics & IMAGE_FILE_DLL) {
		type = (_pimg->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE ? PE_OCX : PE_DLL);
	} else if (_pimg->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) {
		type = PE_SYS;
	}
	return type;
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
	int res = GetSectorNum(name);
	if (res == -1) {
		return NULL;
	}
	return &_psects[res];
}

UINT CPEInfo::GetSectorNum(LPSTR name)
{
	char buffer[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
	for (int i = 0; i < _sect_count; i++) {
		memcpy(buffer, _psects[i].Name, IMAGE_SIZEOF_SHORT_NAME);
		if (!strcmp(buffer, name)) {
			return i;
		}
	}
	return -1;
}

UINT CPEInfo::GetSectorNum(DWORD voffset)
{//Warning! Sector num != sector_inx, num == sector_inx - 1
	UINT num = -1;
	if (voffset < PE_DEFAULT_VIRTUAL_ALIGMENT) {
		return 0;//header
	}
	for (int i = 0; i < _sect_count; i++) {
		if (_psects[i].VirtualAddress <= voffset 
		&& _psects[i].VirtualAddress + _psects[i].Misc.VirtualSize > voffset) {
			if (_psects[i].SizeOfRawData == 0) {
				num = i;
				continue;
			}
			return i + 1;
		}
	}
	return num + 1;
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

UINT CPEInfo::CalcInSectionFreeSpace(DWORD voffset, PUINT psector)
{
	unsigned int free_space = 0;
	for (int i = 0; i < _sect_count; i++) {
		if (_psects[i].VirtualAddress <= voffset 
			&& (_psects[i].VirtualAddress + _psects[i].SizeOfRawData) > voffset) {
			if (psector) {
				*psector = i;
			}

			return (_psects[i].VirtualAddress + _psects[i].SizeOfRawData) - voffset;
		}
	}
	return free_space;
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
	if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}
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

CPEFileManager::CPEFileManager() : CPEInfo(), _opened(false), _can_write(false), _data_size(0), _data(NULL), 
	_reloc_data(NULL), _reloc_size(0)
{
}

CPEFileManager::~CPEFileManager()
{
	Close();
}

BOOL CPEFileManager::Open(LPVOID filename, BOOL write_mode)
{
	DWORD reloc_addr = 0, 
		reloc_size = 0;
	if (_opened) {
		return SetError(E_STATE_ALLREADY, __LINE__, NULL);
	}

	_hfile = CreateFileW((LPWSTR)filename, GENERIC_READ | (write_mode ? GENERIC_WRITE : 0), FILE_SHARE_READ, NULL, 
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_hfile == INVALID_HANDLE_VALUE) {
		return SetError(E_ACCESS_DENIED, GetLastError(), NULL);
	}
	_can_write = write_mode;
	
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
			_data = NULL;
		}
		CloseHandle(_hfile);
		_opened = false;

		if (_reloc_data) {
			free(_reloc_data);
			_reloc_data = NULL;
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
	size = PE_HEADER_RAW_SIZE;
	buff = (PBYTE)malloc(size);
	if (NULL == buff) {
		return SetError(E_ALLOC_FAIL, __LINE__, NULL);
	}
	allocated = false;
	for (int i = 0; i < 2; i++) {
		SetFilePointer(_hfile, NULL, NULL, FILE_BEGIN);
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
		if (NULL != buff) {//?!
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
	DWORD roffset, sect, overfl;

	if (!_can_write) {
		return SetError(E_ACCESS_DENIED, __LINE__, NULL);
	}

	if (!FindRawOffset(voffset, &roffset, &sect, &overfl)) {
		return SetError(E_OUT_OF_RANGE, __LINE__, NULL);
	}
	if (overfl > 0 && !ChangeSectionRawSize(sect, _psects[sect].SizeOfRawData + overfl)) {//Расширяем секцию
		return SetError(E_INHERIT, __LINE__);
	}
	if (!WriteRawData(roffset, buffer, size)) {
		return SetError(E_INHERIT, __LINE__);
	}

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
	if (!_can_write) {
		return SetError(E_ACCESS_DENIED, __LINE__, NULL);
	}

	SetFilePointer(_hfile, roffset, NULL, FILE_BEGIN);
	if (!WriteFile(_hfile, buffer, size, &writed, NULL)) {
		return SetError(E_ACCESS_DENIED, GetLastError());
	}

	return SetError(E_OK);
}

BOOL CPEFileManager::WriteHeader()
{
	UINT size = _pdos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) 
		+ (GetArch() == PE_X86 ? sizeof(IMAGE_OPTIONAL_HEADER32) : sizeof(IMAGE_OPTIONAL_HEADER64))
		+ (_sect_count * sizeof(IMAGE_SECTION_HEADER));
	if (_can_write && !WriteRawData(0, _data, size)) {
		return SetError(E_UNKNOWN, __LINE__);
	}
	return SetError(E_OK);
}

BOOL CPEFileManager::FindRawOffset(DWORD voffset, PVOID roffset, PVOID sector, PVOID poverflow)
{
	if (poverflow) {
		*(PUINT)poverflow = 0;
	}
	for (int i = 0; i < _sect_count; i++) {
		if (_psects[i].SizeOfRawData > 0 && _psects[i].VirtualAddress <= voffset 
		&& Aligment(_psects[i].VirtualAddress + _psects[i].Misc.VirtualSize) > voffset) {
			if (poverflow && _psects[i].VirtualAddress + _psects[i].SizeOfRawData <= voffset) {
				*(PUINT)poverflow = voffset + 1 - (_psects[i].VirtualAddress + _psects[i].SizeOfRawData);
			}
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
		/* Maybe not need
		if (!memcmp(sect_name, _psects[i].Name, len)) {
			return SetError(E_STATE_ALLREADY, 0);
		}*/

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
	/*if (_can_write && !WriteRawData(0, _data, _data_size)) {
		return SetError(E_UNKNOWN, __LINE__);
	}*/
	if (!WriteHeader()) {
		return SetError(E_INHERIT, __LINE__);
	}
	if (_can_write && size > 0 && !WriteRawData(roffset, buffer, size)) {
		return SetError(E_UNKNOWN, __LINE__);
	}

	return SetError(E_OK);
}

BOOL CPEFileManager::EditSection(UINT sect_num, PVOID buffer, UINT size, DWORD virt_size)
{
	PIMAGE_SECTION_HEADER psect = &_psects[sect_num];
	DWORD raw_offset, vcurr_ofst_end, vnew_ofst_end, imgsize, tmpsize;
	int raw_diff, buff_size, file_size;
	PBYTE pbuffer;

	if (sect_num >= _sect_count) {
		return SetError(E_OVERFLOW, __LINE__);
	}

	if (virt_size == 0 || size > virt_size) {
		virt_size = Aligment(size);
	}

	/*
	+ Если секция не последняя, то нужно убедится что она не выходит за свои границы
	- Если секция не последняя, то сдвигаем данные вышестоящих секций под новый размер секции
	*/
	vcurr_ofst_end = psect->VirtualAddress + psect->Misc.VirtualSize;
	vnew_ofst_end = psect->VirtualAddress + virt_size;
	raw_diff = (int)size - (int)psect->Misc.VirtualSize;

	if (vnew_ofst_end > vcurr_ofst_end) {
		for (int i = 0; i < _sect_count; i++) {
			if (sect_num == i) {
				continue;
			}

			//Проверяем выход за границы виртуальной памяти
			if (vcurr_ofst_end <= _psects[i].VirtualAddress 
				&& vnew_ofst_end > _psects[i].VirtualAddress) {
				return SetError(E_OVERFLOW, __LINE__);
			}
			//Налаживаем смещение 
			if (psect->PointerToRawData && _psects[i].PointerToRawData
				&& psect->PointerToRawData <= _psects[i].PointerToRawData) {
				_psects[i].PointerToRawData = (signed int)_psects[i].PointerToRawData + raw_diff;
			}
		}
	}

	if (!_can_write) {
		return SetError(E_OK);
	}

	//Смещаем файловые данные
	file_size = GetEOFOffset();
	if (sect_num < _sect_count - 1) {
		buff_size = file_size - psect->PointerToRawData - psect->SizeOfRawData;
		pbuffer = (PBYTE)malloc(buff_size);
		if (!pbuffer) {
			return SetError(E_ALLOC_FAIL, __LINE__);
		}
		if (!ReadRawData(psect->PointerToRawData + psect->SizeOfRawData, pbuffer, buff_size)) {
			free(pbuffer);
			return SetError(E_INHERIT, __LINE__);
		}

		SetFilePointer(_hfile, (file_size + raw_diff), 0, FILE_BEGIN);
		if (!WriteRawData(psect->PointerToRawData + psect->SizeOfRawData + raw_diff, pbuffer, buff_size)) {
			free(pbuffer);
			return SetError(E_INHERIT, __LINE__);
		}
		free(pbuffer);
	} else {
		SetFilePointer(_hfile, (file_size + raw_diff), 0, FILE_BEGIN);
	}

	psect->Misc.VirtualSize = virt_size;
	psect->SizeOfRawData = size;

	imgsize = 0;
	for (int i = 0; i < _sect_count; i++) {
		tmpsize = _psects[i].VirtualAddress + Aligment(_psects[i].Misc.VirtualSize);
		if (tmpsize > imgsize) {
			imgsize = tmpsize;
		}
	}
	if (GetArch() == PE_X86) {
		_popt32->SizeOfImage = tmpsize;
	} else {
		_popt64->SizeOfImage = tmpsize;
	}

	//Сохраняем новые данные
	/*if (!WriteRawData(0, _data, _data_size)) {
		return SetError(E_UNKNOWN, __LINE__);
	}*/
	if (!WriteHeader()) {
		return SetError(E_INHERIT, __LINE__);
	}
	if (!WriteRawData(psect->PointerToRawData, buffer, size)) {
		return SetError(E_INHERIT, __LINE__);
	}

	return SetError(E_OK);
}

BOOL CPEFileManager::RemoveSection(UINT sect_num)
{/* Warning! Extremal function, without full tests (Can corrupt PE) */
	char buffer[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
	DWORD raw_offset, raw_size, size = 0, read_size, readed;
	PBYTE pbuffer;

	if (sect_num >= _sect_count) {
		return SetError(E_OVERFLOW, __LINE__);
	}

	raw_offset = _psects[sect_num].PointerToRawData;
	raw_size = _psects[sect_num].SizeOfRawData;

	if (sect_num + 1 < _sect_count) {//need move
		if (sect_num > 0) {
			_psects[sect_num - 1].Misc.VirtualSize += Aligment(_psects[sect_num].Misc.VirtualSize);
		}
		memmove(&_psects[sect_num], &_psects[sect_num + 1], sizeof(IMAGE_SECTION_HEADER) * (_sect_count - sect_num - 1));
	} else { //not need move
		memset(&_psects[sect_num], 0, sizeof(IMAGE_SECTION_HEADER));
	}

	//recalc header
	int img_size = 0;
	for (int i = 0; i < _sect_count; i++) {
		if (i == sect_num) {
			continue;
		}
		if (_psects[i].VirtualAddress + _psects[i].Misc.VirtualSize > img_size) {
			img_size = Aligment(_psects[i].VirtualAddress + _psects[i].Misc.VirtualSize);
		}
	}
	if (GetArch() == PE_X86) {
		_popt32->SizeOfImage = img_size;
	} else {
		_popt64->SizeOfImage = img_size;
	}
	_pimg->NumberOfSections -= 1;
	_sect_count = _pimg->NumberOfSections;

	//recalc raw offset
	for (int i = sect_num; i < _pimg->NumberOfSections; i++) {
		_psects[i].PointerToRawData -= raw_size;
	}

	if (!_can_write) {
		return SetError(E_OK);
	}

	//save to file
	/*if (!WriteRawData(0, _data, _data_size)) {
		return SetError(E_UNKNOWN, __LINE__);
	}*/
	if (!WriteHeader()) {
		return SetError(E_INHERIT, __LINE__);
	}

	size = GetFileSize(_hfile, NULL);
	if (raw_offset >= size) {
		return SetError(E_UNKNOWN, __LINE__);
	}

	if (raw_offset + raw_size >= size) {
		SetFilePointer(_hfile, raw_offset, NULL, FILE_BEGIN);
		SetEndOfFile(_hfile);
	} else {//not tested
		read_size = size - (raw_offset + raw_size);
		pbuffer = (PBYTE)malloc(read_size);
		if (!pbuffer) {
			return SetError(E_ALLOC_FAIL, __LINE__);
		}

		SetFilePointer(_hfile, raw_offset + raw_size, NULL, FILE_BEGIN);
		if (!ReadFile(_hfile, pbuffer, read_size, &readed, NULL)) {
			return SetError(E_ACCESS_DENIED, __LINE__ );
		}

		SetFilePointer(_hfile, raw_offset, NULL, FILE_BEGIN);
		if (!WriteFile(_hfile, pbuffer, read_size, &readed, NULL)) {
			return SetError(E_ACCESS_DENIED, __LINE__ );
		}

		SetFilePointer(_hfile, raw_offset + read_size, NULL, FILE_BEGIN);
		SetEndOfFile(_hfile);
	}

	return SetError(E_OK);
}

BOOL CPEFileManager::ChangeSectionRawSize(UINT sect_num, UINT rawsize)
{//TOTEST
	PIMAGE_SECTION_HEADER psect, psects;
	DWORD filesize, filedatasize, new_size, roffset, rwsize;
	UINT count, rsize;
	int diff;
	PBYTE pbuffer;

	if (sect_num >= _sect_count) {
		return SetError(E_OVERFLOW, __LINE__);
	} else if (!_can_write) {
		return SetError(E_ACCESS_DENIED, __LINE__);
	}

	psects = GetSectsPtr(&count);
	psect = &psects[sect_num];

	diff = rawsize - psect->SizeOfRawData;

	if (diff == 0) {
		return SetError(E_OK);
	}
	if ((int)psect->SizeOfRawData + diff < 0) {
		return SetError(E_UNKNOWN, __LINE__);
	}

	filesize = GetEOFOffset();
	filedatasize = GetPeakRawFileSize();
	roffset = psect->PointerToRawData + psect->SizeOfRawData;
	rsize = filesize - roffset;
	pbuffer = (PBYTE)malloc(rsize);
	if (!pbuffer) {
		return SetError(E_ALLOC_FAIL, __LINE__);
	}
	SetFilePointer(_hfile, roffset, NULL, FILE_BEGIN);
	if (!ReadFile(_hfile, pbuffer, rsize, &rwsize, NULL)) {
		return SetError(E_ACCESS_DENIED, __LINE__ );
	}

	if (diff > 0) {//увеличение
		//Расширяем файл
		new_size = filesize;
		if (filedatasize + diff > filesize) {
			new_size = Aligment(filedatasize + diff, PE_DEFAULT_FILE_ALIGMENT);
		}
		SetFilePointer(_hfile, new_size, NULL, FILE_BEGIN);
		SetEndOfFile(_hfile);
		//Передвигаем данные
		SetFilePointer(_hfile, roffset + diff, NULL, FILE_BEGIN);
		if (!WriteFile(_hfile, pbuffer, rsize, &rwsize, NULL)) {
			return SetError(E_ACCESS_DENIED, __LINE__ );
		}
	} else {//уменьшение
		new_size = Aligment((int)filedatasize + diff);
		//Передвигаем данные
		SetFilePointer(_hfile, (LONG)((int)roffset + diff), NULL, FILE_BEGIN);
		if (!WriteFile(_hfile, pbuffer, rsize, &rwsize, NULL)) {
			return SetError(E_ACCESS_DENIED, __LINE__ );
		}
		//Урезаем файл
		SetFilePointer(_hfile, new_size, NULL, FILE_BEGIN);
		SetEndOfFile(_hfile);
	}

	//Смещаем секции
	for (int i = 0; i < count; i++) {
		if (i == sect_num || !psects[i].SizeOfRawData) {
			continue;
		}

		if (psects[i].PointerToRawData >= roffset) {
			psects[i].PointerToRawData = (int)psects[i].PointerToRawData + diff;
		}
	}
	if (!WriteHeader()) {
		return SetError(E_INHERIT, __LINE__);
	}

	return SetError(E_OK);
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

UINT CPEFileManager::GetPeakRawFileSize()
{
	UINT size = 0, count;
	PIMAGE_SECTION_HEADER psect = GetSectsPtr(&count);
	for (int i = 0; i < count; i++) {
		if (psect[i].SizeOfRawData && psect[i].PointerToRawData + psect[i].SizeOfRawData > size) {
			size = psect[i].PointerToRawData + psect[i].SizeOfRawData;
		}
	}
	return size;
}

DWORD CPEFileManager::GetImagebase()
{
	PIMAGE_OPTIONAL_HEADER32 popt32;
	PIMAGE_OPTIONAL_HEADER64 popt64;
	if (GetArch() == PE_X86) {
		popt32 = this->GetHOpt32();
		return popt32->ImageBase;
	} else if (GetArch() == PE_X64) {
		popt64 = this->GetHOpt64();
		return popt64->ImageBase;//Warning ULONGLONG
	}
	return 0;
}

CPEInfo *CPEFileManager::GetInfoObj()
{
	return this->Instance();
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

		if (!prel->VirtualAddress && !prel->SizeOfBlock) {
			break;
		}

		if (prel->VirtualAddress > voffset + size || prel->VirtualAddress + 0x0FFF <= voffset) {
			//вне диапозона
			continue;
		}

		count = (prel->SizeOfBlock - (sizeof(DWORD) * 2)) / sizeof(WORD);
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

// ======================= CPEVirtualManager :: PUBLIC =======================

CPEVirtualManager::CPEVirtualManager() : _opened(false), _can_write(false), _data(NULL)
{
}

CPEVirtualManager::~CPEVirtualManager()
{
	Close();
}

BOOL CPEVirtualManager::Open(LPVOID handle, BOOL write_mode)
{
	if (_opened) {
		return SetError(E_STATE_ALLREADY, __LINE__, NULL);
	}

	_pid = (DWORD)handle;
	
	_hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | (write_mode ? PROCESS_VM_WRITE : 0), false, _pid);
	if (_hproc == INVALID_HANDLE_VALUE) {
		return SetError(E_ACCESS_DENIED, GetLastError(), NULL);
	}

	if (!LoadProcessInfo()) {
		CloseHandle(_hproc);
		return false;
	}

	_can_write = write_mode;
	if (!ReadHeaderData(&_data, &_data_size)) {
		CloseHandle(_hproc);
		return false;
	}

	if (!ParseHeader(_data)) {
		free(_data);
		return false;
	}

	_opened = true;
	return SetError(E_OK);
}

VOID CPEVirtualManager::Close()
{
	if (_opened) {
		if (_data) {
			free(_data);
			_data = NULL;
		}
		CloseHandle(_hproc);
		_opened = false;
	}
}

BOOL CPEVirtualManager::IsOpened()
{
	return _opened;
}

BOOL CPEVirtualManager::ReadHeaderData(LPVOID pbuffer, PUINT psize)
{
	PBYTE buff;
	UINT filesize, size;
	DWORD readed;
	bool allocated;

	size = PE_HEADER_SIZE;
	buff = (PBYTE)malloc(size);
	if (NULL == buff) {
		return SetError(E_ALLOC_FAIL, __LINE__, NULL);
	}
	allocated = false;
	for (int i = 0; i < 2; i++) {
		if (!ReadProcessMemory(_hproc, (LPCVOID)_baseaddr, buff, size, &readed)) {
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

	return SetError(E_OK);
}

BOOL CPEVirtualManager::ReadVirtualData(DWORD voffset, PVOID buffer, UINT size, DWORD imgbase, BOOL use_relocs)
{
	DWORD readed = 0;
	if (!ReadProcessMemory(_hproc, (LPVOID)(_baseaddr + voffset), buffer, size, &readed)) {
		return SetError(E_ACCESS_DENIED, GetLastError(), NULL);
	}
	return SetError(E_OK);
}

BOOL CPEVirtualManager::WriteVirtualData(DWORD voffset, PVOID buffer, UINT size)
{
	DWORD written = 0;
	if (!WriteProcessMemory(_hproc, (LPVOID)(_baseaddr + voffset), buffer, size, &written)) {
		return SetError(E_ACCESS_DENIED, GetLastError(), NULL);
	}
	return SetError(E_OK);
}

BOOL CPEVirtualManager::WriteHeader()
{//stub
	return SetError(E_UNKNOWN);
}

DWORD CPEVirtualManager::GetImagebase()
{
	return _baseaddr;
}

CPEInfo *CPEVirtualManager::GetInfoObj()
{
	return this->Instance();
}

BOOL CPEVirtualManager::AddSection(LPSTR sect_name, INT pos, PVOID buffer, UINT size, DWORD virt_size)
{//stub
	return SetError(E_UNKNOWN);
}

BOOL CPEVirtualManager::EditSection(UINT sect_num, PVOID buffer, UINT size, DWORD virt_size)
{//stub
	return SetError(E_UNKNOWN);
}

BOOL CPEVirtualManager::RemoveSection(UINT sect_num)
{//stub
	return SetError(E_UNKNOWN);
}

// ======================= CPEVirtualManager :: PRIVATE =======================

BOOL CPEVirtualManager::LoadProcessInfo()
{
	enum {VIRT_PROCNAME_SIZE = 1024};
	HANDLE hsnap;
	MODULEENTRY32W mod32;
	LPWSTR procname;

	_baseaddr = NULL;

	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _pid);
	if (hsnap == INVALID_HANDLE_VALUE) {
		return SetError(E_ACCESS_DENIED, __LINE__);
	}

	if (!Module32FirstW(hsnap, &mod32)) {
		CloseHandle(hsnap);
		return SetError(E_ACCESS_DENIED, GetLastError());
	}

	procname = new wchar_t[VIRT_PROCNAME_SIZE];
	ZeroMemory(procname, VIRT_PROCNAME_SIZE);
	if (GetModuleBaseNameW(_hproc, NULL, procname, VIRT_PROCNAME_SIZE) == 0) {
		delete[] procname;
		return SetError(E_ACCESS_DENIED, GetLastError());
	}

	do {
		if (!wcscmp(procname, mod32.szModule)) {
			_baseaddr = (DWORD)mod32.modBaseAddr;
			break;
		}
	} while (Module32NextW(hsnap, &mod32));
	delete[] procname;

	if (!_baseaddr) {
		CloseHandle(hsnap);
		return SetError(E_NOT_FOUND, __LINE__);
	}

	CloseHandle(hsnap);
	return SetError(E_OK);
}