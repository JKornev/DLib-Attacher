#ifndef __H_PEMANAGER
#define __H_PEMANAGER

#include <Windows.h>
#include "ErrorHandler.h"

// Bit-mask type
typedef unsigned int Mask_Type;
// Bit-mask macro
#define _MASK_SIZE sizeof(Mask_Type)
#define _BIT(x) (1 << (x))
#define _GET_BIT(src, pos) (((src)<<(_MASK_SIZE - 1 - (pos))) >> _MASK_SIZE - 1)//non-safe position
#define _GET_SRC_BIT(src, pos) ((((src)<<(_MASK_SIZE - 1 - (pos))) >> _MASK_SIZE - 1) << pos)//safe position

#define PE_DEFAULT_VIRTUAL_ALIGMENT 0x1000
#define PE_DEFAULT_FILE_ALIGMENT 0x200
#define PE_HEADER_SIZE PE_DEFAULT_VIRTUAL_ALIGMENT

#define PE_HEADER_STRUCT32_SIZE sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) + (sizeof(IMAGE_SECTION_HEADER) * 5)
#define PE_HEADER_STRUCT64_SIZE sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64) + (sizeof(IMAGE_SECTION_HEADER) * 5)

enum PE_Architecture {
	PE_UNK,
	PE_X86,
	PE_X64
};

//#define _ARCH(pPEInfo, object, arg_list) ((pPEInfo)->GetArch() == PE_X64 ? object##64##arg_list : object##32##arg_list)
enum PE_InSection {
	INSEC_OUT = -1,
	INSEC_RAW,
	INSEC_VIRT
};

class CPEInfo : public CErrorCtrl {
protected:
	//PE structures
	PIMAGE_DOS_HEADER			_pdos;
	PIMAGE_FILE_HEADER			_pimg;
	PIMAGE_OPTIONAL_HEADER32	_popt32;
	PIMAGE_OPTIONAL_HEADER64	_popt64;
	//
	PIMAGE_SECTION_HEADER	_psects;
	UINT _sect_count;

	BOOL _loaded_flag;
	UINT _range;

	//Расчитываем виртуальный размер загруженного образа
	UINT _CalcVirtualRange();
	//Расчитываем если возможно размер заголовка в буффере
	INT _CalcHeaderSize(PVOID buffer, UINT size);
public:
	CPEInfo();
	~CPEInfo();

	BOOL ParseHeader(PVOID buffer);
	BOOL HeaderIsLoaded();
	PE_Architecture GetArch();
	PIMAGE_DOS_HEADER GetHDos();
	PIMAGE_FILE_HEADER GetHImg();
	PIMAGE_OPTIONAL_HEADER32 GetHOpt32();
	PIMAGE_OPTIONAL_HEADER64 GetHOpt64();
	PIMAGE_SECTION_HEADER GetSectsPtr(PUINT count);
	PIMAGE_SECTION_HEADER GetSectorPtr(LPSTR name);

	UINT GetVirtualRange();

	INT CheckInSectionOffset(DWORD voffset, UINT sector);

	static UINT Aligment(UINT size, UINT aligm_base = PE_DEFAULT_VIRTUAL_ALIGMENT);
};


class CPEFileManager : public CPEInfo {
private:
	BOOL _opened;
	BOOL _can_write;

	HANDLE _hfile;

	UINT _data_size;
	PBYTE _data;

	UINT _reloc_size;
	PBYTE _reloc_data;

	BOOL LoadRelocsTable(DWORD offset, DWORD size);
	BOOL CommitRelocs(DWORD voffset, PVOID buffer, UINT size, DWORD imgbase);
public:
	CPEFileManager();
	~CPEFileManager();

	BOOL Open(LPWSTR filename, BOOL write_mode);
	VOID Close();
	BOOL IsOpened();

	BOOL ReadHeaderData(LPVOID pbuffer, PUINT psize);

	BOOL ReadVirtualData(DWORD voffset, PVOID buffer, UINT size, DWORD imgbase, BOOL use_relocs = true);
	BOOL WriteVirtualData(DWORD voffset, PVOID buffer, UINT size);//TODO

	BOOL ReadRawData(DWORD roffset, PVOID buffer, UINT size);
	BOOL WriteRawData(DWORD roffset, PVOID buffer, UINT size);//TODO

	BOOL FindRawOffset(DWORD voffset, PVOID roffset = NULL, PVOID sector = NULL);

	BOOL AddSection(LPSTR sect_name, INT pos, PVOID buffer, UINT size, DWORD virt_size = 0);
	BOOL RemoveSection(LPSTR sect_name);

	UINT GetEOFOffset();
};


#endif