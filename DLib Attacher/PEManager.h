#ifndef __H_PEMANAGER
#define __H_PEMANAGER

#include <Windows.h>
#include "ErrorHandler.h"


#define PE_DEFAULT_VIRTUAL_ALIGMENT 0x1000
#define PE_DEFAULT_FILE_ALIGMENT 0x200
#define PE_HEADER_SIZE PE_DEFAULT_VIRTUAL_ALIGMENT
#define PE_HEADER_RAW_SIZE 0x400

#define PE_HEADER_STRUCT32_SIZE sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) + (sizeof(IMAGE_SECTION_HEADER) * 5)
#define PE_HEADER_STRUCT64_SIZE sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64) + (sizeof(IMAGE_SECTION_HEADER) * 5)


enum PE_Architecture {
	PE_UNK,
	PE_X86,
	PE_X64
};

enum PE_Type {
	PE_EXE,
	PE_DLL,
	PE_SYS,
	PE_OCX,
	PE_NOEXEC
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
	CPEInfo *Instance();

	BOOL ParseHeader(PVOID buffer);
	BOOL HeaderIsLoaded();
	PE_Architecture GetArch();
	PE_Type GetType();
	PIMAGE_DOS_HEADER GetHDos();
	PIMAGE_FILE_HEADER GetHImg();
	PIMAGE_OPTIONAL_HEADER32 GetHOpt32();
	PIMAGE_OPTIONAL_HEADER64 GetHOpt64();
	PIMAGE_SECTION_HEADER GetSectsPtr(PUINT count);
	PIMAGE_SECTION_HEADER GetSectorPtr(LPSTR name);

	UINT GetVirtualRange();

	//Получаем порядковый номер секции по имени
	UINT GetSectorNum(LPSTR name);
	//Получаем порядковый номер секции по оффсету
	UINT GetSectorNum(DWORD voffset);
	//
	INT CheckInSectionOffset(DWORD voffset, UINT sector);
	//Считаем по виртуальному адресу кол-во памяти свободной для чтения из файла
	UINT CalcInSectionFreeSpace(DWORD voffset, PUINT psector);
	//Выравнивание размера секции
	static UINT Aligment(UINT size, UINT aligm_base = PE_DEFAULT_VIRTUAL_ALIGMENT);
};


class CPEManagerInterface {
public:
	virtual BOOL Open(LPVOID handle, BOOL write_mode) = 0;
	virtual VOID Close() = 0;
	virtual BOOL IsOpened() = 0;

	virtual BOOL ReadHeaderData(LPVOID pbuffer, PUINT psize) = 0;
	virtual BOOL WriteHeader() = 0;

	virtual BOOL ReadVirtualData(DWORD voffset, PVOID buffer, UINT size, DWORD imgbase, BOOL use_relocs = true) = 0;
	virtual BOOL WriteVirtualData(DWORD voffset, PVOID buffer, UINT size) = 0;

	virtual CPEInfo *GetInfoObj() = 0;

	virtual DWORD GetImagebase() = 0;

	//new
	virtual BOOL AddSection(LPSTR sect_name, INT pos, PVOID buffer, UINT size, DWORD virt_size = 0) = 0;
	virtual BOOL EditSection(UINT sect_num, PVOID buffer, UINT size, DWORD virt_size = 0) = 0;
	virtual BOOL RemoveSection(UINT sect_num) = 0;
};


class CPEFileManager : public CPEManagerInterface, public CPEInfo {
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

	BOOL Open(LPVOID filename, BOOL write_mode);
	VOID Close();
	BOOL IsOpened();

	BOOL ReadHeaderData(LPVOID pbuffer, PUINT psize);
	BOOL WriteHeader();

	BOOL ReadVirtualData(DWORD voffset, PVOID buffer, UINT size, DWORD imgbase, BOOL use_relocs = true);
	BOOL WriteVirtualData(DWORD voffset, PVOID buffer, UINT size);//TODO

	BOOL ReadRawData(DWORD roffset, PVOID buffer, UINT size);
	BOOL WriteRawData(DWORD roffset, PVOID buffer, UINT size);

	BOOL FindRawOffset(DWORD voffset, PVOID roffset = NULL, PVOID sector = NULL, PVOID poverflow = NULL);
	
	DWORD GetImagebase();

	CPEInfo *GetInfoObj();
		
	/* TODO
		- переделать сдвиг файло\виртуальных данных при удалении
		+ переделать удаление секций, определять секцию не по имени а по порядковому номеру */
	BOOL AddSection(LPSTR sect_name, INT pos, PVOID buffer, UINT size, DWORD virt_size = 0);
	BOOL EditSection(UINT sect_num, PVOID buffer, UINT size, DWORD virt_size = 0);
	BOOL RemoveSection(UINT sect_num);
	BOOL ChangeSectionRawSize(UINT sect_num, UINT rawsize);

	UINT GetEOFOffset();
	UINT GetPeakRawFileSize();
};


class CPEVirtualManager : public CPEManagerInterface, public CPEInfo {
private:
	BOOL _opened;
	BOOL _can_write;

	HANDLE _hproc;
	DWORD _pid;
	DWORD _baseaddr;

	UINT _data_size;
	PBYTE _data;

	BOOL LoadProcessInfo();
public:
	CPEVirtualManager();
	~CPEVirtualManager();

	BOOL Open(LPVOID handle, BOOL write_mode);
	VOID Close();
	BOOL IsOpened();

	BOOL ReadHeaderData(LPVOID pbuffer, PUINT psize);
	BOOL WriteHeader();

	BOOL ReadVirtualData(DWORD voffset, PVOID buffer, UINT size, DWORD imgbase, BOOL use_relocs = true);
	BOOL WriteVirtualData(DWORD voffset, PVOID buffer, UINT size);

	CPEInfo *GetInfoObj();

	DWORD GetImagebase();

	BOOL AddSection(LPSTR sect_name, INT pos, PVOID buffer, UINT size, DWORD virt_size = 0);
	BOOL EditSection(UINT sect_num, PVOID buffer, UINT size, DWORD virt_size = 0);
	BOOL RemoveSection(UINT sect_num);
};


#endif