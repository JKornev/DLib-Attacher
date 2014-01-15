#ifndef __H_DLIB_ATTACH
#define __H_DLIB_ATTACH

#include "DLibShell.h"
#include "PEManager.h"

#define DLIB_SECTION_MIN_SIZE 0x5000
#define DLIB_SECTION ".dlib"

class CDLibShellAttach : protected CPEFileManager {
private:
	bool _shell_open;
	bool _is_att;
	CDLibShellMain *_pshell;

	UINT _tls_size;
	PBYTE _tls_data;

	UINT _rel_size;
	PBYTE _rel_data;

	static bool GetResourcePtr(PVOID pbuffer, PUINT psize, int size);
	bool ReadTLSCallbackTable(DWORD voffset, PDWORD &ptbl, UINT *pcount);
	/*bool RereadTLSCallbackTable(DWORD voffset, PDWORD &ptbl, UINT *pcount)*/;
	PVOID ReadRelocsBlocks(DWORD voffset, UINT rel_size, UINT max_size, UINT *psize);

public:
	CDLibShellAttach();
	~CDLibShellAttach();

	bool OpenPE(LPVOID wpath);
/*	bool SavePE(LPVOID wpath);*/
	void ClosePE();

	bool AttachShell();
	bool DetachShell();

//Shell code editor
	void SetFlag(Shell_Flags flag, bool state);
	bool GetFlag(Shell_Flags flag);

	void AddDll(LPVOID dllname, LPVOID dllproc, bool check_retn);
	void RemoveDLL(LPVOID dllname);
	void RemoveAllDll();
	bool GetDllList(PShell_DllFrame &plist, int max_count, int *readed);
	
	void SetErrorMessage(Shell_Error_Msg type, PVOID message);
	LPSTR GetErrorMessage(Shell_Error_Msg type);

	//advance mode
	bool EnableAdvance(PVOID dll_name, PVOID dll_proc);

	void AddIgnoreOffset(DWORD offset, UINT size);
	void RemoveIgnoreOffset(DWORD offset);
	bool GetIgnoreList(PShell_IgnoreFrame &plist, int max_count, int *readed);
	UINT GetIgnoreListCount();

	PIMAGE_SECTION_HEADER GetSectorList(PUINT pcount);
	DWORD GetImgbase();

	DWORD GetProtMask();
	void SetProtMask(DWORD mask);
	void SearchProtectSects();

	PVOID GetShellResPtr(UINT id, PUINT psize);

	
//Info
	bool IsShellOpen();
	bool IsAttached();
};

#endif