#ifndef __H_DLIBSHELL
#define __H_DLIBSHELL

#include "ErrorHandler.h"
#include "ResPacker.h"
#include "DLibShellStructs.h"
#include "RelBuilder.h"

#include <list>
//#include <vector>

#define SHELL_VALUE_NONE -1

typedef struct {
//input
	DWORD imagebase;
	DWORD sect_offst;
	BOOL use_rand;
	//orig
	DWORD ori_relocs_addr;
	UINT ori_relocs_size;
	DWORD ori_tls_dir_addr;
	DWORD ori_tls_clbk_addr;
	UINT ori_tls_size;
	DWORD ori_entrypoint;
	DWORD ori_sec_id;
	DWORD ori_sec_raw_size;
//output
	PVOID buffer;
	UINT size;
	DWORD tls_table;
	UINT tls_size;
	DWORD tls_header;
	DWORD reloc_table;
	UINT reloc_size;
	DWORD entry_offst;
} Shell_Build_Result, *PShell_Build_Result;

class CDLibShellMain : public CErrorCtrl {
private:
	bool _opened;
	CResPacker _res;

	PBYTE _shell;
	UINT _shell_size;
/*	DWORD _shell_ep;
	DWORD _shell_tls;
	DWORD _shell_dllep;*/
	Shell_Opcode_Export _shell_addr;
	PBYTE _tramplin;

	CRelBuilder _relocs;

	DWORD _opc_imgbase;
	DWORD _opc_relbase;
	PBYTE _opcode;
	UINT _opc_size;
	PBYTE _opc_rel;
	UINT _opc_rel_size;

	DWORD _tls_offset;

	std::list<Shell_DllFrame> _dlls;
	std::list<Shell_IgnoreFrame> _ignores;
	std::list<Shell_IgnoreFrame> _prots;

	UINT RecalcShellSize();
/*	bool ReloadResource(PVOID pbuffer, PUINT psize, int size);*/
	void ClearOpcode();
	bool SetOpcHeadAddr(BOOL addr);

protected:
	Shell_MainHeader _main;
	Shell_Header _header;
	Shell_AdvHeader _advance;

public:

	CDLibShellMain();
	~CDLibShellMain();

// Main operations
	bool Load(PVOID buffer, UINT size);
	bool Create(PVOID opcode, UINT opc_size, PVOID relocs, UINT rel_size);
	void Close();

// Configuration
	/* Загружаем Opcode */
	bool LoadOpcode(PVOID opcode, UINT opc_size, PVOID relocs, UINT rel_size);

	int AddDll(PVOID dll_name, PVOID proc_name, int pos, bool check_retn);
	void RemoveDll(PVOID dll_name);
	void RemoveAllDll();//mb TODEL
	bool GetDllList(PShell_DllFrame &plist, int max_count, int *readed);
	bool LoadTLSCallbackTable(PVOID ptable, UINT count, bool new_header = false, PVOID pdir = NULL);
	bool LoadRelocsTable(PVOID ptable, UINT count, DWORD ign_offst = 0, UINT ign_size = 0);
	void SetErrorMessage(Shell_Error_Msg type, PVOID message);
	LPSTR GetErrorMessage(Shell_Error_Msg type);
	void SetFlag(Shell_Flags flag, bool state);
	bool GetFlag(Shell_Flags flag);
	//advance mode
	void AddOffset(DWORD offset, UINT size);
	void RemoveOffset(DWORD offset);
	void ClearOffsets();
	bool GetOffsets(PShell_IgnoreFrame &plist, int max_count, int *readed);
	UINT GetOffsetsCount();
	bool SetAnticheatDll(PVOID dll_name, PVOID proc_name);

	void SetSectorProtMask(DWORD mask);
	DWORD GetSectorProtMask();

	void AddScanOffset(DWORD offset, UINT size);
	void RemoveScanOffset(DWORD offset);
	void ClearScanOffsets();
	//void GetScanOffsets(UINT num, DWORD offset, UINT size);

	PVOID GetHeaderStruct();
	PVOID GetShellResPtr(UINT id, PUINT psize);
// Build shell
	bool BuildShell(PShell_Build_Result result);
	PBYTE BuildTramplin(DWORD from, DWORD to, PUINT psize);
};
 
typedef CDLibShellMain CDLibShell32;

class CDLibShell64 : public CDLibShellMain {//TODO support x64 shellcode
private:

public:

};

#endif