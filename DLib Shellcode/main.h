#ifndef __H_MAIN
#define __H_MAIN

#include <Windows.h>

int  init();
/*

#ifdef  __cplusplus
#pragma pack(push, 1)//disable aligment
#endif

typedef struct {
	WORD signature;		// signature 'JK' 0x4A4B
	WORD version;		// format version
	DWORD size;			// total size of block
//Offsets
	DWORD header;		// header offset
	DWORD adv_header;	// advance header offset
	DWORD res_table;	// 
	DWORD res_count;	// 
//Misc
	DWORD flags;		// 
} Shell_MainHeader, *PShell_MainHeader;

typedef struct {
	DWORD checksum;				// Checksum32
//resource id's
	DWORD code_id;				// resource id for code
	DWORD tls_id;				// resource id for TLS callback table
	DWORD phr_error_id[4];		// resource id's for error phrases
	DWORD dll_table_id;			// resource id for dll's table
	DWORD dll_count;			// count of elements from dll's table
} Shell_Header, *PShell_Header;

typedef struct {
	DWORD ignore_id;
	DWORD ignore_count;
} Shell_AdvHeader, *PShell_AdvHeader;

typedef struct {
	DWORD offset;
	DWORD size;
} Shell_IgnoreFrame, *PShell_IgnoreFrame;

typedef struct {
	DWORD name_id;
	DWORD func_id;
} Shell_DllFrame, *PShell_DllFrame;

#ifdef  __cplusplus
#pragma pop//recover aligment
#endif

enum Shell_Error_Msg {
	SE_SYSTEM_FAIL,
	SE_LIBRARY_FAIL
};

enum Shell_Flags {
	SF_ADVANCE,
	SF_CRC32,
};*/

#endif