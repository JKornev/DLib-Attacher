#ifndef __H_DLIBSHELL_STRUCTS
#define __H_DLIBSHELL_STRUCTS

#include "ErrorHandler.h"
#include <Windows.h>

#define SHELL_SIGNATURE 0x4B4A //shell signature
#define SHELL_FORMAT_VER 0x0003 //shell format version
#define SHELL_MINOR_VER 0x0001 //min support version

#define SHELL_CODE_SIGNATURE  0x43534B4A //JKSC
#define SHELL_CODE_SIGNATURE2 0xAAAAAAAA
#define SHELL_CODE_SIGNATURE3 0x43534B4A

#define SHELL_TRAMP_SIGNATURE "JKTJ"
#define SHELL_TRAMP_SIGN_SIZE 4
#define SHELL_TRAMP_SIZE 5 + SHELL_TRAMP_SIGN_SIZE

#define PHRASE_ERROR_COUNT 4

#define SHELL_EXP_PROC_USE_RETN _BIT(31)

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
	DWORD res_table;	// resource table offset
	DWORD res_count;	// count of resource
	//Misc
	DWORD flags;		// flags mask
} Shell_MainHeader, *PShell_MainHeader;

typedef struct {
	DWORD checksum;								// Checksum32
	//resource id's
	DWORD code_id;								// resource id for code
	DWORD tls_id;								// resource id for TLS callback table
	DWORD tls_head_id;							// resource id for TLS header
	DWORD relocs_id;							// resource id for relocs handle
	DWORD phr_error_id[PHRASE_ERROR_COUNT];		// resource id's for error phrases
	DWORD dll_table_id;							// resource id for dll's table
	DWORD dll_count;							// count of elements from dll's table
	//recover data
	DWORD rec_relocs_addr;						// original relocs data RVA address
	UINT rec_relocs_size;						// original relocs data size
	DWORD rec_tls_dir_addr;						// original TLS dir address
	DWORD rec_tls_clbk_addr;					// original TLS callback address
	UINT rec_tls_size;							// original TLS dir size
#ifdef  __cplusplus
} Shell_Header_v1, *PShell_Header_v1;

typedef struct : Shell_Header_v1{
#endif
	DWORD rec_entrypoint;						// original Entry Point RVA address
	DWORD rec_sec_id;							// tramplin section id
	DWORD rec_sec_raw_size;						// original tramplin section size
} Shell_Header, *PShell_Header;

typedef struct {
	DWORD ignore_id;		// resource id for ignored ranges
	DWORD ignore_count;		// count of ignored ranges
	DWORD dll_id;			// resource id Anticheat dll name
	DWORD proc_id;			// resource id Anticheat dll export procedure name (second step)
	//v3
	DWORD sect_id;			// resource id for section protect array
	DWORD sect_prot;		//
} Shell_AdvHeader, *PShell_AdvHeader;

typedef struct {
	DWORD offset;
	DWORD size;
} Shell_IgnoreFrame, *PShell_IgnoreFrame;

typedef struct {
	DWORD name_id;
	DWORD func_id;
} Shell_DllFrame, *PShell_DllFrame;

//Incode
typedef struct {
	DWORD signature;		//JSSC 0x43534B4A
	DWORD address_of_header;
	Shell_MainHeader *pmain;
} Shell_IncodeStruct, *PShell_IncodeStruct;

typedef struct {
	DWORD signature;		// JSSC 0x43534B4A
	DWORD address_of_header;// shell header RVA address
	DWORD signature2;		// end
} Shellcode_Struct, *PShellcode_Struct;

typedef struct {
	UINT id;
	UINT size;
	PBYTE pdata;
} Shell_Resource, *PShell_Resource;

typedef struct {
	DWORD imgbase;
	DWORD relbase;
} Shell_Opcode_Header, *PShell_Opcode_Header;

typedef struct {
	DWORD ep_tls;
	DWORD ep_main;
	DWORD ep_dll;
} Shell_Opcode_Export, *PShell_Opcode_Export;

#ifdef  __cplusplus
#pragma pack(pop)//recover aligment
#endif

enum Shell_Error_Msg {
	SE_SYSTEM_FAIL = 0,
	SE_SYSTEM_FAIL2,
	SE_SYSTEM_FAIL3,
	SE_LIBRARY_FAIL
};

enum Shell_Flags {
	SF_ADVANCE	= _BIT(0),
	SF_CRC32	= _BIT(1),
//misc
	SF_DLL		= _BIT(27),
	SF_USE_EP	= _BIT(28),//if not set, used TLS
	SF_RELOCS	= _BIT(29),
	SF_TLS_DIR	= _BIT(30),
	SF_TLS		= _BIT(31),
};

#endif