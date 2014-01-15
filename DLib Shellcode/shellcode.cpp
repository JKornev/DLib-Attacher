#include "main.h"
#include "../DLib Attacher/DLibShellStructs.h"

#include <Windows.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

//#define DEVELOP_MODE

#define ARCH_X86 1
#define ARCH_X64 2

#define RES_INVALID_ID -1

#define SHELL_MSG_TITLE "Loader"

//string
#define MAX_ARGS 10
#define MAX_STR_BUFF 256
#define CHAR_ENDL '\0'

#define EXPORT extern __declspec(dllexport)

EXPORT VOID NTAPI TLSCallbackEntry(PVOID handle, DWORD reason, PVOID resv);
EXPORT BOOL WINAPI DllMainEntry(PVOID handle, DWORD reason, PVOID resv);
EXPORT int EntryPoint(void);

PVOID StartupShell(HANDLE handle);
BOOL Initialize(void *param);
LPVOID Run(PVOID handle, void *param);
LPVOID GetResourcePtr(DWORD base, UINT count, UINT id, PUINT psize);
LPVOID GetKenrel32Addr();
LPVOID GetEntryPoint(HANDLE handle);

UINT SPrintf(LPSTR buffer, DWORD size, LPSTR message, UINT count, ...);
UINT StrLen(LPSTR str);
int StrCmp(char *str1, char *str2);

void MemSet(void *addr, BYTE val, UINT size);

uint_least32_t Crc32(unsigned char *buf, size_t len);

/* ==================== Linker ==================== */

#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_tls_entry")
#pragma data_seg(".CRT$XLB")
extern  PIMAGE_TLS_CALLBACK tls_entry = TLSCallbackEntry;

#pragma comment(linker, "/SECTION:.shell,ERW")
#pragma comment(linker, "/SECTION:.scode,ERW")

#pragma section(".shell")
#pragma code_seg(".scode")
#pragma data_seg(".sdata")

#pragma comment(linker, "/MERGE:.scode=.shell")
#pragma comment(linker, "/MERGE:.sdata=.shell")

/* ==================== Data block ==================== */

enum Shell_Error_Type {
	SERRT_ERROR,
	SERRT_NORM
};

typedef HMODULE (WINAPI *Orig_LoadLibraryExAAddr)(LPSTR lpFileName, HANDLE hFile, DWORD dwFlags);
typedef FARPROC (WINAPI *Orig_GetProcAddressAddr)(HMODULE hModule, LPCSTR lpProcName);
typedef VOID (WINAPI *Orig_ExitProcessAddr)(UINT uExitCod);
typedef int (WINAPI *Orig_MessageBoxAddr)(HWND hWnd, LPSTR lpText, LPSTR lpCaption, UINT uType);
typedef DWORD (WINAPI *Orig_GetLastErrorAddr)(void);
typedef HMODULE (WINAPI *Orig_GetModuleHandleWAddr)(LPCWSTR lpModuleName);
typedef int (WINAPI *ExportProc)(void);
typedef int (*Orig_EntryPoint)(void);
typedef BOOL (*WINAPI Orig_DllMain)(PVOID handle, DWORD reason, PVOID resv);

typedef struct {
	Orig_LoadLibraryExAAddr Orig_LoadLibraryExA;
	Orig_GetProcAddressAddr Orig_GetProcAddress;
	Orig_ExitProcessAddr Orig_ExitProcess;
	Orig_MessageBoxAddr Orig_MessageBoxA;
	Orig_GetLastErrorAddr Orig_GetLastError;
	Orig_GetModuleHandleWAddr Orig_GetModuleHandleW;
} Shell_WinApi, *PShell_WinApi;

#define VAR __declspec(allocate(".shell"))

VAR Shellcode_Struct data = {SHELL_CODE_SIGNATURE, SHELL_CODE_SIGNATURE2, SHELL_CODE_SIGNATURE3};
VAR static char alphabet[] = "0123456789";

/* ==================== Code block ==================== */

EXPORT VOID NTAPI TLSCallbackEntry(PVOID handle, DWORD reason, PVOID resv)
{
	if (reason == DLL_PROCESS_ATTACH) {
		StartupShell(handle);
		return;
	}
}

EXPORT int EntryPoint(void)
{
	Orig_EntryPoint Entry = (Orig_EntryPoint)StartupShell(NULL);
	return Entry();
}

EXPORT BOOL WINAPI DllMainEntry(PVOID handle, DWORD reason, PVOID resv)
{
	Orig_DllMain Entry = NULL;
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		Entry = (Orig_DllMain)StartupShell(handle);
		break;
	default:
		Entry = (Orig_DllMain)GetEntryPoint(handle);
	}
	return Entry(handle, reason, resv);
}

PVOID StartupShell(HANDLE handle)
{
	Shell_WinApi win;
	LPVOID retn;
#ifdef DEVELOP_MODE
	FILE *pfile = fopen("shell.dump.bin", "rb");
	BYTE *buff;
	int size;

	fseek(pfile, 0, SEEK_END);
	size = ftell(pfile);
	fseek(pfile, 0, SEEK_SET);
	buff = (BYTE *)malloc(size);

	fread(buff, size, 1, pfile);
	fclose(pfile);

	data.address_of_header = (DWORD)buff - (DWORD)handle;
#endif
	//data.address_of_header += (DWORD)handle;
	if (!Initialize(&win)) {
		if (!win.Orig_ExitProcess) {
			*(DWORD *)0x00000000 = 0x01;//extreme exit
		} else {
			win.Orig_ExitProcess(1);
		}
	}

	if (!handle) {
		handle = win.Orig_GetModuleHandleW(NULL);
	}

	retn = Run(handle, &win);
	if (!retn) {
		win.Orig_ExitProcess(2);
	}

	return (PVOID)((DWORD)retn + (DWORD)handle);//TODO
}

BOOL Initialize(void *param)
{
	PShell_WinApi pwin = (PShell_WinApi)param;
	DWORD img, offset, arch = 0, ofst_exp;
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_FILE_HEADER pimg;
	PIMAGE_OPTIONAL_HEADER32 popt32;
	PIMAGE_OPTIONAL_HEADER64 popt64;
	PIMAGE_EXPORT_DIRECTORY pexp;
	HMODULE hmod;

// Load functions addresses
	img = (DWORD)GetKenrel32Addr();

	//dos
	pdos = (PIMAGE_DOS_HEADER)img;
	offset = pdos->e_lfanew;

	//signature
	offset += 4;

	//image
	pimg = (PIMAGE_FILE_HEADER)(img + offset);
	offset += sizeof(IMAGE_FILE_HEADER);

	//optional
	if (pimg->Machine == IMAGE_FILE_MACHINE_I386) {
		arch = ARCH_X86;
		popt32 = (PIMAGE_OPTIONAL_HEADER32)(img + offset);
		ofst_exp = popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	} else if (pimg->Machine == IMAGE_FILE_MACHINE_AMD64) {
		arch = ARCH_X64;
		popt64 = (PIMAGE_OPTIONAL_HEADER64)(img + offset);
		ofst_exp = popt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	} else {
		return FALSE;
	}
	if (ofst_exp == 0) {
		return FALSE;
	}

	pwin->Orig_LoadLibraryExA = (Orig_LoadLibraryExAAddr)GetExportProcAddr(img, (PIMAGE_EXPORT_DIRECTORY)(img + ofst_exp), "LoadLibraryExA");
	pwin->Orig_GetProcAddress = (Orig_GetProcAddressAddr)GetExportProcAddr(img, (PIMAGE_EXPORT_DIRECTORY)(img + ofst_exp), "GetProcAddress");
	if (!pwin->Orig_LoadLibraryExA || !pwin->Orig_GetProcAddress) {
		return FALSE;
	}

	hmod = pwin->Orig_LoadLibraryExA("Kernel32.dll", NULL, NULL);
	if (!hmod) {
		return FALSE;
	}
	pwin->Orig_ExitProcess = (Orig_ExitProcessAddr)pwin->Orig_GetProcAddress(hmod, "ExitProcess");
	pwin->Orig_GetLastError = (Orig_GetLastErrorAddr)pwin->Orig_GetProcAddress(hmod, "GetLastError");
	pwin->Orig_GetModuleHandleW = (Orig_GetModuleHandleWAddr)pwin->Orig_GetProcAddress(hmod, "GetModuleHandleW");

	hmod = pwin->Orig_LoadLibraryExA("User32.dll", NULL, NULL);
	if (!hmod) {
		return FALSE;
	}
	pwin->Orig_MessageBoxA = (Orig_MessageBoxAddr)pwin->Orig_GetProcAddress(hmod, "MessageBoxA");

	if (!pwin->Orig_ExitProcess || !pwin->Orig_MessageBoxA || !pwin->Orig_GetLastError || !pwin->Orig_GetModuleHandleW) {
		return FALSE;
	}

	return TRUE;
}

LPVOID Run(PVOID handle, void *param)
{
	PShell_WinApi pwin = (PShell_WinApi)param;
	PShell_MainHeader pmain = (PShell_MainHeader)(data.address_of_header + (DWORD)handle);
	PShell_Header pheader = (PShell_Header)((DWORD)pmain + sizeof(Shell_MainHeader));
	PShell_AdvHeader padv = NULL;
	PShell_DllFrame pdll = NULL;
	UINT size;
	DWORD res_addr, ret, checksum;
	int i, chk_rtn;
	HMODULE hlib, hadv;
	char *dll_name, *proc_name, *adv_proc, *phr_error[PHRASE_ERROR_COUNT], 
		*error_title = SHELL_MSG_TITLE, msg_buff[MAX_STR_BUFF + 1];
	ExportProc pexp_proc;

	MemSet(msg_buff, 0, MAX_STR_BUFF + 1);

	if (pmain->signature != SHELL_SIGNATURE) {
		pwin->Orig_MessageBoxA(NULL, "Can't startup application!", error_title, MB_ICONERROR);
		return NULL;
	} else if (pmain->version < SHELL_MINOR_VER || pmain->version > SHELL_FORMAT_VER) {
		pwin->Orig_MessageBoxA(NULL, "Image version not supported!", error_title, MB_ICONERROR);
		return NULL;
	}

	if (pmain->flags & SF_ADVANCE) {
		padv = (Shell_AdvHeader *)((DWORD)pheader + sizeof(Shell_Header));
	}

	res_addr = (DWORD)pmain + pmain->res_table;

//Load DLLS
	for (i = 0; i < PHRASE_ERROR_COUNT; i++) {
		phr_error[i] = (char *)GetResourcePtr(res_addr, pmain->res_count, pheader->phr_error_id[i], &size);
		if (!phr_error[i]) {
			phr_error[i] = "Unknown error!";
		}
	}

	//first step Anticheat
	if (pmain->flags & SF_ADVANCE) {
		dll_name = (char *)GetResourcePtr(res_addr, pmain->res_count, padv->dll_id, &size);
		adv_proc = (char *)GetResourcePtr(res_addr, pmain->res_count, padv->proc_id, &size);
		if (!dll_name || !adv_proc) {
			pwin->Orig_MessageBoxA(NULL, "Corrupt advance data", error_title, MB_ICONERROR);
			return NULL;
		}
		hadv = pwin->Orig_LoadLibraryExA(dll_name, NULL, 0);
		if (!hadv) {
			pwin->Orig_MessageBoxA(NULL, phr_error[SE_SYSTEM_FAIL], error_title, MB_ICONERROR);
			return NULL;
		}
	}

	pdll = (PShell_DllFrame)GetResourcePtr(res_addr, pmain->res_count, pheader->dll_table_id, &size);
	if (!pdll) {
		pwin->Orig_MessageBoxA(NULL, "Can't load config (#1)!", error_title, MB_ICONERROR);
		return NULL;
	}
	for (i = 0; i < pheader->dll_count; i++) {
		dll_name = (char *)GetResourcePtr(res_addr, pmain->res_count, pdll->name_id, &size);
		if (pdll->func_id != RES_INVALID_ID) {
			proc_name = (char *)GetResourcePtr(res_addr, pmain->res_count, _CLEAR(pdll->func_id, 1), &size);
			chk_rtn = pdll->func_id & SHELL_EXP_PROC_USE_RETN;
		}
		if (!dll_name || (pdll->func_id != RES_INVALID_ID && !proc_name)) {
			pwin->Orig_MessageBoxA(NULL, "Corrupt import data", error_title, MB_ICONERROR);
			return NULL;
		}

		hlib = pwin->Orig_LoadLibraryExA(dll_name, NULL, 0);
		if (!hlib) {
			SPrintf(msg_buff, MAX_STR_BUFF, phr_error[SE_SYSTEM_FAIL], 2, dll_name, pwin->Orig_GetLastError());
			pwin->Orig_MessageBoxA(NULL, msg_buff, error_title, MB_ICONERROR);
			return NULL;
		}
		if (pdll->func_id != RES_INVALID_ID) {
			pexp_proc = pwin->Orig_GetProcAddress(hlib, proc_name);
			if (!pexp_proc) {
				SPrintf(msg_buff, MAX_STR_BUFF, phr_error[SE_SYSTEM_FAIL2], 2, dll_name, pwin->Orig_GetLastError());
				pwin->Orig_MessageBoxA(NULL, msg_buff, error_title, MB_ICONERROR);
				return NULL;
			}

			if (chk_rtn) {
				ret = pexp_proc();
				if (ret) {
					SPrintf(msg_buff, MAX_STR_BUFF, phr_error[SE_LIBRARY_FAIL], 2, dll_name, ret);
					pwin->Orig_MessageBoxA(NULL, msg_buff, error_title, MB_ICONERROR);
					return NULL;
				}
			} else {
				pexp_proc();
			}
			
		}
		pdll++;
	}

	//second step Anticheat
	if (pmain->flags & SF_ADVANCE) {
		pexp_proc = pwin->Orig_GetProcAddress(hadv, adv_proc);
		if (!pexp_proc) {
			pwin->Orig_MessageBoxA(NULL, phr_error[SE_SYSTEM_FAIL2], error_title, MB_ICONERROR);
			return NULL;
		} 
		if (!pexp_proc()) {
			pwin->Orig_MessageBoxA(NULL, phr_error[SE_LIBRARY_FAIL], error_title, MB_ICONERROR);
			return NULL;
		}
	}

#ifdef DEVELOP_MODE
	pwin->Orig_MessageBoxA(NULL, "All ok!", error_title, MB_OK);
#endif
	return (PVOID)pheader->rec_entrypoint; 
}

LPVOID GetResourcePtr(DWORD base, UINT count, UINT id, PUINT psize) 
{
	PShell_Resource pres;
	int i = 0, a = 0;
	while (a < count) {
		pres = (PShell_Resource)(base + i);
		if (pres->id == id) {
			if (psize) {
				*psize += pres->size;
			}
			return &pres->pdata;
		}
		i += pres->size + (sizeof(DWORD) * 2);
		a++;
	}
	return NULL;
}

DWORD GetExportProcAddr(DWORD base, PIMAGE_EXPORT_DIRECTORY pexp, void *proc)
{
	char **name_table = (char **)(base + pexp->AddressOfNames);
	int i;

	for (i = 0; i < pexp->NumberOfNames; i++) {
		if (!StrCmp((char *)proc, (char *)((DWORD)name_table[i] + base))) {
			WORD ordinal = *(WORD *)(base + pexp->AddressOfNameOrdinals + (i * 2));
			return (base + *(DWORD *)(base + pexp->AddressOfFunctions + (ordinal * 4)));
		}
	}
	return 0;
}

LPVOID GetEntryPoint(HANDLE handle)
{
	PShell_MainHeader pmain = (PShell_MainHeader)(data.address_of_header + (DWORD)handle);
	PShell_Header pheader = (PShell_Header)((DWORD)pmain + sizeof(Shell_MainHeader));
	return (LPVOID)pheader->rec_entrypoint;
}

int StrCmp(char *str1, char *str2)
{
	int i = -1;

	do {
		i++;
		if (str1[i] > str2[i]) {
			return -1;
		} else if (str1[i] < str2[i]) {
			return 1;
		}
	} while (str1[i] != 0x00 && str2[i] != 0x00);

	return 0;
}

UINT CalcEmbStrs(LPSTR str, UINT len)
{
	UINT count = 0, i;
	for (i = 0; i < len; i++) {
		if (str[i] == '%' && (str[i + 1] == 's' || str[i + 1] == 'd')) {
			count++;
		}
	}
	return count;
}

UINT StrLen(LPSTR str)
{
	UINT i = 0;
	do {
		if (str[i] == CHAR_ENDL) {
			return i;
		}
		i++;
	} while (TRUE);
	return 0;
}

UINT SPrintf(LPSTR buffer, DWORD size, LPSTR message, UINT count, ...)
{
	int i, a, b, emb_inx, len = 0, emb_size, emb_len, div, num;
	DWORD val[MAX_ARGS];
	char *str;
	va_list vl;

	len = StrLen(message);
	if (len > size) {
		len = size;
	}
	emb_size = CalcEmbStrs(message, len);
	if (emb_size > MAX_ARGS) {
		emb_size = MAX_ARGS;
	}

	va_start(vl, count);
	for (i = emb_size - 1; i >= 0; i--) {
		val[emb_size - i - 1] = va_arg(vl, DWORD);
	}
	va_end(vl);

	emb_inx = 0;
	for (i = 0, a = 0; i < len && a < size; i++, a++) {
		if (message[i] == '%' && emb_inx < emb_size) {
			if (message[i + 1] == 'd') {
				//embedding decimal value
				num = div = val[emb_inx++];
				emb_len = 0;
				while (div) {
					div = div / 10;
					emb_len++;
				}
				if (num < 0) {
					emb_len++;
				}

				if (a + emb_len >= size) {
					break;
				}

				for (b = emb_len - 1; b >= 0; b--) {
					buffer[a + b] = alphabet[num % 10];
					num /= 10;
				}
				a += emb_len - 1;
				i++;
			} else if (message[i + 1] == 's') {
				//embedding string
				str = (char *)val[emb_inx++];
				emb_len = StrLen(str);

				if (a + emb_len >= size) {
					break;
				}

				for (b = 0; b < emb_len; b++) {
					buffer[a + b] = str[b];
				}
				a += emb_len - 1;
				i++;
			}
		} else {
			buffer[a] = message[i];
		}
	}
	buffer[a] = CHAR_ENDL;
	return a;
}

void MemSet(void *addr, BYTE val, UINT size) 
{
	int i = 0;
	char *mem = (char *)addr;
//goto воимя запутывания оптимизатора
do_repeat:
	mem[i] = val;
	i++;
	if (i >= size) {
		goto end_repeat;
	}
	goto do_repeat;
end_repeat:
	return;
}

LPVOID GetKenrel32Addr()
{/* WARNING: Undocumented feature
	- x64 not supported
	- for Windows 7, 8 return address for KernelBase.dll
	- for Windows XP must return address for Kernel32.dll
 */
	LPVOID result = NULL;
	__asm {
		mov eax, dword ptr fs:[0x30]
		test eax, eax
		js retn_label
		mov eax, dword ptr ds:[eax + 0x0C]
		mov eax, dword ptr ds:[eax + 0x1C]
		mov eax, dword ptr ds:[eax]
		mov eax, dword ptr ds:[eax + 0x08]
		mov result, eax
	}
retn_label:
	return result;
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