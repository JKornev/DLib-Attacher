#ifndef __H_EXCEPTION
#define __H_EXCEPTION

#include <Windows.h>

#ifndef CRASH_LOG_FILE
#define CRASH_LOG_FILE L"Crash.log"
#endif
#define CRASH_LOG_BUFFER 1500

const char *GetCodeStr(DWORD code) ;
LONG __stdcall MainExceptionHandler(EXCEPTION_POINTERS *e);
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI Hook_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);

extern LPTOP_LEVEL_EXCEPTION_FILTER last_filter;

#endif