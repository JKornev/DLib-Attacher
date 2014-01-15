//-----------
#include "stdafx.h"
#include "Exception.h"
#include "PEScan.h"
//-----------
#include <Windows.h>
//-----------

//---------------------------------------------------------------------------
LPTOP_LEVEL_EXCEPTION_FILTER last_filter = NULL;
//---------------------------------------------------------------------------

const char * GetCodeStr(DWORD code) 
{
	switch (code) 
	{
	case EXCEPTION_ACCESS_VIOLATION:
		return "ACCESS_VIOLATION"; break;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		return "ARRAY_BOUNDS_EXCEEDED"; break;
	case EXCEPTION_BREAKPOINT:
		return "BREAKPOINT"; break;
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		return "DATATYPE_MISALIGNMENT"; break;
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		return "FLT_DENORMAL_OPERAND"; break;
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		return "FLT_DIVIDE_BY_ZERO"; break;
	case EXCEPTION_FLT_INEXACT_RESULT:
		return "FLT_INEXACT_RESULT"; break;
	case EXCEPTION_FLT_INVALID_OPERATION:
		return "FLT_INVALID_OPERATION"; break;
	case EXCEPTION_FLT_OVERFLOW:
		return "FLT_OVERFLOW"; break;
	case EXCEPTION_FLT_STACK_CHECK:
		return "FLT_STACK_CHECK"; break;
	case EXCEPTION_FLT_UNDERFLOW:
		return "FLT_UNDERFLOW"; break;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		return "ILLEGAL_INSTRUCTION"; break;
	case EXCEPTION_IN_PAGE_ERROR:
		return "IN_PAGE_ERROR"; break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		return "INT_DIVIDE_BY_ZERO"; break;
	case EXCEPTION_INT_OVERFLOW:
		return "INT_OVERFLOW"; break;
	case EXCEPTION_INVALID_DISPOSITION:
		return "INVALID_DISPOSITION"; break;
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		return "NONCONTINUABLE_EXCEPTION"; break;
	case EXCEPTION_PRIV_INSTRUCTION:
		return "PRIV_INSTRUCTION"; break;
	case EXCEPTION_SINGLE_STEP:
		return "SINGLE_STEP"; break;
	case EXCEPTION_STACK_OVERFLOW:
		return "STACK_OVERFLOW"; break;
		break;
	default:
		break;
	}
	return "Unknown";
}

//---------------------------------------------------------------------------

LONG __stdcall MainExceptionHandler(EXCEPTION_POINTERS *e)
{
	char buffer[CRASH_LOG_BUFFER];

	SYSTEMTIME Time = {0};
	GetLocalTime(&Time);

	if (!e)
		return EXCEPTION_NONCONTINUABLE_EXCEPTION;

	if (last_filter == MainExceptionHandler) {
		last_filter = NULL;
	}

	sprintf_s(buffer, 
		"Crash at %02d.%02d.%04d %02d:%02d:%02d\r\n" \
		"  Address: %08X\r\n"\
		"  Code: %s (%08X)\r\n"\
		"  Flag: %08X\r\n"\
		" ------------------------------------------------\r\n"\
		"  EAX: %08X    CS: %08X    DR0: %08X\r\n"\
		"  ECX: %08X    DS: %08X    DR1: %08X\r\n"\
		"  EDX: %08X    ES: %08X    DR2: %08X\r\n"\
		"  EBX: %08X    FS: %08X    DR3: %08X\r\n"\
		"  ESP: %08X    GS: %08X    DR6: %08X\r\n"\
		"  EBP: %08X    SS: %08X    DR7: %08X\r\n"\
		"  ESI: %08X\r\n"\
		"  EDI: %08X\r\n"\
		" ------------------------------------------------\r\n"\
		"  EIP: %08X    Flags: %08X\r\n"\
		" ------------------------------------------------\r\n"\
		"\r\n\r\n",
		Time.wDay, Time.wMonth, Time.wYear, Time.wHour, Time.wMinute, Time.wSecond,
		e->ExceptionRecord->ExceptionAddress,
		GetCodeStr(e->ExceptionRecord->ExceptionCode), e->ExceptionRecord->ExceptionCode,
		e->ExceptionRecord->ExceptionFlags,

		e->ContextRecord->Eax, e->ContextRecord->SegCs, e->ContextRecord->Dr0,
		e->ContextRecord->Ecx, e->ContextRecord->SegDs, e->ContextRecord->Dr1,
		e->ContextRecord->Edx, e->ContextRecord->SegEs, e->ContextRecord->Dr2,
		e->ContextRecord->Ebx, e->ContextRecord->SegFs, e->ContextRecord->Dr3,
		e->ContextRecord->Esp, e->ContextRecord->SegGs, e->ContextRecord->Dr6,
		e->ContextRecord->Ebp, e->ContextRecord->SegSs, e->ContextRecord->Dr7,
		e->ContextRecord->Esi,
		e->ContextRecord->Edi,
		e->ContextRecord->Eip, e->ContextRecord->EFlags);

	HANDLE hfile = CreateFileW(CRASH_LOG_FILE, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hfile) {
		if (last_filter) {
			return last_filter(e);
		} else {
			return EXCEPTION_EXECUTE_HANDLER;
		}
	}

	SetFilePointer(hfile, 0, NULL, FILE_END);
	DWORD written;
	WriteFile(hfile, buffer, strlen(buffer), &written, NULL);
	CloseHandle(hfile);

	if (last_filter) {
		return last_filter(e);
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI Hook_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) 
{
	LPTOP_LEVEL_EXCEPTION_FILTER result = last_filter;
	SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
	SetUnhandledExceptionFilter(MainExceptionHandler);
	last_filter = lpTopLevelExceptionFilter;
	return result;
}