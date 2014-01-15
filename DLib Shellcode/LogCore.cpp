#include "stdafx.h"
#include "LogCore.h"
#include <stdio.h>
#include <stdarg.h>

// ======================= CLog :: PUBLIC =======================

LogCore::LogCore() : _hfile(NULL), _hstream(NULL), _logfile(false), _logconsole(false)
{
	InitializeCriticalSection(&critsect);
}

LogCore::~LogCore()
{
	CloseLogFile();
	CloseLogConsole();
	DeleteCriticalSection(&critsect);
}

bool LogCore::OpenLogFile(void *filename)
{
	if (_logfile) {
		return false;
	}

	_hfile = CreateFileA((LPCSTR)filename, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_hfile == INVALID_HANDLE_VALUE) {
		return false;
	}

	_logfile = true;
	return true;
}

void LogCore::CloseLogFile()
{
	if (_logfile) {
		CloseHandle(_hfile);
		_logfile = false;
	}
}

bool LogCore::OpenLogConsole()
{
	if (_logconsole) {
		return false;
	}

	if (!AllocConsole()) {
		return false;
	}

	_hstream = GetStdHandle(STD_OUTPUT_HANDLE);
	if (_hstream == INVALID_HANDLE_VALUE) {
		return false;
	}

	_logconsole = true;
	return true;
}

void LogCore::CloseLogConsole()
{
	if (_hstream) {
		FreeConsole();
		CloseHandle(_hstream);
		_logconsole = false;
	}
}

void LogCore::WriteLog(bool write_date, char *format, ...)
{
	char buffer[LOG_BUFFER_SIZE];
	int size;

	va_list vlist;
	va_start(vlist, format);
	vsprintf_s(buffer, format, vlist);
	va_end(vlist);
	buffer[LOG_BUFFER_SIZE - 1] = 0x00;

	size = strlen(buffer);

	if (_logfile) {
		OutputData(_hfile, buffer, size, false, write_date);
	}
	if (_logconsole) {
		OutputData(_hstream, buffer, size, false, write_date);
	}
}

void LogCore::WriteLog(bool write_date, wchar_t *format, ...)
{
	wchar_t buffer[LOG_BUFFER_SIZE];
	int size;

	va_list vlist;
	va_start(vlist, format);
	vswprintf_s(buffer, format, vlist);
	va_end(vlist);
	buffer[LOG_BUFFER_SIZE - 1] = 0x00;

	size = wcslen(buffer);

	if (_logfile) {
		OutputData(_hfile, buffer, size, true, write_date);
	}
	if (_logconsole) {
		OutputData(_hstream, buffer, size, true, write_date);
	}
}

void LogCore::WriteLogTo(bool write_date, _Log_To type, char *format, ...)
{
	char buffer[LOG_BUFFER_SIZE];
	int size;

	va_list vlist;
	va_start(vlist, format);
	vsprintf_s(buffer, format, vlist);
	va_end(vlist);
	buffer[LOG_BUFFER_SIZE - 1] = 0x00;

	size = strlen(buffer);

	switch (type) {
	case LOG_FILE:
		OutputData(_hfile, buffer, size, false, write_date);
		break;
	case LOG_CONSOLE:
		OutputData(_hstream, buffer, size, false, write_date);
		break;
	}
}

void LogCore::WriteLogTo(bool write_date, _Log_To type, wchar_t *format, ...)
{
	wchar_t buffer[LOG_BUFFER_SIZE];
	int size;

	va_list vlist;
	va_start(vlist, format);
	vswprintf_s(buffer, format, vlist);
	va_end(vlist);
	buffer[LOG_BUFFER_SIZE - 1] = 0x00;

	size = wcslen(buffer);

	switch (type) {
	case LOG_FILE:
		OutputData(_hfile, buffer, size, true, write_date);
		break;
	case LOG_CONSOLE:
		OutputData(_hstream, buffer, size, true, write_date);
		break;
	}
}

// ======================= CLog :: PRIVATE =======================

void LogCore::OutputData(HANDLE hndl, void *buffer, int size, bool widechar, bool write_date)
{
	DWORD written = 0, dsize;
	char datestr[20], *output;

	if (widechar) {
		output = new char[size];
		WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, (LPWSTR)buffer, -1, (LPSTR)output, size, NULL, NULL);
	} else {
		output = (char *)buffer;
	}

	EnterCriticalSection(&critsect);
	SetFilePointer(hndl, NULL, NULL, FILE_END);
	if (write_date) {
		dsize = AddDate(datestr, sizeof(datestr));
		WriteFile(hndl, datestr, dsize, &written, NULL);
	}
	WriteFile(hndl, output, size, &written, NULL);
	WriteFile(hndl, "\n", 1, &written, NULL);
	LeaveCriticalSection(&critsect);

	if (widechar) {
		delete[] output;
	}
}

int LogCore::AddDate(void *buffer, int len)
{
	SYSTEMTIME t;
	GetLocalTime(&t);
	char *output = (char *)buffer;
	sprintf_s(output, len, "[%02d:%02d:%02d] ", t.wHour, t.wMinute, t.wSecond);
	return strlen(output);
}
