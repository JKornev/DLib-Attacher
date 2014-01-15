#include "stdafx.h"
#include "LogCore.h"
#include "LogPrinter.h"
#include "Exception.h"
#include <stdio.h>

LogPrinter::LogPrinter()
{
	char filename[128];
	SYSTEMTIME t;

	GetLocalTime(&t);
	sprintf_s(filename, LOG_FILENAME, t.wDay, t.wMonth, t.wYear);
	OpenLogFile(filename);

#ifdef DEBUG_MODE
	OpenLogConsole();
#endif

	SetUnhandledExceptionFilter(MainExceptionHandler);
}

LogPrinter *LogPrinter::Instance()
{
	static LogPrinter *_pinstance = NULL;
	if (!_pinstance) {
		_pinstance = new LogPrinter();
	}
	return _pinstance;
}
