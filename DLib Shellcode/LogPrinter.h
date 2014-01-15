#ifndef __H_LOGPRINTER
#define __H_LOGPRINTER

#include "LogCore.h"

#define LOG_FILENAME "Client_(%02d-%02d-%02d).log"
#define CRASH_LOG_FILE L"Client_Crash.log"
//TODO change DEBUG_MODE to debug-defined constant 
#define DEBUG_MODE

#ifndef DEBUG_MODE
#define DebugLog //
#else
#define DebugLog LogPrinter::Instance()->WriteLog
#endif

#define Log LogPrinter::Instance()->WriteLog

class LogPrinter : public LogCore //singleton pattern
{
	LogPrinter();
public:
	static LogPrinter *Instance();
};

#endif