#ifndef __H_LOG
#define __H_LOG

#define LOG_BUFFER_SIZE 1024

enum _Log_To {
	LOG_FILE,
	LOG_CONSOLE
};

class LogCore {
private:
	bool _logfile;
	bool _logconsole;

	HANDLE _hfile;
	HANDLE _hstream;
	CRITICAL_SECTION critsect;

	void OutputData(HANDLE hndl, void *buffer, int size,  bool widechar, bool write_date);
	int AddDate(void *buffer, int len);
public:
	LogCore();
	~LogCore();

	bool OpenLogFile(void *filename);
	void CloseLogFile();

	bool OpenLogConsole();
	void CloseLogConsole();

	void WriteLog(bool write_date, char *format, ...);
	void WriteLog(bool write_date, wchar_t *format, ...);

	void WriteLogTo(bool write_date, _Log_To type, char *format, ...);
	void WriteLogTo(bool write_date, _Log_To type, wchar_t *format, ...);
};

#endif