#ifndef __H_ERROR_HNLR
#define __H_ERROR_HNLR

#define _E_CTRL_DESR_BUFF_SIZE 100
#define _E_CTRL_NULL_STR ""

enum _DefErrorCode {
	E_OK,
	E_UNKNOWN,
	E_NOT_FOUND,
	E_STATE_ALLREADY,
	E_OVERFLOW,
	E_OUT_OF_RANGE,
	E_ACCESS_DENIED,
	E_ALLOC_FAIL,
	E_NOT_SUPPORTED,
};

class CErrorCtrl {
	char _descr_buff[_E_CTRL_DESR_BUFF_SIZE];
	unsigned int _error;
	unsigned int _sub;

public:
	bool SetError(unsigned int error_code, unsigned int sub_code = 0, void *error_descr = NULL);
	void ClearError();

	CErrorCtrl();
	~CErrorCtrl();

	unsigned int LastError();
	unsigned int LastErrorSub();
	const char *LastErrorStr();
};

#endif