#include "stdafx.h"
#include "ErrorHandler.h"
#include <string.h>

CErrorCtrl::CErrorCtrl() : _error(E_OK), _sub(0)
{ 
	_descr_buff[0] = 0x00;
}

CErrorCtrl::~CErrorCtrl()
{
	return;
}

bool CErrorCtrl::SetError(unsigned int error_code, unsigned int sub_code, void *error_descr)
{
	_error = error_code;
	_sub = sub_code;

	if (NULL == error_descr) {
		_descr_buff[0] = '\0';
		//memset(&_descr_buff, 0, _E_CTRL_DESR_BUFF_SIZE - 1);
	} else {
		memset(&_descr_buff, 0, _E_CTRL_DESR_BUFF_SIZE - 1);
		memcpy(&_descr_buff, error_descr, strlen((char *)error_descr));
	}

	return (error_code == E_OK ? true : false);
}

unsigned int CErrorCtrl::LastError()
{
	return _error;
}

unsigned int CErrorCtrl::LastErrorSub()
{
	return _sub;
}

const char *CErrorCtrl::LastErrorStr()
{
	return (const char *)_descr_buff;
}

void CErrorCtrl::ClearError()
{
	_error = E_OK;
	_sub = 0;
}