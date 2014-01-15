#ifndef __H_ERROR_HNLR
#define __H_ERROR_HNLR

// Bit-mask type
typedef unsigned int Mask_Type;
// Bit-mask macro
#define _MASK_SIZE sizeof(Mask_Type)
#define _BIT(x) (1 << (x))
#define _CLEAR(src, lbits) (((src)<<(lbits))>>(lbits))
#define _GET_BIT(src, pos) (((src)<<(_MASK_SIZE - 1 - (pos))) >> _MASK_SIZE - 1)//non-safe position
#define _GET_SRC_BIT(src, pos) ((((src)<<(_MASK_SIZE - 1 - (pos))) >> _MASK_SIZE - 1) << pos)//safe position

#define _E_CTRL_DESR_BUFF_SIZE 100
#define _E_CTRL_NULL_STR ""

enum _DefErrorCode {
	E_OK,
	E_INHERIT,
	E_UNKNOWN,
	E_NOT_FOUND,
	E_STATE_ALLREADY,
	E_OVERFLOW,
	E_OUT_OF_RANGE,
	E_ACCESS_DENIED,
	E_ALLOC_FAIL,
	E_NOT_SUPPORTED,
};

#ifdef  __cplusplus //fix for C code
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
#endif //end fix for C code

#endif