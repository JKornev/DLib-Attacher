#ifndef __H_RESPACK
#define __H_RESPACK

#include <Windows.h>
#include <list>

#define RES_INVALID_ID -1

typedef struct {
	UINT id;
	UINT size;
	PVOID pdata;
} _ResFrame, *_PResFrame;


/* Binary resource compiler */
class CResPacker {
private:
	std::list<_ResFrame> _res;
	UINT _guid;

	UINT GetGuid();
	std::list<_ResFrame>::iterator GetResFrame(UINT id);
public:
	CResPacker();
	~CResPacker();

	UINT Add(PVOID buffer, UINT size);
	BOOL Edit(UINT id, PVOID buffer, UINT size);
	BOOL Resize(UINT id, UINT size);
	BOOL Delete(UINT id);
	UINT Count();

	void Clear();

	PVOID GetDataPtr(UINT id, PUINT psize);
	DWORD GetResOffset(UINT id);

	UINT GetTotalSize();
	BOOL Compile(PVOID output, UINT buff_size, PUINT pcomp_size);
	BOOL Decompile(PVOID input, UINT buff_size, PUINT pcount);
};

#endif