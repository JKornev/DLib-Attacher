#ifndef __H_RELBUILDER
#define __H_RELBUILDER

#include <Windows.h>
#include <set>

/* Relocs container */
class CRelBuilder {
	PBYTE _buffer;
	UINT _size;

	std::set<DWORD> _relocs;

	UINT Aligment(UINT offset, UINT aligm_base = 0x1000);
	PVOID _Compile(PUINT psize, bool gen_bin);
public:
	CRelBuilder();
	~CRelBuilder();

	PVOID Compile(PUINT psize);
	void Clear();

	bool LoadTable(LPVOID ptable, UINT size, DWORD offset = 0);
	void AddRel(DWORD offset);
	void RemoveRel(DWORD offset);
	int RemoveRange(DWORD offset, UINT size);

	UINT CalcCompileSize();
};

#endif