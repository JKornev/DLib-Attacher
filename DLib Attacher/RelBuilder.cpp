#include "stdafx.h"
#include "RelBuilder.h"
#include <stdlib.h>
#include <map>

// ======================= CRelBuilder :: PUBLIC =======================

CRelBuilder::CRelBuilder() : _buffer(NULL)
{

}

CRelBuilder::~CRelBuilder()
{
	Clear();
}

void CRelBuilder::Clear()
{
	_relocs.clear();
	if (_buffer) {
		free(_buffer);
		_buffer = NULL;
	}
}

PVOID CRelBuilder::Compile(PUINT psize)
{
	return _Compile(psize, true);
}

UINT CRelBuilder::CalcCompileSize()
{
	UINT size = 0;
	_Compile(&size, false);
	return size;
}

bool CRelBuilder::LoadTable(LPVOID ptable, UINT size, DWORD offset)
{
	PIMAGE_BASE_RELOCATION prel;
	PWORD prels;
	DWORD base, count, type;
	int i = 0;
	while (i < size) {
		prel = (PIMAGE_BASE_RELOCATION)((DWORD)ptable + i);
		i += prel->SizeOfBlock;
		if (prel->SizeOfBlock == 0) {
			break;
		}
		if (i <= size) {//add to list
			base = prel->VirtualAddress + offset;
			count = prel->SizeOfBlock / sizeof(WORD);
			prels = (PWORD)prel;
			for (int a = 4; a < count; a++) {
				type = prels[a] >> 12;
				switch (type) {
				case IMAGE_REL_BASED_HIGHLOW://3
					_relocs.insert(base + (0x00000FFF & prels[a]));
					break;
				case IMAGE_REL_BASED_ABSOLUTE://0
					break;
				case IMAGE_REL_BASED_HIGH://1
				case IMAGE_REL_BASED_LOW://2
				case IMAGE_REL_BASED_HIGHADJ://4
				case IMAGE_REL_BASED_MIPS_JMPADDR://5
				case IMAGE_REL_BASED_MIPS_JMPADDR16://9 IMAGE_REL_BASED_IA64_IMM64 too
				case IMAGE_REL_BASED_DIR64://10
				default:
					return false;
				}
			}
		}
	}
	return true;
}

void CRelBuilder::AddRel(DWORD offset)
{
	_relocs.insert(offset);
}

void CRelBuilder::RemoveRel(DWORD offset)
{
	_relocs.erase(offset);
}

int CRelBuilder::RemoveRange(DWORD offset, UINT size)
{
	int count = 0;
	std::set<DWORD>::iterator it = _relocs.begin(), rem_it;
	while (it != _relocs.end()) {
		if (*it >= offset && *it < offset + size) {
			rem_it = it;
			it++;
			_relocs.erase(rem_it);
			count++;
			continue;
		}
		it++;
	}
	return count;
}

// ======================= CRelBuilder :: PRIVATE =======================

UINT CRelBuilder::Aligment(UINT offset, UINT aligm_base)
{
	return offset - (offset % aligm_base);
}

PVOID CRelBuilder::_Compile(PUINT psize, bool gen_bin)
{
	UINT size = 0, block;
	std::map<DWORD, std::set<DWORD>> calc;
	std::map<DWORD, std::set<DWORD>>::iterator m_it;
	std::set<DWORD>::iterator it = _relocs.begin();
	IMAGE_BASE_RELOCATION rel;

	while (it != _relocs.end()) {
		calc[Aligment(*it)].insert(*it);
		it++;
	}

	m_it = calc.begin();
	while (m_it != calc.end()) {
		block = sizeof(IMAGE_BASE_RELOCATION) + (m_it->second.size() * sizeof(WORD));
		block += block % sizeof(DWORD);
		size += block;
		//size += sizeof(IMAGE_BASE_RELOCATION) + (m_it->second.size() * sizeof(WORD)) + sizeof(WORD);
		m_it++;
	}
	/*size += sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD);*/

	if (!gen_bin) {
		if (psize) {
			*psize = size;
		}
		return NULL;
	}

	PBYTE pbuffer = (PBYTE)calloc(size, 1);
	if (!pbuffer) {
		return NULL;
	}

	int offset = 0, i;
	PWORD ptable;
	m_it = calc.begin();
	while (m_it != calc.end()) {
		rel.VirtualAddress = m_it->first;
		block = sizeof(IMAGE_BASE_RELOCATION) + (m_it->second.size() * sizeof(WORD));
		block += block % sizeof(DWORD);
		rel.SizeOfBlock = block;
		//rel.SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + (m_it->second.size() * sizeof(WORD)) + sizeof(WORD);
		memcpy((PBYTE)((DWORD)pbuffer + offset), &rel, sizeof(IMAGE_BASE_RELOCATION));
		offset += sizeof(IMAGE_BASE_RELOCATION);

		ptable = (PWORD)((DWORD)pbuffer + offset);
		it = m_it->second.begin();
		i = 0;
		while (it != m_it->second.end()) {
			ptable[i] = (WORD)((*it - rel.VirtualAddress) | 0x3000);
			i++;
			it++;
		}
		block = (m_it->second.size() * sizeof(WORD));
		block += block % sizeof(DWORD);
		if (block % sizeof(DWORD)) {
			ptable[i] = 0x0000;
		}
		offset += block;
		m_it++;
	}

/*
	rel.VirtualAddress = 0;
	rel.SizeOfBlock = 0;
	memcpy((PBYTE)((DWORD)pbuffer + offset), &rel, sizeof(IMAGE_BASE_RELOCATION));
	if (_heapchk() != _HEAPOK) {
		MessageBoxA(NULL, "Error, heap corrupt #4", "Error", NULL);
	}
	memset((PBYTE)((DWORD)pbuffer + offset + sizeof(IMAGE_BASE_RELOCATION)), 0, sizeof(WORD));*/

	_buffer = pbuffer;
	_size = size;

	if (psize) {
		*psize = _size;
	}
	return _buffer;
}