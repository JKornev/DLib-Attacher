#include "stdafx.h"
#include "ResPacker.h"

// ======================= CResPacker :: PUBLIC =======================

CResPacker::CResPacker() : _guid(0)
{
}

CResPacker::~CResPacker()
{
	Clear();
}

UINT CResPacker::Add(PVOID buffer, UINT size)
{
	_ResFrame frame;
	if (size < 1) {
		return RES_INVALID_ID;
	}

	frame.id = GetGuid();
	frame.pdata = calloc(size, 1);
	frame.size = size;
	if (!frame.pdata) {
		return RES_INVALID_ID;
	}
	memcpy(frame.pdata, buffer, size);

	_res.push_back(frame);
	return frame.id;
}

BOOL CResPacker::Edit(UINT id, PVOID buffer, UINT size)
{
	std::list<_ResFrame>::iterator frame = GetResFrame(id);

	if (frame == _res.end() || size < 1) {
		return false;
	}

	free(frame->pdata);
	frame->pdata = calloc(size, 1);
	frame->size = size;
	if (!frame->pdata) {
		return false;
	}
	memcpy(frame->pdata, buffer, size);
	return true;
}

BOOL CResPacker::Resize(UINT id, UINT size)
{
	std::list<_ResFrame>::iterator frame = GetResFrame(id);
	if (frame == _res.end() || size < 1) {
		return false;
	}

	if (size == frame->size) {
		return true;
	}

	frame->pdata = realloc(frame->pdata, size);
	frame->size = size;

	return true;
}

BOOL CResPacker::Delete(UINT id)
{
	std::list<_ResFrame>::iterator frame = GetResFrame(id);
	if (frame == _res.end()) {
		return false;
	}
	free(frame->pdata);
	_res.erase(frame);
	return true;
}

void CResPacker::Clear()
{
	std::list<_ResFrame>::iterator it = _res.begin();

	while (it != _res.end()) {
		free(it->pdata);
		it++;
	}
	_res.clear();
}

PVOID CResPacker::GetDataPtr(UINT id, PUINT psize)
{
	std::list<_ResFrame>::iterator frame = GetResFrame(id);
	if (frame == _res.end()) {
		return NULL;
	}
	if (psize) {
		*psize = frame->size;
	}
	return frame->pdata;
}

DWORD CResPacker::GetResOffset(UINT id)
{
	std::list<_ResFrame>::iterator it = _res.begin();
	UINT offset = 0;
	while (it != _res.end()) {
		if (it->id == id) {
			return offset + sizeof(UINT) + sizeof(UINT);//offset + header(id_var + size_var)
		}
		offset += it->size + sizeof(UINT) + sizeof(UINT);//buffer + id_var + size_var
		it++;
	}
	return RES_INVALID_ID;
}

UINT CResPacker::GetTotalSize()
{
	std::list<_ResFrame>::iterator it = _res.begin();
	UINT total_size = 0;
	while (it != _res.end()) {
		total_size += it->size + sizeof(UINT) + sizeof(UINT);//buffer + id_var + size_var
		it++;
	}
	return total_size;
}

BOOL CResPacker::Compile(PVOID output, UINT buff_size, PUINT pcomp_size)
{
	std::list<_ResFrame>::iterator it = _res.begin();
	DWORD offset = 0;

	*pcomp_size = GetTotalSize();
	if (*pcomp_size > buff_size) {
		return false;
	}

	while (it != _res.end()) {
		*(UINT *)((UINT)output + offset) = it->id;
		offset += sizeof(UINT);

		*(UINT *)((UINT)output + offset) = it->size;
		offset += sizeof(UINT);

		memcpy((PVOID)((UINT)output + offset), it->pdata, it->size);
		offset += it->size;

		it++;
	}

	return true;
}

BOOL CResPacker::Decompile(PVOID input, UINT buff_size, PUINT pcount)
{
	DWORD added = 0, offset = 0;
	UINT guid = 0;
	_ResFrame frame;

	Clear();

	while (true) {
		if (offset + (sizeof(UINT) * 2) > buff_size) {
			break;
		}

		frame.id = *(UINT *)((UINT)input + offset);
		offset += sizeof(UINT);

		frame.size = *(UINT *)((UINT)input + offset);
		offset += sizeof(UINT);

		if (offset + frame.size > buff_size) {
			break;
		}
		if (!frame.id && !frame.size) {
			break;
		}

		if (frame.id > guid) {
			guid = frame.id;
		}

		if (GetDataPtr(frame.id, NULL)) {
			Clear();
			return false;
		}

		frame.pdata = calloc(frame.size, 1);
		if (!frame.pdata) {
			Clear();
			return false;
		}
		memcpy(frame.pdata, (PVOID)((UINT)input + offset), frame.size);
		_res.push_back(frame);
		offset += frame.size;
		added++;

		if (offset == buff_size) {
			break;
		}
	}

	_guid = ++guid;

	if (pcount) {
		*pcount = added;
	}
	return true;
}

UINT CResPacker::Count()
{
	return _res.size();
}

// ======================= CResPacker :: PRIVATE =======================

UINT CResPacker::GetGuid()
{
	return _guid++;
}

std::list<_ResFrame>::iterator CResPacker::GetResFrame(UINT id)
{
	std::list<_ResFrame>::iterator it = _res.begin();

	while (it != _res.end()) {
		if (it->id == id) {
			return it;
		}
		it++;
	}
	return _res.end();
}
