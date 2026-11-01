#pragma once

class QPatch
{
private:
	void * addr;
	DWORD oldproc;
	BYTE* orig_bytes;
	BYTE* new_bytes;
	size_t size;
public:
	QPatch(void * ad, BYTE* n_bytes, size_t sz);
	bool patch();
	bool unpatch();
};