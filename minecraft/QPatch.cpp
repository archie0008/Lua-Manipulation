#include "stdafx.h"
#include "QPatch.h"
#include "Output.h"
#include "strings.h"

QPatch::QPatch(void * ad, BYTE* n_bytes, size_t sz)
{
	addr = ad;
	size = sz;
	new_bytes = new BYTE[sz];
	orig_bytes = new BYTE[sz];

	if (VirtualProtect(n_bytes, sz, PAGE_EXECUTE_READWRITE, &oldproc) == 0)
	{
		ui::error(enc("Can't patch memory."));
		return;
	}
	memcpy(new_bytes, n_bytes, sz);
	VirtualProtect(n_bytes, sz, oldproc, &oldproc);

}

bool QPatch::patch()
{
	if (VirtualProtect((void*)addr, size, PAGE_EXECUTE_READWRITE, &oldproc) == 0)
	{
		ui::error(enc("Can't patch memory."));
		return false;
	}

	memcpy(orig_bytes, addr, size);
	memcpy(addr, new_bytes, size);

	return true;
}

bool QPatch::unpatch()
{

	memcpy(addr, orig_bytes, size);

	if (VirtualProtect(addr, size, oldproc, &oldproc) == 0)
	{
		ui::error(enc("Can't patch memory."));
		return false;
	}

	return true;
}
