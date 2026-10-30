#include "stdafx.h"
#include "Hooks.h"

BYTE tempJMP[JMP_BUFFER] = { JMP_OPCODE, 0x90, 0x90, 0x90, 0x90, RTN_OPCODE };

DWORD getrealitivedisplacement(DWORD from, DWORD to, DWORD insSize)
{
	if (to < from)
		return 0 - (from - to) - insSize;
	return to - (from + insSize);
}

C_Hook::C_Hook()
{

	setSubs(0, 0);
}

C_Hook::C_Hook(void * osub, void * nsub)
{
	setSubs(osub, nsub);
}

void C_Hook::setSubs(void * osub, void * nsub)
{
	originalsub = osub;
	newsub = nsub;

	BYTE jmpbytes[JMP_BUFFER];
	memcpy(jmpbytes, tempJMP, JMP_BUFFER);
	DWORD JMPSize = getrealitivedisplacement((DWORD)originalsub, (DWORD)newsub, 5);
	memcpy(&jmpbytes[1], &JMPSize, 4);

	jpatch = new QPatch(originalsub, (BYTE*)jmpbytes, JMP_BUFFER);

	installed = false;
}

bool C_Hook::installHook()
{
	if (jpatch->patch())
	{
		installed = true;
		return true;
	}
	else
	{
		installed = false;
		return false;
	}
}

bool C_Hook::removeHook()
{
	if (jpatch->unpatch())
	{
		installed = false;
		return true;
	}
	else
	{
		return false;
	}
}
