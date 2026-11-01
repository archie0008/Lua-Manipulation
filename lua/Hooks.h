#pragma once
#include "QPatch.h"
#define JMP_OPCODE 0xE9
#define RTN_OPCODE 0xC3
#define JMP_BUFFER 6

class C_Hook
{
private:
	void * originalsub;
	void * newsub;
	QPatch* jpatch;
	bool installed;
public:
	C_Hook();
	C_Hook(void * osub, void * nsub);
	void setSubs(void * osub, void * nsub);

	bool installHook();
	bool removeHook();
};