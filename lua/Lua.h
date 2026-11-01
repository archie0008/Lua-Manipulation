#pragma once
typedef int(__cdecl *loadbuffer_fn)(int lua_state, char* buffer, size_t size, char* chunkname);
typedef int(__cdecl *resume_fn)(int lua_state, int nargs);
typedef int(__cdecl *pcall_fn)(int lua_state, int a, int b, int c);
typedef int(__cdecl *gettop_fn)(int lua_state);
typedef void(__cdecl *settop_fn)(int lua_state, int a);
typedef int(__cdecl *newthread_fn)(int lua_state);
typedef char*(__cdecl *tolstring_fn)(int lua_state, int a, size_t* b);

namespace lua
{
	bool initialize();
	bool bind_native_globals(int state);
	extern loadbuffer_fn loadbuffer;
	extern pcall_fn pcall;
	extern resume_fn resume;
	extern gettop_fn gettop;
	extern settop_fn settop;
	extern newthread_fn newthread;
	extern tolstring_fn tolstring;
}
