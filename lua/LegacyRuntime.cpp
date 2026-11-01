#include "stdafx.h"
#include "strings.h"
#include "LegacyCompiler.h"
#include <cstring>

namespace legacy
{
namespace
{
struct native_string
{
    union { char inline_bytes[16]; const unsigned char* data; } storage;
    uint32_t size;
    uint32_t capacity;
};
static_assert(sizeof(native_string)==24,"Unexpected MSVC string layout");
using load_fn=int(__cdecl*)(int,const native_string*,const char*,uint32_t);
using load_fast_fn=int(__fastcall*)(int,const native_string*,const char*,uint32_t);
using newstring_fn=uintptr_t(__cdecl*)(int,const char*,size_t);
using growstack_fn=void(__cdecl*)(int,int);
struct profile
{
    uint32_t timestamp,image_size,loader,string_function,grow_function;
    bool fastcall_loader,relative_key,encrypt_operands;
    bool inherited_globals = false;
};

const profile profiles[]={
    {1410826426u,0xf70000u,0x18a0u,0x1838e0u,0x1845e0u,true,false,false},
    {1444701777u,0x13e3000u,0x5800u,0x11e210u,0x11ef50u,false,true,false},
    {1791139176u,0x12bd000u,0x5a20u,0x118ee0u,0x119c60u,false,true,true},
    {0x57ae115cu,0x1771000u,0x5ba0u,0x14ac40u,0x14b9e0u,false,true,true,true},
    {0x6adb1663u,0x164a000u,0x43670u,0x159be0u,0x15a960u,false,true,true,true}
};
const profile* active=nullptr;
uintptr_t script_loader=0;
newstring_fn newstring=nullptr;
growstack_fn growstack=nullptr;

int fail(int state,const std::string& error)
{
    uintptr_t address=static_cast<uintptr_t>(static_cast<uint32_t>(state));
    uintptr_t value=newstring(state,error.data(),error.size());
    uintptr_t top=*reinterpret_cast<uintptr_t*>(address+0x10);
    uintptr_t end=*reinterpret_cast<uintptr_t*>(address+0x20);
    if (end-top<=16) {growstack(state,1);top=*reinterpret_cast<uintptr_t*>(address+0x10);}
    uint32_t slot[4]={static_cast<uint32_t>(value),0,4,0};
    std::memcpy(reinterpret_cast<void*>(top),slot,sizeof(slot));
    *reinterpret_cast<uintptr_t*>(address+0x10)=top+16;
    return 3;
}
bool matches(uintptr_t address,const unsigned char* bytes,size_t size)
{
    return std::memcmp(reinterpret_cast<const void*>(address),bytes,size)==0;
}
}
bool initialize(uintptr_t module)
{
    active=nullptr;
    const auto* dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    const auto* nt=reinterpret_cast<const IMAGE_NT_HEADERS32*>(module+dos->e_lfanew);
    for (const profile& candidate:profiles)
    {
        if (nt->FileHeader.TimeDateStamp!=candidate.timestamp || nt->OptionalHeader.SizeOfImage!=candidate.image_size) continue;
        const unsigned char cdecl_header[]={0x55,0x8b,0xec,0x64,0xa1,0,0,0,0,0x6a,0xff,0x68};
        const unsigned char fast_header[]={0x55,0x8b,0xec,0x83,0xe4,0xf8,0x6a,0xff,0x68};
        const unsigned char string_header[]={0x55,0x8b,0xec,0x51,0x8b,0x45,0x10,0x53,0x56,0x8b,0xf0,0xc1};
        const unsigned char grow_header[]={0x55,0x8b,0xec,0x8b,0x4d,0x08,0x8b,0x55,0x0c,0x8b,0x41,0x30};
        if (!(candidate.fastcall_loader?matches(module+candidate.loader,fast_header,sizeof(fast_header)):
                matches(module+candidate.loader,cdecl_header,sizeof(cdecl_header))) ||
            !matches(module+candidate.string_function,string_header,sizeof(string_header)) ||
            !matches(module+candidate.grow_function,grow_header,sizeof(grow_header))) return false;
        active=&candidate;
        script_loader=module+candidate.loader;
        newstring=reinterpret_cast<newstring_fn>(module+candidate.string_function);
        growstack=reinterpret_cast<growstack_fn>(module+candidate.grow_function);
        return true;
    }
    return false;
}
bool uses_native_environment()
{
    return active && active->inherited_globals;
}
int __cdecl loadbuffer(int state,char* source,size_t size,char* name)
{
    uintptr_t address=static_cast<uintptr_t>(static_cast<uint32_t>(state));
    uintptr_t key_slot=address+*reinterpret_cast<uint32_t*>(address+8)+0x24;
    uint32_t key=*reinterpret_cast<uint32_t*>(key_slot);
    if (active->relative_key) key+=static_cast<uint32_t>(key_slot);
    if (!(key&1)) return fail(state,enc("Invalid Lua instruction key"));
    std::vector<unsigned char> bytecode;
    std::string error;
    if (!compile(source,size,name,inverse_odd(key),bytecode,error,active->encrypt_operands)) return fail(state,error);
    std::vector<unsigned char> encoded=package(bytecode);
    native_string input={};
    input.storage.data=encoded.data();
    input.size=static_cast<uint32_t>(encoded.size());
    input.capacity=input.size;

    if (active->fastcall_loader)
        return reinterpret_cast<load_fast_fn>(script_loader)(state,&input,name,1);
    return reinterpret_cast<load_fn>(script_loader)(state,&input,name,1);
}
}