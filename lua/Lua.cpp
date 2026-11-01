#include "stdafx.h"
#include "strings.h"
#include "Lua.h"
#include "Output.h"
#include "LegacyCompiler.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>
#include <initializer_list>

namespace {
using lua_reader = const char* (__cdecl *)(int, void*, size_t*);
using lua_load_fn = int (__cdecl *)(int, lua_reader, void*, const char*, const char*);
lua_load_fn lua_load = nullptr;
struct source_buffer { const char* data; size_t size; };
const char* __cdecl read_source(int, void* data, size_t* size)
{
    auto& source = *static_cast<source_buffer*>(data);
    *size = source.size;
    const char* bytes = source.size ? source.data : nullptr;
    source.size = 0;
    return bytes;
}
int __cdecl load_source(int state, char* data, size_t size, char* name)
{
    source_buffer source = {data, size};
    return lua_load(state, read_source, &source, name, nullptr);
}
}
loadbuffer_fn lua::loadbuffer = nullptr;
pcall_fn lua::pcall = nullptr;
resume_fn lua::resume = nullptr;
gettop_fn lua::gettop = nullptr;
settop_fn lua::settop = nullptr;
newthread_fn lua::newthread = nullptr;
tolstring_fn lua::tolstring = nullptr;

namespace
{
using pushclosure_fn = void(__cdecl*)(int, uintptr_t, int);
using setfield_fn = void(__cdecl*)(int, int, const char*);
using pushstring_fn = void(__cdecl*)(int, const char*);
using settable_fn = void(__cdecl*)(int, int);
struct native_global
{
    std::string name;
    uintptr_t callback;
};
std::vector<native_global> native_globals;
pushclosure_fn pushclosure = nullptr;
setfield_fn setfield = nullptr;
pushstring_fn pushstring = nullptr;
settable_fn settable = nullptr;

struct region_data
{
    uintptr_t address;
    std::vector<unsigned char> bytes;
};

bool read_memory(uintptr_t address, void* output, size_t size)
{
    SIZE_T read = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), output, size, &read) && read == size;
}

std::vector<region_data> get_regions(uintptr_t base)
{
    std::vector<region_data> regions;
    IMAGE_DOS_HEADER dos = {};
    if (!read_memory(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
        return regions;
    uintptr_t nt_address = base + dos.e_lfanew;
    IMAGE_NT_HEADERS32 nt = {};
    if (!read_memory(nt_address, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return regions;
    uintptr_t table = nt_address + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    for (unsigned index = 0; index < nt.FileHeader.NumberOfSections; ++index)
    {
        IMAGE_SECTION_HEADER section = {};
        if (!read_memory(table + index * sizeof(section), &section, sizeof(section)) || !(section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        size_t size = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
        if (section.VirtualAddress >= nt.OptionalHeader.SizeOfImage)
            continue;
        size = (std::min)(size, static_cast<size_t>(nt.OptionalHeader.SizeOfImage - section.VirtualAddress));
        uintptr_t cursor = base + section.VirtualAddress;
        uintptr_t end = cursor + size;
        while (cursor < end)
        {
            MEMORY_BASIC_INFORMATION info = {};
            if (!VirtualQuery(reinterpret_cast<void*>(cursor), &info, sizeof(info)))
                break;
            uintptr_t chunk_end = (std::min<uintptr_t>)(end, reinterpret_cast<uintptr_t>(info.BaseAddress) + static_cast<uintptr_t>(info.RegionSize));
            if (chunk_end <= cursor)
                break;
            DWORD protection = info.Protect & 0xFF;
            bool readable = protection == PAGE_READONLY || protection == PAGE_READWRITE || protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
            if (info.State == MEM_COMMIT && !(info.Protect & PAGE_GUARD) && readable)
            {
                region_data region;
                region.address = cursor;
                region.bytes.resize(chunk_end - cursor);
                if (read_memory(cursor, region.bytes.data(), region.bytes.size()))
                {
                    if (!regions.empty() && regions.back().address + regions.back().bytes.size() == cursor)
                        regions.back().bytes.insert(regions.back().bytes.end(), region.bytes.begin(), region.bytes.end());
                    else
                        regions.push_back(region);
                }
            }
            cursor = chunk_end;
        }
    }
    return regions;
}

bool find_native_globals(const std::vector<region_data>& regions)
{
    native_globals.clear();
    pushclosure = nullptr;
    setfield = nullptr;
    pushstring = nullptr;
    settable = nullptr;
    auto executable = [&](uintptr_t address)
    {
        for (const auto& region : regions)
            if (address >= region.address && address - region.address < region.bytes.size()) return true;
        return false;
    };
    uintptr_t push_address = 0, set_address = 0;
    for (const auto& region : regions)
    {
        for (size_t offset = 0; offset + 29 <= region.bytes.size(); ++offset)
        {
            const unsigned char* bytes = region.bytes.data() + offset;
            if (bytes[0] != 0x6a || bytes[1] != 0 || bytes[2] != 0x68 ||
                bytes[7] < 0x50 || bytes[7] > 0x57 || bytes[8] != 0xe8 || bytes[13] != 0x68 ||
                bytes[18] != 0x68 || bytes[19] != 0xee || bytes[20] != 0xd8 ||
                bytes[21] != 0xff || bytes[22] != 0xff || bytes[23] != bytes[7] || bytes[24] != 0xe8) continue;
            uint32_t callback = 0, name_address = 0;
            int32_t push_relative = 0, set_relative = 0;
            std::memcpy(&callback, bytes + 3, 4);
            std::memcpy(&name_address, bytes + 14, 4);
            std::memcpy(&push_relative, bytes + 9, 4);
            std::memcpy(&set_relative, bytes + 25, 4);
            std::string canonical;
            for (const std::string& name : {enc("spawn"), enc("Spawn"), enc("delay"), enc("Delay"), enc("wait"), enc("Wait"), enc("ypcall"), enc("loadstring")})
            {
                char actual[12] = {};
                size_t length = name.size() + 1;
                if (read_memory(name_address, actual, length) && std::memcmp(actual, name.c_str(), length) == 0)
                {
                    canonical = name;
                    break;
                }
            }
            if (canonical.empty()) continue;
            uintptr_t current_push = region.address + offset + 13 + push_relative;
            uintptr_t current_set = region.address + offset + 29 + set_relative;
            if (!executable(callback) || !executable(current_push) || !executable(current_set)) return false;
            if ((push_address && push_address != current_push) || (set_address && set_address != current_set)) return false;
            push_address = current_push;
            set_address = current_set;
            for (const auto& entry : native_globals)
                if (entry.name == canonical && entry.callback != callback) return false;
            native_globals.push_back({canonical, callback});
        }
    }
    uintptr_t string_address = 0, table_address = 0;
    auto target = [](const region_data& region, size_t call)
    {
        int32_t relative = 0;
        std::memcpy(&relative, region.bytes.data() + call + 1, 4);
        return region.address + call + 5 + relative;
    };
    auto record = [&](const std::string& name, uint32_t callback, uintptr_t push, uintptr_t setter, uintptr_t stringer)
    {
        if (!executable(callback) || !executable(push) || !executable(setter) || (stringer && !executable(stringer))) return false;
        if (push_address && push_address != push) return false;
        push_address = push;
        if (stringer)
        {
            if ((string_address && string_address != stringer) || (table_address && table_address != setter)) return false;
            string_address = stringer;
            table_address = setter;
        }
        else
        {
            if (set_address && set_address != setter) return false;
            set_address = setter;
        }
        for (const auto& entry : native_globals)
            if (entry.name == name && entry.callback != callback) return false;
        native_globals.push_back({name, callback});
        return true;
    };
    for (const auto& region : regions)
    {
        const auto& b = region.bytes;
        for (size_t at = 24; at + 112 <= b.size(); ++at)
        {
            if (b[at] != 0x68) continue;
            uint32_t address = 0;
            std::memcpy(&address, b.data() + at + 1, 4);
            std::string name;
            for (const std::string& candidate : {enc("spawn"), enc("Spawn"), enc("delay"), enc("Delay"), enc("wait"), enc("Wait"), enc("ypcall"), enc("loadstring")})
            {
                char value[12] = {};
                if (read_memory(address, value, candidate.size() + 1) && std::memcmp(value, candidate.c_str(), candidate.size() + 1) == 0)
                {name = candidate; break;}
            }
            if (name.empty()) continue;
            if (b[at + 5] == 0x68 && b[at + 6] == 0xee && b[at + 7] == 0xd8 &&
                b[at + 8] == 0xff && b[at + 9] == 0xff && b[at + 10] >= 0x50 && b[at + 10] <= 0x57 && b[at + 11] == 0xe8)
            {
                for (size_t c = at - 24; c + 12 <= at; ++c)
                {
                    size_t argument = b[c] == 0x53 ? c + 1 : c + 2;
                    if (!(b[c] == 0x53 || (b[c] == 0x6a && b[c + 1] == 0)) || b[argument] != 0x68 ||
                        b[argument + 5] < 0x50 || b[argument + 5] > 0x57 || b[argument + 6] != 0xe8 || argument + 11 > at) continue;
                    uint32_t callback = 0;
                    std::memcpy(&callback, b.data() + argument + 1, 4);
                    if (!record(name, callback, target(region, argument + 6), target(region, at + 11), 0)) return false;
                }
            }
            if (b[at + 5] < 0x50 || b[at + 5] > 0x57 || b[at + 6] != 0xe8) continue;
            uintptr_t stringer = target(region, at + 6);
            for (size_t c = at + 11; c < at + 40; ++c)
            {
                size_t argument = b[c] == 0x53 ? c + 1 : c + 2;
                if (!(b[c] == 0x53 || (b[c] == 0x6a && b[c + 1] == 0)) || b[argument] != 0x68 ||
                    b[argument + 5] < 0x50 || b[argument + 5] > 0x57 || b[argument + 6] != 0xe8) continue;
                uint32_t callback = 0;
                std::memcpy(&callback, b.data() + argument + 1, 4);
                for (size_t g = argument + 11; g < argument + 28; ++g)
                {
                    if (b[g] != 0x68 || b[g + 1] != 0xee || b[g + 2] != 0xd8 || b[g + 3] != 0xff || b[g + 4] != 0xff) continue;
                    size_t call = g + 5;
                    if (b[call] == 0x8b && (b[call + 1] & 0xc0) == 0x80) call += 6;
                    if (b[call] < 0x50 || b[call] > 0x57 || b[call + 1] != 0xe8) continue;
                    if (!record(name, callback, target(region, argument + 6), target(region, call + 1), stringer)) return false;
                    break;
                }
                break;
            }
        }
    }
    bool has_wait = false;
    for (const auto& entry : native_globals)
        if (entry.name == enc("wait") || entry.name == enc("Wait")) has_wait = true;
    if (!has_wait) return false;
    pushclosure = reinterpret_cast<pushclosure_fn>(push_address);
    setfield = reinterpret_cast<setfield_fn>(set_address);
    pushstring = reinterpret_cast<pushstring_fn>(string_address);
    settable = reinterpret_cast<settable_fn>(table_address);
    return pushclosure && (setfield || (pushstring && settable));
}

using pushbytes_fn = void(__cdecl*)(int, const char*, size_t);
pushbytes_fn pushbytes = nullptr;
uintptr_t native_compiler = 0;
int __cdecl compile_native_source(int state, char* source, size_t size, char* name)
{
    int before = lua::gettop(state);
    pushclosure(state, native_compiler, 0);
    pushbytes(state, source, size);
    pushbytes(state, name, std::strlen(name));
    int status = lua::pcall(state, 2, -1, 0);
    if (status != 0) return status;
    return lua::gettop(state) == before + 1 ? 0 : 3;
}

uintptr_t find_address(const std::vector<region_data>& regions, uintptr_t, const char* name, std::initializer_list<const char*> patterns, bool report = true)
{
    std::vector<uintptr_t> matches;
    for (const char* text : patterns)
    {
        std::vector<int> pattern;
        std::istringstream stream(text);
        std::string token;
        while (stream >> token)
            pattern.push_back(token == enc("??").c_str() ? -1 : static_cast<int>(std::strtoul(token.c_str(), nullptr, 16)));
        for (const region_data& region : regions)
        {
            if (pattern.empty() || region.bytes.size() < pattern.size())
                continue;
            for (size_t offset = 0; offset <= region.bytes.size() - pattern.size(); ++offset)
            {
                bool matched = true;
                for (size_t index = 0; index < pattern.size(); ++index)
                {
                    if (pattern[index] >= 0 && region.bytes[offset + index] != pattern[index])
                    {
                        matched = false;
                        break;
                    }
                }
                if (matched)
                    matches.push_back(region.address + offset);
            }
        }
    }
    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    if (matches.size() == 1)
    {
        if (report) ui::writef(enc("ADDR_%s = 0x%08lX\n").c_str(), name, static_cast<unsigned long>(matches[0]));
        return matches[0];
    }
    return 0;
}
}

bool lua::bind_native_globals(int state)
{
    if (legacy::uses_native_environment())
    {
        std::string check = enc("if type(spawn) ~= 'function' or type(wait) ~= 'function' or type(delay) ~= 'function' or type(pcall) ~= 'function' then error('Missing native globals') end");
        int status = loadbuffer(state, &check[0], check.size(), &check[0]);
        if (status == 0) status = pcall(state, 0, 0, 0);
        return status == 0;
    }
    if (!pushclosure || (!setfield && (!pushstring || !settable))) return false;
    auto install = [&](uintptr_t callback, const char* name)
    {
        if (setfield)
        {
            pushclosure(state, callback, 0);
            setfield(state, -10002, name);
        }
        else
        {
            pushstring(state, name);
            pushclosure(state, callback, 0);
            settable(state, -10002);
        }
    };
    for (const auto& entry : native_globals)
    {
        install(entry.callback, entry.name.c_str());
    }
    for (const auto& entry : native_globals)
    {
        if (entry.name == enc("Spawn"))
        {
            install(entry.callback, enc("spawn").c_str());
        }
        if (entry.name == enc("Wait") || entry.name == enc("Delay"))
        {
            install(entry.callback, entry.name == enc("Wait") ? enc("wait").c_str() : enc("delay").c_str());
        }
        if (entry.name == enc("ypcall"))
        {
            install(entry.callback, enc("pcall").c_str());
        }
    }
    return true;
}

bool lua::initialize()
{
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    std::vector<region_data> regions = get_regions(base);
    
    loadbuffer = reinterpret_cast<loadbuffer_fn>(find_address(regions, base, enc("LOADBUFFER").c_str(), {
        enc("83 EC 08 8B 44 24 10 8B 54 24 18 8B 4C 24 14 52 89 44 24 04 8D 44 24 04 50 89 4C 24 0C 8B 4C 24 14 68 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 18 C3").c_str()
    }, false));
    if (loadbuffer)
        ui::writef(enc("ADDR_LOADBUFFER = 0x%08lX\n").c_str(), static_cast<unsigned long>(reinterpret_cast<uintptr_t>(loadbuffer)));
    else
    {
    lua_load = reinterpret_cast<lua_load_fn>(find_address(regions, base, enc("LOAD").c_str(), {
        enc("83 EC 14 56 57 8B 7C 24 2C 85 FF 75 05 BF ?? ?? ?? ?? 8B 44 24 28 8B 4C 24 24 8B 74 24 20 50 51 8D 54 24 10 52 56 E8 ?? ?? ?? ?? 57 8D 44 24 1C 50 56 E8 ?? ?? ?? ?? 83 C4 1C 5F 5E 83 C4 14 C3").c_str(),
        enc("55 8B EC 8B 45 14 83 EC 14 85 C0 57 FF 75 10 BF ?? ?? ?? ?? FF 75 0C 0F 45 F8").c_str(),
        enc("55 8B EC 8B 45 14 83 EC 14 85 C0 56 57 FF 75 10 8B 7D 08 FF 75 0C BE ?? ?? ?? ?? 0F 45 F0").c_str(),
        enc("55 8B EC 8B 45 14 83 EC 14 85 C0 56 8B 75 08 57 FF 75 10 BF ?? ?? ?? ?? FF 75 0C 0F 45 F8").c_str()
    }));
    loadbuffer = lua_load ? load_source : nullptr;
    }
    pcall = reinterpret_cast<pcall_fn>(find_address(regions, base, enc("PCALL").c_str(), {
        enc("8B 44 24 10 83 EC 08 85 C0 56 8B 74 24 10 75 ?? 33 C9 EB ?? 8B CE E8 ?? ?? ?? ?? 2B 46 20 8B C8").c_str(),
        enc("8B 44 24 10 83 EC 08 56 8B 74 24 10 85 C0 75 ?? 33 C9 EB ?? 8B CE E8 ?? ?? ?? ?? 2B 46 20 8B C8").c_str(),
        enc("55 8B EC 8B 45 14 83 EC 08 57 8B 7D 08 85 C0 75 04 33 D2 EB 0F 50 57 E8 ?? ?? ?? ?? 8B D0 83 C4 08 2B 57 ?? 8B 4D 0C 8B 47 ?? 41 56 8B 75 10 C1 E1 04").c_str(),
        enc("55 8B EC 8B 45 14 83 EC 08 53 56 57 8B 7D 08 85 C0 75 ?? 33 D2 EB ?? 50 57 E8 ?? ?? ?? ?? 8B D0 83 C4 08 2B 57 18").c_str()
    }));
    gettop = reinterpret_cast<gettop_fn>(find_address(regions, base, enc("GETTOP").c_str(), {
        enc("8B 4C 24 04 8B 41 08 2B 41 0C C1 F8 04 C3").c_str(),
        enc("55 8B EC 8B 4D 08 8B 41 10 2B 41 1C C1 F8 04 5D C3").c_str(),
        enc("55 8B EC 8B 4D 08 8B 41 08 2B 41 0C C1 F8 04 5D C3").c_str()
    }));
    settop = reinterpret_cast<settop_fn>(find_address(regions, base, enc("SETTOP").c_str(), {
        enc("55 8B EC 8B 4D 0C 8B 55 08 85 C9 78 35 8B 42 1C C1 E1 04 03 C1 39 42 10 73 1E").c_str(),
        enc("8B 4C 24 08 85 C9 8B 44 24 04 7C ?? 8B 50 0C C1 E1 04 03 D1 39 50 08 73 ??").c_str(),
        enc("8B 4C 24 08 8B 44 24 04 85 C9 7C ?? 8B 50 0C C1 E1 04 03 D1 39 50 08 73 ??").c_str(),
        enc("55 8B EC 8B 55 0C 8B 45 08 85 D2 78 35 8B 48 1C C1 E2 04 03 CA 39 48 10").c_str(),
        enc("55 8B EC 8B 55 0C 8B 45 08 85 D2 78 35 8B 48 0C C1 E2 04 03 CA 39 48 08").c_str()
    }));
    newthread = reinterpret_cast<newthread_fn>(find_address(regions, base, enc("NEWTHREAD").c_str(), {
        enc("56 8B 74 24 08 8B 46 10 8B 48 44 3B 48 40 72 ?? 56 E8 ?? ?? ?? ?? 83 C4 04 56 E8 ?? ?? ?? ?? 8B 4E 08 89 01 C7 41 08 08 00 00 00").c_str(),
        enc("56 8B 74 24 08 8B 46 10 8B 48 44 3B 48 40 57 72 ?? 56 E8 ?? ?? ?? ?? 83 C4 04 56 E8 ?? ?? ?? ?? 8B F8 8B 46 08 89 38 C7 40 08 08 00 00 00").c_str(),
        enc("56 8B 74 24 08 8B 46 10 8B 48 44 57 3B 48 40 72 ?? 56 E8 ?? ?? ?? ?? 83 C4 04 56 E8 ?? ?? ?? ?? 8B F8 8B 46 08 89 38 C7 40 08 08 00 00 00").c_str(),
        enc("55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B 75 08 57 8B 4E 08 8B 44 31 60 3B 44 31 54").c_str(),
        enc("55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B 75 08 57 8B 4E 10 8B 41 48 3B 41 44").c_str()
    }));
    tolstring = reinterpret_cast<tolstring_fn>(find_address(regions, base, enc("TOLSTRING").c_str(), {
        enc("56 8B 74 24 08 57 8B 7C 24 10 8B C7 8B CE E8 ?? ?? ?? ?? 83 78 08 04 74 ?? 50 56 E8 ?? ?? ?? ??").c_str(),
        enc("55 8B EC 56 8B 75 08 57 FF 75 0C 56 E8 ?? ?? ?? ?? 8B F8 83 C4 08 83 7F 08 04").c_str(),
        enc("55 8B EC 56 FF 75 0C 8B 75 08 56 E8 ?? ?? ?? ?? 8B C8 83 C4 08 83 79 08 04 74 ?? 51 56").c_str(),
        enc("55 8B EC 56 57 FF 75 0C 8B 7D 08 57 E8 ?? ?? ?? ?? 8B F0 83 C4 08 83 7E 08 04 74 ?? 56 57").c_str()
    }));
    resume = reinterpret_cast<resume_fn>(find_address(regions, base, enc("RESUME").c_str(), {
        enc("56 8B 74 24 08 8A 46 06 3C 01 74 24 84 C0 74 0C BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5E C3 8B 46 14 3B 46 28 74 0C BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5E C3").c_str(),
        enc("55 8B EC 83 EC 08 56 8B 75 08 8A 46 06 3C 01 74 1F 84 C0 75 08 8B 46 14 3B 46 28 74 13 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 08 5E 8B E5 5D C3 B8 C8 00 00 00").c_str(),
        enc("56 8B 74 24 08 8A 46 06 3C 01 74 18 84 C0 75 08 8B 46 14 3B 46 28 74 0C BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5E C3 B9 C8 00 00 00").c_str(),
        enc("55 8B EC 56 8B 75 08 8A 46 06 3C 01 74 1D 84 C0 75 08 8B 46 ?? 3B 46 28 74 11 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 08 5E 5D C3 B8 C8 00 00 00").c_str()
    }));
    if (!newthread)
        newthread = reinterpret_cast<newthread_fn>(find_address(regions, base, enc("NEWTHREAD").c_str(), {
            enc("55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 56 8B 75 08 57 8B 4E 10 8B 41 48 3B 41 44 72 ?? 56 E8 ?? ?? ?? ?? 83 C4 04 56 E8 ?? ?? ?? ?? 8B 4E 08 8B F8 83 C4 04 89 39 C7 41 08 08 00 00 00").c_str()
        }));
    uintptr_t compiler_stub = find_address(regions, base, enc("PARSER").c_str(), {
        enc("55 8B EC 68 ?? ?? ?? ?? FF 75 08 E8 ?? ?? ?? ?? 6A 03 FF 75 08 E8 ?? ?? ?? ?? 83 C4 10 33 C0 5D C3").c_str()
    }, false);
    if (compiler_stub && legacy::initialize(base))
    {
        loadbuffer = legacy::loadbuffer;
        compiler_stub = 0;
    }
    if (compiler_stub)
        ui::error(enc("This client has no source compiler"));
    bool globals_ready = legacy::uses_native_environment() || find_native_globals(regions);
    if (!loadbuffer && globals_ready)
    {
        for (const auto& entry : native_globals)
            if (entry.name == enc("loadstring")) native_compiler = entry.callback;
        pushbytes = reinterpret_cast<pushbytes_fn>(find_address(regions, base, enc("PUSHLSTRING").c_str(), {
            enc("55 8B EC 56 57 8B 7D 08 8B 4F 10 8B 41 48 3B 41 44 72 ?? 57 E8 ?? ?? ?? ?? 83 C4 04 FF 75 10 8B 77 08 FF 75 0C 57 E8 ?? ?? ?? ?? 83 C4 0C 89 06 C7 46 08 04 00 00 00 83 47 08 10").c_str()
        }));
        if (pushbytes && native_compiler) loadbuffer = compile_native_source;
    }
    if (!globals_ready) ui::error(enc("Can't bind native globals."));
    if (!loadbuffer || !pcall || !resume || !gettop || !settop || !newthread || !tolstring)
        ui::error(enc("Failed to initialize"));
    bool ready = globals_ready && loadbuffer && pcall && resume && gettop && settop && newthread && tolstring && !compiler_stub;
    
    return ready;
}