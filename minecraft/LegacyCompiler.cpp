#ifdef _WIN32
#include "stdafx.h"
#endif
#include "LegacyCompiler.h"
#include <cstring>
#include <limits>
#include <stdexcept>
#include <unordered_map>
extern "C" {
#include "lua51/lua.h"
#include "lua51/lauxlib.h"
#include "lua51/lobject.h"
#include "lua51/lstate.h"
#include "lua51/lopcodes.h"
}

namespace legacy
{
namespace
{

constexpr uint8_t opcodes[38] = {
    6,4,0,7,2,8,1,3,5,15,13,9,16,11,17,10,12,14,24,22,18,25,
    20,26,19,21,23,33,31,31,34,29,35,28,30,32,37,36
};
constexpr uint32_t operand_mask = 0x03ffffff;
uint32_t encode_instruction(uint32_t instruction, uint32_t pc)
{
    uint32_t opcode = instruction >> 26;
    if (opcode != 27 && opcode != 31 && opcode != 34 && opcode != 37) return instruction;
    uint32_t target = instruction & operand_mask;
    uint32_t encoded = 0;

    for (unsigned bit = 0; bit < 26; ++bit)
        if (((decode_instruction(encoded | (opcode << 26), pc) ^ target) >> bit) & 1)
            encoded |= uint32_t(1) << bit;
    return encoded | (opcode << 26);
}
struct serializer
{
    std::vector<unsigned char> bytes;
    std::vector<std::string> strings;
    std::unordered_map<std::string, uint32_t> ids;
    uint32_t inverse_key = 1;
    bool encrypt_operands = false;

    void word(uint32_t value)
    {
        for (unsigned i = 0; i < 4; ++i) bytes.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
    uint32_t string_id(const TString* value)
    {
        if (!value) return 0;
        std::string text(getstr(value), value->tsv.len);
        auto found = ids.find(text);
        if (found != ids.end()) return found->second;
        uint32_t id = static_cast<uint32_t>(strings.size() + 1);
        ids.emplace(text, id);
        strings.push_back(text);
        return id;
    }
    void proto(const Proto* p, unsigned depth)
    {
        if (depth > 200) throw std::runtime_error("Lua function nesting is too deep");
        word(p->sizep);
        word(p->sizek);
        word(p->sizecode);
        word(p->sizelocvars);
        word(p->sizelineinfo);
        word(p->sizeupvalues);
        bytes.push_back(p->maxstacksize);
        bytes.push_back(p->is_vararg);
        bytes.push_back(p->nups);
        bytes.push_back(p->numparams);
        for (int i = 0; i < p->sizek; ++i)
        {
            const TValue* k = &p->k[i];
            switch (ttype(k))
            {
            case LUA_TNIL: bytes.push_back(0); break;
            case LUA_TBOOLEAN: bytes.push_back(bvalue(k) ? 2 : 1); break;
            case LUA_TNUMBER:
            {
                static_assert(sizeof(lua_Number) == 8, "Lua numbers must be doubles");
                bytes.push_back(3);
                double number = nvalue(k);
                unsigned char raw[8];
                std::memcpy(raw, &number, 8);
                bytes.insert(bytes.end(), raw, raw + 8);
                break;
            }
            case LUA_TSTRING:
                bytes.push_back(4);
                word(string_id(rawtsvalue(k)));
                break;
            default: throw std::runtime_error("Unsupported Lua constant");
            }
        }
        uint32_t previous_line = 0;
        for (int i = 0; i < p->sizelineinfo; ++i)
        {
            uint32_t line = static_cast<uint32_t>(p->lineinfo[i]);
            word(line - previous_line);
            previous_line = line;
        }
        for (int i = 0; i < p->sizelocvars; ++i)
        {
            word(p->locvars[i].startpc);
            word(p->locvars[i].endpc);
            word(string_id(p->locvars[i].varname));
        }
        for (int i = 0; i < p->sizeupvalues; ++i) word(string_id(p->upvalues[i]));
        bool raw_setlist = false;
        for (int i = 0; i < p->sizecode; ++i)
        {
            uint32_t original = static_cast<uint32_t>(p->code[i]);
            if (raw_setlist)
            {
                word(original * inverse_key);
                raw_setlist = false;
                continue;
            }
            unsigned op = GET_OPCODE(original);
            if (op >= 38) throw std::runtime_error("Unsupported Lua opcode");
            uint32_t instruction = uint32_t(opcodes[op]) << 26;
            instruction |= uint32_t(GETARG_A(original)) << 18;
            if (getOpMode(static_cast<OpCode>(op)) == iABC)
            {
                instruction |= uint32_t(GETARG_B(original));
                instruction |= uint32_t(op == OP_MOVE ? 1 : GETARG_C(original)) << 9;
            }
            else instruction |= uint32_t(GETARG_Bx(original));
            raw_setlist = op == OP_SETLIST && GETARG_C(original) == 0;
            if (encrypt_operands) instruction = encode_instruction(instruction, static_cast<uint32_t>(i));
            word(instruction * inverse_key);
        }
        for (int i = 0; i < p->sizep; ++i) proto(p->p[i], depth + 1);
    }
};
}
uint32_t inverse_odd(uint32_t key)
{
    uint32_t inverse = key;
    for (unsigned i = 0; i < 5; ++i) inverse *= 2u - key * inverse;
    return inverse;
}
uint32_t decode_instruction(uint32_t instruction, uint32_t pc)
{
    uint32_t op = instruction >> 26;
    if (op != 27 && op != 31 && op != 34 && op != 37) return instruction;
    return (op << 26) | (((pc - instruction * 0x1c6b438u) ^
             (instruction * 0x1451afbu - 0x1a7d575u)) & operand_mask);
}
bool compile(const char* source, size_t size, const char* name, uint32_t inverse_key,
             std::vector<unsigned char>& output, std::string& error, bool encrypt_operands)
{
    output.clear();
    error.clear();
    lua_State* L = luaL_newstate();
    if (!L) { error = "Unable to allocate Lua compiler"; return false; }
    try
    {
        int status = luaL_loadbuffer(L, source, size, name);
        if (status != 0)
        {
            const char* message = lua_tostring(L, -1);
            error = message ? message : "Lua compilation failed";
            lua_close(L);
            return false;
        }
        serializer writer;
        writer.inverse_key = inverse_key;
        writer.encrypt_operands = encrypt_operands;
        writer.word(0);
        writer.proto(clvalue(L->top - 1)->l.p, 0);
        if (writer.bytes.size() > (std::numeric_limits<uint32_t>::max)())
            throw std::runtime_error("Compiled script is too large");
        uint32_t string_offset = static_cast<uint32_t>(writer.bytes.size());
        for (unsigned i = 0; i < 4; ++i) writer.bytes[i] = static_cast<unsigned char>(string_offset >> (i * 8));
        writer.word(static_cast<uint32_t>(writer.strings.size()));
        for (const auto& text : writer.strings) writer.word(static_cast<uint32_t>(text.size()));
        for (const auto& text : writer.strings) writer.bytes.insert(writer.bytes.end(), text.begin(), text.end());
        output.swap(writer.bytes);
    }
    catch (const std::exception& ex) { error = ex.what(); }
    lua_close(L);
    return error.empty();
}
}
