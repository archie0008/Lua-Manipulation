#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace legacy
{
bool compile(const char* source, size_t size, const char* name,
             uint32_t inverse_key, std::vector<unsigned char>& output, std::string& error, bool encrypt_operands = true);
std::vector<unsigned char> package(const std::vector<unsigned char>& bytecode);
uint32_t decode_instruction(uint32_t instruction, uint32_t pc);
uint32_t inverse_odd(uint32_t key);
bool initialize(uintptr_t module);
bool uses_native_environment();
int __cdecl loadbuffer(int state, char* source, size_t size, char* name);
}