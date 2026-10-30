#pragma once
#include <string>
namespace ui
{
void write(const std::string& text);
void error(const std::string& text);
void writef(const char* format, ...);
}
