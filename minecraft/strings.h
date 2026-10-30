#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace strings
{
template<std::size_t size, std::uint8_t key>
struct literal
{
    std::uint8_t data[size] = {};
    constexpr literal(const char (&text)[size])
    {
        for (std::size_t index = 0; index < size; ++index)
            data[index] = static_cast<std::uint8_t>(text[index]) ^ static_cast<std::uint8_t>(key + index * 17);
    }
    std::string reveal() const
    {
        std::string text(size - 1, '\0');
        volatile std::uint8_t seed = key;
        for (std::size_t index = 0; index + 1 < size; ++index)
            text[index] = static_cast<char>(data[index] ^ static_cast<std::uint8_t>(seed + index * 17));
        return text;
    }
};
}
#define enc(text) ([] { static constexpr strings::literal<sizeof(text), static_cast<std::uint8_t>((__COUNTER__ * 37 + 91) % 251 + 1)> value(text); return value.reveal(); }())
