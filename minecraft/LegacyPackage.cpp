#ifdef _WIN32
#include "stdafx.h"
#endif
#include "LegacyCompiler.h"
#include <cstring>
namespace legacy
{
namespace
{
uint32_t rotate(uint32_t value, unsigned shift) { return (value << shift) | (value >> (32 - shift)); }
uint32_t read_word(const unsigned char* p)
{
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
uint32_t hash32(const std::vector<unsigned char>& bytes)
{

    constexpr uint32_t p1=0x9e3779b1u,p2=0x85ebca77u,p3=0xc2b2ae3du,p4=0x27d4eb2fu,p5=0x165667b1u;
    size_t offset=0;
    uint32_t hash;
    if (bytes.size() >= 16)
    {
        constexpr uint64_t seed=42;
        constexpr uint64_t modulus=uint64_t(1)<<32;
        constexpr uint64_t mask=modulus-1;
        uint32_t lanes[4]={
            static_cast<uint32_t>((seed+p1+p2)&mask),
            static_cast<uint32_t>((seed+p2)&mask),
            static_cast<uint32_t>(seed),
            static_cast<uint32_t>((modulus+seed-p1)&mask)
        };
        do
        {
            for (unsigned i=0;i<4;++i) {lanes[i]=rotate(lanes[i]+read_word(bytes.data()+offset)*p2,13)*p1;offset+=4;}
        } while (offset+16<=bytes.size());
        hash=rotate(lanes[0],1)+rotate(lanes[1],7)+rotate(lanes[2],12)+rotate(lanes[3],18);
    }
    else hash=42u+p5;
    hash+=static_cast<uint32_t>(bytes.size());
    while (offset+4<=bytes.size()) {hash=rotate(hash+read_word(bytes.data()+offset)*p3,17)*p4;offset+=4;}
    while (offset<bytes.size()) {hash=rotate(hash+bytes[offset++]*p5,11)*p1;}
    hash^=hash>>15;hash*=p2;hash^=hash>>13;hash*=p3;hash^=hash>>16;
    return hash;
}
}
std::vector<unsigned char> package(const std::vector<unsigned char>& bytecode)
{

    std::vector<unsigned char> raw(1,0);
    raw.insert(raw.end(),bytecode.begin(),bytecode.end());
    std::vector<unsigned char> result={'R','S','B','1'};
    uint32_t size=static_cast<uint32_t>(raw.size());
    for (unsigned i=0;i<4;++i) result.push_back(static_cast<unsigned char>(size>>(8*i)));

    result.push_back(static_cast<unsigned char>((raw.size()<15?raw.size():15)<<4));
    if (raw.size()>=15)
    {
        size_t remaining=raw.size()-15;
        while (remaining>=255) {result.push_back(255);remaining-=255;}
        result.push_back(static_cast<unsigned char>(remaining));
    }
    result.insert(result.end(),raw.begin(),raw.end());
    uint32_t hash=hash32(result);
    for (size_t i=0;i<result.size();++i)
        result[i]^=static_cast<unsigned char>((hash>>((i&3)*8))+i*41);
    return result;
}
}
