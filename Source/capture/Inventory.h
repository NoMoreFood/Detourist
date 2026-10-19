#pragma once
#include "WinSupport.h"
#include <vector>

namespace Detourist
{
struct ProcessInfo
{
    DWORD id;
    std::wstring name;
    std::wstring architecture;
};
struct ExportInfo
{
    std::string name;
    uint32_t ordinal;
    uint32_t rva;
    std::string forwarder;
    bool executable;
};
std::vector<ProcessInfo> Processes();
std::vector<ExportInfo> ReadExports(const std::wstring& file);
}
