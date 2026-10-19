#pragma once
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace Detourist::Tests
{
inline auto GuardedPages(size_t pageBytes, DWORD protection, size_t pairs = 1)
{
    if (!pairs || !pageBytes || pairs > SIZE_MAX / pageBytes / 2)
        throw std::runtime_error("Invalid protected test region");
    auto release = [](std::byte* address) { VirtualFree(address, 0, MEM_RELEASE); };
    std::unique_ptr<std::byte, decltype(release)> pages(static_cast<std::byte*>(
        VirtualAlloc(nullptr, pairs * 2 * pageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)), release);
    DWORD previous = 0;
    if (!pages) throw std::runtime_error("Cannot allocate protected test pages");
    for (size_t index = 0; index < pairs; ++index)
        if (!VirtualProtect(pages.get() + (2 * index + 1) * pageBytes, pageBytes, protection, &previous))
            throw std::runtime_error("Cannot protect test page");
    return pages;
}
}
