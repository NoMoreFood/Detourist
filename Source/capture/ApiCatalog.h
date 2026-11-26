#pragma once
#include "CatalogView.h"
#include <string>

namespace Detourist
{
std::wstring ArchitectureDirectory(uint32_t pointerSize);
enum class CatalogUse { Metadata, Capture, Refresh };
void PrepareApiCatalog(CatalogUse use = CatalogUse::Capture, uint32_t pointerSize = sizeof(void*));
const std::wstring& CaptureCatalogName(uint32_t pointerSize = sizeof(void*));
}
