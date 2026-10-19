#pragma once
#include "CatalogView.h"
#include <string>

namespace Detourist
{
std::wstring ArchitectureDirectory(uint32_t pointerSize);
void PrepareApiCatalog(bool refresh = false, uint32_t pointerSize = sizeof(void*));
const std::wstring& CaptureCatalogName(uint32_t pointerSize = sizeof(void*));
}
