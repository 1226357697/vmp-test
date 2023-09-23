#pragma once
#include <vector>

#pragma warning(disable: 33010)
#pragma warning(disable: 26812)

struct Section_t
{
	uint64_t begin;
	uint32_t size;
};

// int FindPatternAddress(const std::vector<Section_t>& Scetions, /*out*/ std::vector<uint64_t>& Patterns);

int Initialize();

int Destory();

int VmpFixImport();
