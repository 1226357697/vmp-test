#pragma once

#include <list>
#include <cstdint>
#ifdef _WIN64
typedef long long          ptr_t;
#else
typedef long          ptr_t;
#endif

#define IMAGE_SIZEOF_SHORT_NAME 8
constexpr uint32_t  MAX_PATH = 260;

#define ALIGIN_UP(v,a) ((((uint64_t)(v)) + ((a) - 1)) & (~((a) - 1)))

struct FuncInfo
{
	char func_name[260];
	uint32_t rva;
	uint32_t int_rva;
};

union FuncName
{
	FuncName(char* name_) :name(name_) {};
	FuncName(uint16_t ordinal_) :ordinal(ordinal) {};
	char* name;
	uint16_t ordinal;
};

struct ImportDir
{
	char name[MAX_PATH];
	std::list<FuncName> import_func; // 大于MAXSHORT为名称导出(需要手动释放堆内存)，反之为序号导出
};

struct Section
{
	char name[IMAGE_SIZEOF_SHORT_NAME];
	void* data;
	uint32_t size;
	uint32_t flags;
};

struct ExecutableInfo
{
	bool is_64bit;
	// bool is_shard_library;
	ptr_t entrypoint;
	ptr_t image_base;
	uint32_t section_align;
	uint32_t file_align;
	size_t file_size;
	uint32_t image_size;

	std::list<Section> sections;

	std::list<FuncInfo> export_dir;
	std::list<ImportDir> import_dir;

	void* overload_data; //附加数据
	uint32_t overload_size; 
};

class IExecuteFile
{
public:

private:

};