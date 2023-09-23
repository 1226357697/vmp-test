#pragma once

#include <memory>
#include <list>
#include "IFile.h"
#include "IExecuteFile.h"

#ifndef  WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // ! 

#include <Windows.h>

class PE
{
	using IFilePtr = std::unique_ptr<IFile>;
	
public:
	explicit PE();
	explicit PE(const char* filepath);
	PE(const PE& other) = delete;
	PE(PE& other) = delete;
	PE& operator=(const PE& other) = delete;
	~PE();

	void Attach(void* imagebase);
	bool IsValid()const;
	bool Is64Bit();
	int dump(const char* destpath);

	void ResetImport(std::list<ImportDir>& importDirs);
private:
	uint32_t rva_to_fa(PIMAGE_SECTION_HEADER sects, size_t count, uint32_t rva);
	inline void* ptr(uint32_t rva);
	int Parse();
	//int ParseImport();

	void* AddSection(const char* sect_name, size_t sect_size, size_t sect_flags);


private:
	void* m_imageBuffer;
	size_t m_file_size;
	bool m_isDisk;
	ExecutableInfo m_peinfo;
};

