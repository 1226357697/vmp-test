#include "GeneralFile.h"
#include <cassert>

GeneralFile::GeneralFile()
{
	m_fullPath[0] = '\0';
}

GeneralFile::GeneralFile(const char* filepath, std::ios::openmode mode)
	:GeneralFile()
{
	Open(filepath, mode);
}

GeneralFile::~GeneralFile()
{
	m_fs.close();
}

bool GeneralFile::Open(const char* filepath, std::ios::openmode mode)
{
	assert(strlen(filepath) < _MAX_PATH_);
	if (IsOpen())
		return 0;
	
	strcpy(m_fullPath, filepath);
	m_fs = std::fstream(filepath, mode);
	return m_fs.is_open();
}

size_t GeneralFile::Read(void* buffer, size_t size) noexcept
{
	if (!IsOpen())
		return 0;
	
	return m_fs.read(static_cast<char*>(buffer), size).gcount();
}

size_t GeneralFile::Write(void* buffer, size_t size) noexcept
{
	if (!IsOpen())
		return 0;

	m_fs.write(static_cast<char*>(buffer), size).flush();
	
	return size;
}

size_t GeneralFile::GetFileSize() const 
{
	if (!IsOpen())
		return 0;

	size_t curpos = GetFilePointPos();

	size_t filesize = _SetFilePointPos(0, std::ios::end);

	_SetFilePointPos(curpos, std::ios::beg);

	return filesize;
}

size_t GeneralFile::_SetFilePointPos(size_t offset, std::ios::seekdir pos) const
{
	if (!IsOpen())
		return 0;

	m_fs.seekg(offset, pos);
	m_fs.seekp(offset, pos);

	return GetFilePointPos();
}

size_t GeneralFile::GetFilePointPos() const
{
	if (!IsOpen())
		return 0;

	return m_fs.tellg();
}
