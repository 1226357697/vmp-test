#pragma once
#include <fstream>
#include <cstdint>
#include "IFile.h"

constexpr uint32_t  _MAX_PATH_ = 260;

class GeneralFile : public IFile
{
public:
	explicit GeneralFile();
	explicit GeneralFile(const char* filepath, std::ios::openmode mode = std::ios_base::in | std::ios_base::out);
	explicit GeneralFile(const GeneralFile& other)=default;
	GeneralFile& operator=(const GeneralFile& other) = default;
	explicit GeneralFile(GeneralFile&& other)noexcept { other.m_fs = std::move(m_fs); strcpy(other.m_fullPath, m_fullPath); };
	virtual ~GeneralFile();

	virtual inline bool IsOpen() const override { return m_fs.is_open(); };
	virtual bool Open(const char* filepath, std::ios::openmode mode) override;
	virtual size_t Read(void* buffer, size_t size)  noexcept override;
	virtual size_t Write(void* buffer, size_t size) noexcept override;
	virtual size_t GetFileSize() const  override;
	virtual size_t GetFilePointPos() const  override;
	virtual inline size_t SetFilePointPos (size_t offset, std::ios::seekdir pos) override { return _SetFilePointPos(offset, pos); };
	virtual inline const char* GetFullFilePath()const override { return m_fullPath; };

private:
	size_t _SetFilePointPos(size_t offset, std::ios::seekdir pos)const ;
public:
	mutable std::fstream m_fs;
	char m_fullPath[_MAX_PATH_];
};

