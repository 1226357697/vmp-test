#pragma once

class IFile
{
public:
	virtual inline bool IsOpen() const  = 0;
	virtual bool Open(const char* filepath, int mode) = 0;
	virtual size_t Read(void* buffer, size_t size) noexcept = 0;
	virtual size_t Write(void* buffer, size_t size) noexcept = 0;
	virtual size_t GetFileSize() const = 0;
	virtual size_t GetFilePointPos() const = 0;
	virtual inline size_t SetFilePointPos(size_t offset, int pos) = 0;
	virtual inline const char* GetFullFilePath()const = 0;
};

