#include "PE.h"
#include "GeneralFile.h"



#define to_ptr(ptr, off) ((void*)(((char*)(ptr)) + (off)))


PE::PE()
	:m_imageBuffer(nullptr), m_isDisk(true)
{
}

PE::PE(const char* filepath)
	:PE()
{
	GeneralFile file(filepath, std::ios::in | std::ios::binary);
	m_file_size = file.GetFileSize();
	void* buffer = calloc(m_file_size, 1);
	file.Read(buffer, m_file_size);
	m_isDisk = true;

	Attach(buffer);

}

PE::~PE()
{
	if (m_isDisk)
	{
		free(m_imageBuffer);
	}
}

void PE::Attach(void* imagebase)
{
	m_imageBuffer = imagebase;

	Parse();
}

bool PE::IsValid() const
{
	if (m_imageBuffer == NULL)
		return false;

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)m_imageBuffer;
	PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)to_ptr(dos, dos->e_lfanew);

	if (dos->e_magic == 'ZM' && nt && nt->Signature == 'EP')
		return true;
	return false;
}

bool PE::Is64Bit()
{
	return m_peinfo.is_64bit;
}

int PE::dump(const char* destpath)
{
	GeneralFile file(destpath, std::ios::out | std::ios::binary);
	
	return 0;
}

void PE::ResetImport(std::list<ImportDir>& importDirs)
{
	m_peinfo.import_dir = std::move(importDirs);
}

uint32_t PE::rva_to_fa(PIMAGE_SECTION_HEADER sects, size_t count, uint32_t rva)
{
	for (size_t i = 0; i < count; i++)
	{
		if (rva >= sects[i].VirtualAddress && rva < (sects[i].VirtualAddress + sects[i].Misc.VirtualSize))
		{
			return rva - sects[i].VirtualAddress + sects[i].PointerToRawData;
		}
	}

	return 0;
}

inline void* PE::ptr(uint32_t rva)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)m_imageBuffer;
	PIMAGE_SECTION_HEADER Sects = nullptr;
	int sectCount = 0;

	if (Is64Bit())
	{
		PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)to_ptr(dos, dos->e_lfanew);
		Sects = IMAGE_FIRST_SECTION(nt64);
		sectCount = nt64->FileHeader.NumberOfSections;
	}
	else
	{
		PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)to_ptr(dos, dos->e_lfanew);
		Sects = IMAGE_FIRST_SECTION(nt);
		sectCount = nt->FileHeader.NumberOfSections;
	}

	return to_ptr(m_imageBuffer, rva_to_fa(Sects, sectCount, rva));
}

int PE::Parse()
{
	if (!IsValid())
		return -1;

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)m_imageBuffer;
	PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)to_ptr(dos, dos->e_lfanew);
	PIMAGE_DATA_DIRECTORY data_dir = nullptr;
	uint32_t dir_count = 0;
	PIMAGE_SECTION_HEADER Sects = nullptr;

	m_peinfo.is_64bit = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && nt->FileHeader.Machine  == IMAGE_FILE_MACHINE_AMD64;

	if (!Is64Bit())
	{
		IMAGE_OPTIONAL_HEADER32& opt32 = nt->OptionalHeader;
		m_peinfo.entrypoint = nt->OptionalHeader.AddressOfEntryPoint;
		m_peinfo.file_align = opt32.FileAlignment;
		m_peinfo.section_align = opt32.SectionAlignment;
		m_peinfo.image_base = opt32.ImageBase;
		m_peinfo.image_size = opt32.SizeOfImage;
		data_dir = opt32.DataDirectory;
		dir_count = opt32.NumberOfRvaAndSizes;
		Sects = IMAGE_FIRST_SECTION(nt);
	}
	else
	{
		PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)nt;

		IMAGE_OPTIONAL_HEADER64& opt64 = nt64->OptionalHeader;
		m_peinfo.entrypoint = nt->OptionalHeader.AddressOfEntryPoint;
		m_peinfo.file_align = opt64.FileAlignment;
		m_peinfo.section_align = opt64.SectionAlignment;
		m_peinfo.image_base = opt64.ImageBase;
		m_peinfo.image_size = opt64.SizeOfImage;
		data_dir = opt64.DataDirectory;
		dir_count = opt64.NumberOfRvaAndSizes;
		Sects = IMAGE_FIRST_SECTION(nt64);
	}

	for (size_t i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		Section sect;
		memcpy(sect.name, (void*)Sects[i].Name, sizeof(sect.name));
		sect.data = calloc(Sects[i].SizeOfRawData, 1);
		memcpy(sect.data, to_ptr(m_imageBuffer, Sects[i].PointerToRawData), Sects[i].SizeOfRawData);
		sect.size = Sects[i].SizeOfRawData;
		sect.flags = Sects[i].Characteristics;
		m_peinfo.sections.emplace_back(sect);
	}

	PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)(ptr(data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
	IMAGE_IMPORT_DESCRIPTOR zerobuffer;
	memset(&zerobuffer, 0, sizeof(zerobuffer));

	while (memcmp(import, &zerobuffer, sizeof(zerobuffer)) != 0)
	{
		ImportDir importItem;
		strcpy(importItem.name, (char*)ptr(import->Name));
		
		uint32_t int_rva = import->OriginalFirstThunk == 0 ? import->FirstThunk : import->OriginalFirstThunk;

		if (!Is64Bit())
		{
			uint32_t* INT = (uint32_t*)ptr(int_rva);

			while (*INT != 0)
			{
				if (*INT > MAXSHORT)
				{
					PIMAGE_IMPORT_BY_NAME improtname = (PIMAGE_IMPORT_BY_NAME)ptr(*INT);
					importItem.import_func.emplace_back(strdup(improtname->Name));
				}
				else
				{
					importItem.import_func.emplace_back((ptr_t)*INT);
				}
				INT++;
			}
		}
		else
		{
			uint64_t* INT64 = (uint64_t*)ptr(int_rva);

			while (!INT64 != 0)
			{
				if (*INT64 > MAXSHORT)
				{
					PIMAGE_IMPORT_BY_NAME improtname = (PIMAGE_IMPORT_BY_NAME)ptr(*INT64);
					importItem.import_func.emplace_back(strdup(improtname->Name));
				}
				else
				{
					importItem.import_func.emplace_back(*INT64);
				}
				INT64++;
			}
		}

		m_peinfo.import_dir.emplace_back(importItem);
		import++;
	}

	return 0;
}

void* PE::AddSection(const char* sect_name, size_t sect_size, size_t sect_flags)
{
	Section newSection;
	strncpy((char*)newSection.name, sect_name, IMAGE_SIZEOF_SHORT_NAME);
	newSection.data = calloc(sect_size, 1);
	newSection.size = sect_size;
	newSection.flags = sect_flags;

	m_peinfo.sections.emplace_back(newSection);
	return newSection.data;
}
