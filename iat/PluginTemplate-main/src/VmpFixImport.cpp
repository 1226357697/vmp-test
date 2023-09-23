#include "VmpFixImport.h"
#include <assert.h>
#include "capstone/capstone.h"
#include "pluginmain.h"
#include <string>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

static thread_local csh g_cshandle = 0;

#define ALIGIN_UP(v,a) ((((uint64_t)(v)) + ((a) - 1)) & (~((a) - 1)))

// (((size) + ALIGN_SIZE - 1) & (~(ALIGN_SIZE - 1)))

int Initialize()
{
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &g_cshandle) != CS_ERR_OK)
		return -1;
	cs_option(g_cshandle, CS_OPT_DETAIL, CS_OPT_ON);
	
	return 0;
}

int Destory()
{
	cs_close(&g_cshandle);

	return 0;
}

static int FindPatternAddress(const std::vector<Section_t>& Scetions, /*out*/ std::vector<uint64_t>& Patterns)
{
	cs_insn* insn = NULL;

	for (const auto& sce : Scetions)
	{
		int PreInsnId = X86_INS_INVALID;
		int InsnSize = 0;
		for (size_t index = 0; index < sce.size; index += InsnSize)
		{
			InsnSize = 1;
			uint8_t insnBuff[0xf];
			bool isRead = Script::Memory::Read((duint)(sce.begin + index), insnBuff, sizeof(insnBuff), NULL);

			if (isRead && cs_disasm(g_cshandle, insnBuff, sizeof(insnBuff), sce.begin + index, 1, &insn))
			{
				if (X86_INS_PUSH == PreInsnId 
					&& X86_INS_CALL == insn[0].id 
					&& insn[0].detail->x86.op_count == 1 
					&& insn[0].detail->x86.operands[0].type == X86_OP_IMM)
				{
					Patterns.emplace_back(insn[0].address);
				}

				PreInsnId = insn[0].id;
				InsnSize = insn[0].size;
				cs_free(insn, 1);
			}
		}
		
	}

	return 0;
}

static int GetCodeScetion(std::vector<Section_t>& Sections)
{
	// 遍历节表， 获取有可执行的代码段
	using namespace Script::Memory;

	uint64_t ModuleBase = Script::Module::GetMainModuleBase();
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ModuleBase;
	PIMAGE_NT_HEADERS pNt = ReadWord((duint)&pDos->e_magic) != 'ZM' ? NULL : (PIMAGE_NT_HEADERS)(ModuleBase + ReadDword((duint)&pDos->e_lfanew));

	if (pNt == NULL || ReadDword((duint)&pNt->Signature) != 'EP')
	{
		_plugin_logputs("不是有效的PE文件格式");
		return -1;
	}

	PIMAGE_FILE_HEADER pFileHdr = (PIMAGE_FILE_HEADER)&pNt->FileHeader;
	PIMAGE_SECTION_HEADER pSect = (PIMAGE_SECTION_HEADER)((duint)&pNt->OptionalHeader + ReadWord((duint)&pFileHdr->SizeOfOptionalHeader));
	WORD wNumberOfSection = ReadWord((duint)&pFileHdr->NumberOfSections);

	for (WORD i = 0; i < wNumberOfSection; i++)
	{
		// 60000020
		constexpr uint32_t Flags = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

		//if ((ReadDword((duint)&pSect[i].Characteristics) & Flags) == Flags)
		if (ReadDword((duint)&pSect[i].Characteristics) == Flags)
		{
			Sections.push_back({ ModuleBase + ReadWord((duint)&pSect[i].VirtualAddress) ,  ReadWord((duint)&pSect[i].Misc.VirtualSize) });
		}
	}

#ifdef _DEBUG
	_plugin_logputs(u8"代码段:");
	for (const auto& sect : Sections)
	{
		_plugin_logprintf("VA:%p  Size:%08X\n", sect.begin, sect.size);

	}
#endif // _DEBUG

	return 0;
}

static int GetExportFunctionAddress(std::vector<uint64_t> MatchCalls, std::vector<uint64_t>& ExportFunctions)
{

	cs_insn* insn = NULL;
	uint8_t CodeBuffer[16];

	for (const auto& Addr : MatchCalls)
	{
		bool isRead = Script::Memory::Read(Addr, CodeBuffer, sizeof(CodeBuffer), NULL);
		size_t Count = cs_disasm(g_cshandle, CodeBuffer, sizeof(CodeBuffer), Addr, 1, &insn);

		if (isRead && Count == 1)
		{
			if (insn[0].id == X86_INS_CALL && insn[0].detail->x86.op_count == 1 && insn[0].detail->x86.operands[0].type == X86_OP_IMM)
			{
				// uint32_t JmpOffset = insn[0].detail->x86.operands[0].imm ;
				uint32_t TargetAddress = insn[0].detail->x86.operands[0].imm;

				// 一直循环匹配特征，直到ret， 匹配到则判断reg的值为导出函数的地址。
				// call imm32
				// mov reg, imm32
				// mov reg, dword ptr ss:[reg+0x960D5]
				// lea reg, ss:[reg+0x259128DA]
				// push reg / xchg [esp], reg
				// ret

				uint64_t ExportFunctionAddress = -1;
				x86_reg tempRegId = X86_REG_INVALID;
				int InsnId = X86_INS_INVALID;
				do
				{
					uint32_t CodeSize = 1;
					isRead = Script::Memory::Read(TargetAddress, CodeBuffer, sizeof(CodeBuffer), NULL);
					Count = cs_disasm(g_cshandle, CodeBuffer, sizeof(CodeBuffer), TargetAddress, 1, &insn);

					if (isRead && Count == 1)
					{
						InsnId = insn[0].id;
						CodeSize = insn[0].size;

						if (insn[0].id == X86_INS_JMP && insn[0].detail->x86.op_count == 1  && insn[0].detail->x86.operands[0].type == X86_OP_IMM)
						{
							CodeSize = 0;
							TargetAddress = insn[0].detail->x86.operands[0].imm;
						}
						else if (insn[0].detail->x86.op_count == 2 && insn[0].detail->x86.operands[0].type == X86_OP_REG)
						{
							if (insn[0].id == X86_INS_MOV)
							{
								if (insn[0].detail->x86.operands[1].type == X86_OP_IMM)
								{
									tempRegId = insn[0].detail->x86.operands[0].reg;
									ExportFunctionAddress = insn[0].detail->x86.operands[1].imm;
								}
								else if (tempRegId == insn[0].detail->x86.operands[0].reg 
									&& tempRegId == insn[0].detail->x86.operands[0].reg
									&& insn[0].detail->x86.operands[1].type == X86_OP_MEM)
								{
									ExportFunctionAddress += insn[0].detail->x86.operands[1].mem.disp;
									uint32_t ApiOffset = Script::Memory::ReadDword(ExportFunctionAddress);
									ExportFunctionAddress = ApiOffset;
								}
							}
							else if (tempRegId == insn[0].detail->x86.operands[0].reg
								&& insn[0].id == X86_INS_LEA
								&& insn[0].detail->x86.operands[1].type == X86_OP_MEM)
							{
								// 判定是一个vmp的IAT加密结束
								ExportFunctionAddress += insn[0].detail->x86.operands[1].mem.disp;
								ExportFunctions.push_back(ExportFunctionAddress);

								cs_free(insn, 1);
								break;
							}
						}

						cs_free(insn, 1);
					}

					TargetAddress += CodeSize;
					
				} while (InsnId != X86_INS_RET);
				
			}
		}

	}
	
	return 0;
}


struct Import_t
{
	char ModuleName[MAX_MODULE_SIZE];
	std::vector<char*> ExportFuncName;
};


static int AddImportSection(void* Data, size_t Size)
{
	using namespace Script::Module;
	using namespace Script::Memory;

	char TempHead[0x200];
	char Path[MAX_PATH] = {'\0'};
	GetMainModulePath(Path);

	FILE* fd = fopen(Path, "r");
	fseek(fd, 0, SEEK_SET);
	fread(TempHead, 1, sizeof(TempHead), fd);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)TempHead;
	PIMAGE_NT_HEADERS pNT = pDos->e_magic == 'ZM' ? (PIMAGE_NT_HEADERS)((duint)pDos + pDos->e_lfanew-1) : NULL;

	if (pNT == NULL || pNT->Signature != 'EP')
		return -1;
	Size = ALIGIN_UP(Size, pNT->OptionalHeader.FileAlignment);

	fseek(fd, 0, SEEK_END);
	size_t FileSize = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	char* FileBuff = (char*)calloc(FileSize + Size , 1);
	if (FileBuff == NULL)
		return -1;

	fread(FileBuff, 1, FileSize, fd);
	fclose(fd);

	pDos = (PIMAGE_DOS_HEADER)FileBuff;
	pNT = (PIMAGE_NT_HEADERS)((duint)pDos + pDos->e_lfanew-1);
	PIMAGE_FILE_HEADER pFileHdr = (PIMAGE_FILE_HEADER)(&pNT->FileHeader);
	PIMAGE_OPTIONAL_HEADER pOptionHdr = (PIMAGE_OPTIONAL_HEADER)(&pNT->OptionalHeader);
	
	
	
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);

	strcpy((char*)pSection[pFileHdr->NumberOfSections].Name, "fiximpt");

	pSection[pFileHdr->NumberOfSections].PointerToRawData =
		pSection[pFileHdr->NumberOfSections - 1].PointerToRawData + pSection[pFileHdr->NumberOfSections - 1].SizeOfRawData;

	pSection[pFileHdr->NumberOfSections].SizeOfRawData = ALIGIN_UP(Size, pOptionHdr->FileAlignment);

	pSection[pFileHdr->NumberOfSections].VirtualAddress = 
		pSection[pFileHdr->NumberOfSections - 1].VirtualAddress + ALIGIN_UP(pSection[pFileHdr->NumberOfSections - 1].Misc.VirtualSize, pOptionHdr->SectionAlignment);

	pSection[pFileHdr->NumberOfSections].Misc.VirtualSize = ALIGIN_UP(Size, pOptionHdr->SectionAlignment);

	pSection[pFileHdr->NumberOfSections].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

	pOptionHdr->SizeOfImage = 
		ALIGIN_UP(pSection[pFileHdr->NumberOfSections].Misc.VirtualSize + pSection[pFileHdr->NumberOfSections].VirtualAddress, pOptionHdr->SectionAlignment);

	
	// fix importsction
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)Data;
	char buf[sizeof(IMAGE_IMPORT_DESCRIPTOR)];
	memset(buf, 0, sizeof(buf));

	while (memcmp(pImport, buf, sizeof(buf)) != 0)
	{
		uint32_t* pIAT = (uint32_t*)((uint32_t)Data + pImport->FirstThunk);
		uint32_t* pINT = (uint32_t*)((uint32_t)Data + pImport->OriginalFirstThunk);

		while (*pIAT != 0)
		{
			(*pIAT) += pSection[pFileHdr->NumberOfSections].VirtualAddress;
			(*pINT) += pSection[pFileHdr->NumberOfSections].VirtualAddress;
			pIAT++;
			pINT++;
		}

		pImport->OriginalFirstThunk += pSection[pFileHdr->NumberOfSections].VirtualAddress;
		pImport->FirstThunk += pSection[pFileHdr->NumberOfSections].VirtualAddress;
		pImport->Name += pSection[pFileHdr->NumberOfSections].VirtualAddress;
		pImport++;
	}
	memcpy(FileBuff + pSection[pFileHdr->NumberOfSections - 1].PointerToRawData + pSection[pFileHdr->NumberOfSections - 1].SizeOfRawData, Data, Size);

	pOptionHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pSection[pFileHdr->NumberOfSections].VirtualAddress;

	pFileHdr->NumberOfSections++;
	// 写出文件
	PathRemoveFileSpecA(Path);
	strcat(Path, "\\fiximpt.exe");
	fd = fopen(Path, "w+");

	fwrite(FileBuff, 1, FileSize + Size, fd);

	fclose(fd);

	return 0;
}

static int ReBuildImportTable(const std::vector<Import_t>& vctImport, PIMAGE_IMPORT_DESCRIPTOR* NewImportTable)
{
	uint8_t* pImportBuff = (uint8_t*)calloc(0x1000, 1);
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)pImportBuff;

	if (pImportDesc == NULL)
		return -1;

	uint32_t* pPos = (uint32_t*)((uint64_t)pImportBuff + (vctImport.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));

	// 修复结构
	for (const auto& Item : vctImport)
	{
		uint32_t ItemSpace = (Item.ExportFuncName.size() + 1) * 4;
		uint32_t* pINT = pPos;
		uint32_t* pIAT = (uint32_t*)((uint32_t)pINT + ItemSpace);
		pImportDesc->OriginalFirstThunk = (uint32_t)pINT - (uint32_t)pImportBuff;
		pImportDesc->FirstThunk = (uint32_t)pIAT - (uint32_t)pImportBuff;

		char* pTmpPos = (char*)((uint32_t)pIAT + ItemSpace);
		strcpy(pTmpPos, Item.ModuleName);
		pImportDesc->Name = (uint32_t)pTmpPos - (uint32_t)pImportBuff;

		pTmpPos += strlen(pTmpPos) + 1;

		PIMAGE_IMPORT_BY_NAME pImprtName = (PIMAGE_IMPORT_BY_NAME)pTmpPos;
		for (const auto& Name : Item.ExportFuncName)
		{
			pImprtName->Hint = 0;
			strcpy(pImprtName->Name, Name);

			*pINT = (uint32_t)pImprtName - (uint32_t)pImportBuff;
			*pIAT = (uint32_t)pImprtName - (uint32_t)pImportBuff;

			pINT++;
			pIAT++;
			pImprtName = (PIMAGE_IMPORT_BY_NAME)((uint32_t)pImprtName + sizeof(pImprtName->Hint) + strlen(pImprtName->Name) + 1);
		}
		pPos = (uint32_t*)pImprtName;
		pImportDesc++;
	}

	// 添加一个节， 并修复RVA
	AddImportSection(pImportBuff, (uint64_t)pPos - (uint64_t)pImportBuff);


	*NewImportTable = (PIMAGE_IMPORT_DESCRIPTOR)pImportBuff;

	return 0;
}

/*
* 构造一个导入表结构， 记得资源释放
*/
static void* FixImprotByExportFuncationAddress(const std::vector<uint64_t>& ExportFunctions, /*out*/ PIMAGE_IMPORT_DESCRIPTOR* pImport)
{
	using namespace Script::Module;

	std::vector<Import_t> vctImport;

	// 遍历已加载所有模块的导出表
	ListInfo ModList;
	if (!GetList(&ModList) || ModList.data == NULL)
		return NULL;

	assert(ModList.size == ModList.count * sizeof(ModuleInfo));

	ModuleInfo* pModInfo = reinterpret_cast<ModuleInfo*>(ModList.data);

	// 跳过主模块
	for (size_t i = 1; i < ModList.count; i++)
	{
		ListInfo ExportList;

		if (!GetExports(&pModInfo[i], &ExportList) || ExportList.data == NULL)
			continue;

		assert(ExportList.size == ExportList.count * sizeof(ModuleExport));

		// 获取导出的IAT的值，进行对比
		ModuleExport* pModExport = reinterpret_cast<ModuleExport*>(ExportList.data);

		for (size_t j = 0; j < ExportList.count; j++)
		{
			// 转发函数特殊处理
			if (!pModExport[j].forwarded)
			{
				for (const auto& FunVA : ExportFunctions)
				{
					if (pModExport[j].va == FunVA)
					{
						auto Pos =  std::find_if(std::begin(vctImport), std::end(vctImport), 
							[pModInfo, i](const Import_t& iter) {
								return strcmp(pModInfo[i].name, iter.ModuleName) == 0;
							});

						if (Pos == std::end(vctImport))
						{
							Import_t Import;
							strcpy(Import.ModuleName, pModInfo[i].name);
							Import.ExportFuncName.emplace_back( strdup(pModExport[j].name) );
							vctImport.emplace_back(Import);
						}
						else
						{
							(*Pos).ExportFuncName.emplace_back(strdup(pModExport[j].name));
						}

						break;
					}
				}
				

			}
			else
			{

			}
		}
		
		//free(pModExport);
	}


#ifdef _DEBUG

	for (const auto& Iter : vctImport)
	{
		_plugin_logprintf("MoudleName: %s\n", Iter.ModuleName);
		for (auto& FunName : Iter.ExportFuncName)
		{
			_plugin_logprintf("\t\tFunName: %s\n", FunName);
		}
	}

#endif // _DEBUG


	void* newImprt = NULL;
	ReBuildImportTable(vctImport, pImport);

	//free(ModList.data);

	return newImprt;
}

int VmpFixImport()
{
	
	std::vector<Section_t> CodeSects;
	std::vector<uint64_t> MatchCalls;
	std::vector<uint64_t> ExportFunctions;
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = NULL; 

	// 获取代码段
	if (GetCodeScetion(CodeSects) != 0)
	{
		return -1;
	}

	// 获取匹配到特征的call 
	if (FindPatternAddress(CodeSects, MatchCalls) != 0)
	{
		return -1;
	}


#ifndef _DEBUG
	_plugin_logprintf(u8"匹配到的地址数：%d\n", MatchCalls.size());
	for (const auto& calladdr : MatchCalls)
	{
		_plugin_logprintf(u8"Address：%p\n", calladdr);
	}

#endif // _DEBUG

	// 获取导出函数的地址
	if (GetExportFunctionAddress(MatchCalls, ExportFunctions) != 0)
	{
		return -1;
	}
#ifndef _DEBUG
	_plugin_logprintf(u8"导出函数地址：%d\n", ExportFunctions.size());
	for (const auto& FuncAddr : ExportFunctions)
	{
		_plugin_logprintf(u8"Address：%p\n", FuncAddr);
	}

#endif // _DEBUG


	// 根据地址，反推导出表
	if (FixImprotByExportFuncationAddress(ExportFunctions, &pImportTable) != 0)
	{
		return -1;
	}

	FILE* fd = fopen("fiximprt.bin", "w+");
	fwrite(pImportTable, 1, 0x1000, fd);

	fclose(fd);

	return 0;
}
