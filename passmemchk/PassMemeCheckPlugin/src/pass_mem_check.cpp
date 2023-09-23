#include "pass_mem_check.h"
#include <Windows.h>
#include "pluginmain.h"

#define EXITON_ACCESS_READ 0
#define EXITON_ACCESS_WRITE 1
#define EXITON_ACCESS_DEP 8
#define INVALID_OFFSET -1

struct SectionBackup
{
    Section scetion;
    uint8_t* data = nullptr;
    DWORD old_protect = 0;
    void * access_address = nullptr;
    uint32_t access_offset = INVALID_OFFSET;
};

static std::list<SectionBackup> s_section_backup;

static void set_no_access_check_section();
static void resume_access_check_section();

void save_check_section(const std::list<Section>& sects)
{
    // Backup the detected section
    for (const auto& sect : sects)
    {
        DWORD old_attr = 0;
        
        SectionBackup sect_back;
        sect_back.scetion = sect;
        sect_back.data = (uint8_t*)malloc(sect.virtual_size);
        if (sect_back.data)
        {
            duint readofbyte = 0;
            Script::Memory::Read((duint)sect.virtual_address, sect_back.data, sect.virtual_size, &readofbyte);
        }

        s_section_backup.emplace_back(sect_back);
    }
}

int initialize_cheat_handle()
{
    
    // Set the detected section to NOACCESS
    set_no_access_check_section();

    // Bypassing memory check in VEH handle

    return MEM_CHECK_ERROR_OK;
}

void destory_cheat_handle()
{
    // Resume the detected section to NOACCESS
    resume_access_check_section();

    // Remove VEH handle
    //RemoveVectoredExceptionHandler(s_veh_handle);
    //s_veh_handle = NULL;
}

static void swap_memory(void* src, void* desc, uint32_t size)
{
    void* buffer =  alloca(size);
    Script::Memory::Read((duint)src, buffer,  size, NULL);
    Script::Memory::Read((duint)desc, src, size, NULL);
    Script::Memory::Read((duint)buffer, desc, size, NULL);
    //memcpy(buffer, src, size);
    //memcpy(src, desc, size);
    //memcpy(desc, buffer, size);
}


PLUG_EXPORT
void  CBDEBUGEVENT(CBTYPE  cbType, PLUG_CB_DEBUGEVENT* info)
{

    if (cbType == CB_DEBUGEVENT && info->DebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
        static SectionBackup prev_section;
        EXCEPTION_RECORD* ExceptionInfo = &info->DebugEvent->u.Exception.ExceptionRecord;
        if (ExceptionInfo->ExceptionCode == EXCEPTION_ACCESS_VIOLATION
            && (ExceptionInfo->ExceptionInformation[0] == EXITON_ACCESS_READ || ExceptionInfo->ExceptionInformation[0] == EXITON_ACCESS_DEP))
        {
            void* access_address = (void*)ExceptionInfo->ExceptionInformation[1];
            for (auto& sect_back : s_section_backup)
            {
                if (access_address >= sect_back.scetion.virtual_address
                    && access_address <= ((char*)sect_back.scetion.virtual_address + sect_back.scetion.virtual_size))
                {
                    resume_access_check_section();
                    sect_back.access_address = access_address;
                    sect_back.access_offset = (char*)access_address - sect_back.scetion.virtual_address;
                    swap_memory(access_address, (char*)sect_back.scetion.virtual_address + sect_back.access_offset, 1);

                    Script::Debug::StepIn();

                    swap_memory(prev_section.access_address, (char*)prev_section.scetion.virtual_address + prev_section.access_offset, 1);
                    prev_section.access_offset = INVALID_OFFSET;
                    set_no_access_check_section();
                }

            }
        }
    }
}

static void set_no_access_check_section()
{
    for (auto& sect : s_section_backup)
    {
        sect.old_protect = Script::Memory::GetProtect((duint)sect.scetion.virtual_address);
        Script::Memory::SetProtect((duint)sect.scetion.virtual_address, PAGE_NOACCESS, sect.scetion.virtual_size);
    }
}

static void resume_access_check_section()
{
    for (auto& sect : s_section_backup)
    {
        Script::Memory::SetProtect((duint)sect.scetion.virtual_address, sect.old_protect, sect.scetion.virtual_size);
    }
}