#pragma once
#include <cstdint>
#include <list>

#ifdef WIN32
#define ptr_t uint32_t
#else
#define ptr_t uint64_t
#endif

enum BYPASS_MEM_CHECK_ERROR
{
    MEM_CHECK_ERROR_OK = 0,
    MEM_CHECK_ERROR_REGISTER_VEH_FAILED = -1,
    MEM_CHECK_ERROR_ALREADY_INITIALIZED = -2,
};

struct Section
{
    void* virtual_address = nullptr;
    uint32_t virtual_size = 0;
};


void save_check_section(const std::list<Section>& sects);

int initialize_cheat_handle();

void destory_cheat_handle();


