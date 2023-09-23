#pragma once

#ifdef WIN32
#include "thrid/capstone/capstone-4.0.2-win32/include/capstone/capstone.h"
#else
#include "thrid/capstone/capstone-4.0.2-win64/include/capstone/capstone.h"
#endif // WIN32

#include "thrid/XEDParse/XEDParse.h"
#include <cstdint>

#ifdef __cplusplus 
extern "C" {
#endif // __cplusplus



int remove_destore(uint8_t* code_buffer, size_t size);



#ifdef __cplusplus 
}
#endif // __cplusplus