#include "remove_deadstore.h"


static uint8_t ss_junk_code[][16] = {
    {0xF9}, // stc
    {0xF5}, // cmc
    {0xF8}, // clc
};


int remove_destore(uint8_t* code_buffer, size_t size)
{
    csh handle;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
        return -1;

    // clear junk code 
    for (size_t i = 0; i < size; ++i)
    {
        for (size_t j = 0; j < _countof(ss_junk_code); ++j)
        {
            if (memcmp(code_buffer + i, ss_junk_code[j], sizeof(ss_junk_code[j])) == 0)
            {
                memset(code_buffer + i, 90, sizeof(ss_junk_code[j]));
                i += sizeof(ss_junk_code[j]) - 1;
                break;
            }
        }
    }

    // scan code
    cs_insn* insn;
    int index = 0;
    while(index < size)
    {
        size_t count = cs_disasm(handle, code_buffer + index, size - index, 0, 1, &insn);
        if (count > 0)
        {
            cs_insn* cursor_insn;
            size_t cursor = index + insn->size;
            while (cursor < size)
            {
                size_t cursor_count = cs_disasm(handle, code_buffer + cursor, size - cursor, 0, 1, &cursor_insn);
                if (cursor_count > 0 )
                {


                    cs_free(cursor_insn, cursor_count);
                }
            }

            
            cs_free(insn, count);
        }
    
    }


    cs_close(&handle);
    return -1;
}
