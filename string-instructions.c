#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#define CODE "\xF3\x6c\xf3\x6d\xf3\xa4\xf3\xa5\xf3\x6e\xf3\x6f\xf3\xac\xf3\xad\xf3\xaa\xf3\xab\xf3\xa6\xf3\xa7\xf3\xae\xf3\xaf" "\xf2\x6c\xf2\x6d\xf2\xa4\xf2\xa5\xf2\x6e\xf2\x6f\xf2\xac\xf2\xad\xf2\xaa\xf2\xab\xf2\xa6\xf2\xa7\xf2\xae\xf2\xaf"
int main(void)
{
    csh capstHandle;
    cs_insn *insn;
    size_t count;

    cs_mode modes[]={CS_MODE_16,CS_MODE_32,CS_MODE_64};
    const char* names[]={"16 bit","32 bit","64 bit"};
    int modeNum;
    for(modeNum=0;modeNum<sizeof(modes)/sizeof(*modes);++modeNum)
    {
        if (cs_open(CS_ARCH_X86, modes[modeNum], &capstHandle) != CS_ERR_OK)
            return -1;
        printf("______________________________________________________________\n%s mode\n",names[modeNum]);
        cs_option(capstHandle, CS_OPT_DETAIL, CS_OPT_ON);
        count = cs_disasm(capstHandle, CODE, sizeof(CODE)-1, 0x7f3280480a8ULL, 0, &insn);
        if (count > 0)
        {
            size_t j,k;
            for (j = 0; j < count; j++)
            {
                printf("0x%"PRIx64": ",insn[j].address);
                for(k=0;k<insn[j].size;++k)
                    printf("%02X ",insn[j].bytes[k]);
                printf("   %-13s %-35s ", insn[j].mnemonic, insn[j].op_str);
                printf("; pfx: %02x %02x %02x %02x op: %02x %02x %02x %02x",insn[j].detail->x86.prefix[0]
                                                                           ,insn[j].detail->x86.prefix[1]
                                                                           ,insn[j].detail->x86.prefix[2]
                                                                           ,insn[j].detail->x86.prefix[3]
                                                                           ,insn[j].detail->x86.opcode[0]
                                                                           ,insn[j].detail->x86.opcode[1]
                                                                           ,insn[j].detail->x86.opcode[2]
                                                                           ,insn[j].detail->x86.opcode[3]
                      );
                printf("; read: ");
                for(k=0;k<insn[j].detail->regs_read_count;++k)
                    printf("%-7s ",cs_reg_name(capstHandle,insn[j].detail->regs_read[k]));
                printf("; write: ");
                for(k=0;k<insn[j].detail->regs_write_count;++k)
                    printf("%-7s ",cs_reg_name(capstHandle,insn[j].detail->regs_write[k]));
                puts("");
            }
       
            cs_free(insn, count);
        }
        else printf("ERROR: Failed to disassemble given code!\n");
       
        cs_close(&capstHandle);
    }
   
     return 0;
}
