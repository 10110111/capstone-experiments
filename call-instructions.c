#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#define CODE "\xe8\x35\x64\x93\x53\x66\xe8\x35\x64\x93\x53\xe9\x35\x64\x93\x53\x66\xe9\x35\x64\x93\x53\x78\x33"
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
        cs_option(capstHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
        cs_option(capstHandle, CS_OPT_DETAIL, CS_OPT_ON);
        uint64_t address=0x649123ffe1;
        if(modes[modeNum]==CS_MODE_32)
            address&=0xffffffff;
        if(modes[modeNum]==CS_MODE_16)
            address&=0xffff;
        count = cs_disasm(capstHandle, CODE, sizeof(CODE)-1, address, 0, &insn);
        if (count > 0)
        {
            size_t j,k;
            for (j = 0; j < count; j++)
            {
                printf("0x%"PRIx64": ",insn[j].address);
                for(k=0;k<insn[j].size;++k)
                    printf("%02X ",insn[j].bytes[k]);
                printf("\n       string: %s %s\n", insn[j].mnemonic, insn[j].op_str);
                printf("       prefix: %02x %02x %02x %02x\n       opcode: %02x %02x %02x %02x\n",insn[j].detail->x86.prefix[0]
                                                                                                 ,insn[j].detail->x86.prefix[1]
                                                                                                 ,insn[j].detail->x86.prefix[2]
                                                                                                 ,insn[j].detail->x86.prefix[3]
                                                                                                 ,insn[j].detail->x86.opcode[0]
                                                                                                 ,insn[j].detail->x86.opcode[1]
                                                                                                 ,insn[j].detail->x86.opcode[2]
                                                                                                 ,insn[j].detail->x86.opcode[3]
                      );
                uint8_t op_count=insn[j].detail->x86.op_count;
                printf("     op_count: %d\n",op_count);
                if(op_count>0)
                    printf("  Operands:\n");
                cs_x86_op* op=insn[j].detail->x86.operands;
                for(k=0;k<op_count;++k)
                {
                    printf("\t>type : ");
                    switch(op[k].type)
                    {
                    case X86_OP_INVALID: printf("invalid");   break;
                    case X86_OP_REG:     printf("register");  break;
                    case X86_OP_IMM:     printf("immediate"); break;
                    case X86_OP_MEM:     printf("memory");    break;
                    default:             printf("(Error)");
                    }
                    printf("\n\t size : %d",op[k].size);
                    printf("\n\t value: ");
                    switch(op[k].type)
                    {
                    case X86_OP_REG:
                        printf("%s\n",cs_reg_name(capstHandle,op[k].reg));
                        break;
                    case X86_OP_IMM:
                        printf("%08"PRIx64"\n",op[k].imm);
                        break;
                    case X86_OP_MEM:
                        printf("seg: %s, base: %s, index: %s, scale: %d, disp: %"PRIx64"\n",cs_reg_name(capstHandle,op[k].mem.segment)
                                                                                           ,cs_reg_name(capstHandle ,op[k].mem.base)
                                                                                           ,cs_reg_name(capstHandle,op[k].mem.index)
                                                                                           ,op[k].mem.scale
                                                                                           ,op[k].mem.disp);
                        break;
                    default:
                        puts("");
                    }
                }
                puts("");
            }
       
            cs_free(insn, count);
        }
        else printf("ERROR: Failed to disassemble given code!\n");
       
        cs_close(&capstHandle);
    }
       
       return 0;
}
