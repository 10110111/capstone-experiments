#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#define CODE "\x04\x08\x24\x05\x0c\x05\x00\x00\xa1\x12\x34\x90\x90\x90\x90\x90\x90"

int main(void)
{
    csh capstHandle;
    cs_insn *insn;
    size_t count;

    cs_mode modes[]={CS_MODE_16,CS_MODE_32,CS_MODE_64};
    cs_opt_value syntax[]={CS_OPT_SYNTAX_INTEL,CS_OPT_SYNTAX_ATT};
    const char* modeNames[]={"16 bit","32 bit","64 bit"};
    const char* syntaxNames[]={"Intel","AT&T"};
    int modeNum, syntaxNum;
    for(syntaxNum=0;syntaxNum<2;++syntaxNum)
    {
        for(modeNum=0;modeNum<sizeof(modes)/sizeof(*modes);++modeNum)
        {
            if (cs_open(CS_ARCH_X86, modes[modeNum], &capstHandle) != CS_ERR_OK)
                return -1;
            printf("______________________________________________________________________\n%s mode, %s syntax\n",modeNames[modeNum],syntaxNames[syntaxNum]);
            cs_option(capstHandle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_option(capstHandle, CS_OPT_SYNTAX, syntax[syntaxNum]);
            count = cs_disasm(capstHandle, CODE, sizeof(CODE)-1, 0x80a8, 0, &insn);
            if (count > 0)
            {
                size_t j,k;
                for (j = 0; j < count; j++)
                {
                    printf("0x%"PRIx64": ",insn[j].address);
                    for(k=0;k<insn[j].size;++k)
                        printf("%02X ",insn[j].bytes[k]);
                    printf("   %-5s %-8s ", insn[j].mnemonic, insn[j].op_str);
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
                    uint8_t op_count=insn[j].detail->x86.op_count;
                    printf("Operand count: %d\n",op_count);
                    cs_x86_op* op=insn[j].detail->x86.operands;
                    for(k=0;k<op_count;++k)
                    {
                        printf("\t>type: ");
                        switch(op[k].type)
                        {
                        case X86_OP_INVALID: printf("invalid  ");   break;
                        case X86_OP_REG:     printf("register ");  break;
                        case X86_OP_IMM:     printf("immediate"); break;
                        case X86_OP_MEM:     printf("memory   ");    break;
                        case X86_OP_FP:      printf("floatg-pt"); break;
                        default:             printf(" (Error) ");
                        }
                        printf(", size: %d",op[k].size);
                        printf(", value: ");
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
                        case X86_OP_FP:
                            printf("%g\n",op[k].fp);
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
    }
   
     return 0;
}
