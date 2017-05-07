#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

//#define CODE "\xf3\x0f\xe6\x90\x90\x90\x90\x90\x67\x48\xb9\x00\x00\x00\x00\x67\xe3\xfd\x90\xe2\xfe\xdd\xd8\x2e\x3e\x2e\x3e\x66\x67\x78\x03"
//#define CODE "\xff\x2d\x34\x35\x23\x01\x78\x00\xe0\xfe\xe1\xfe\xe2\xfe\xea\x12\x34\x56\x78\x9a\xbc\xeb\xfe\x0f\xb6\xca\xdd\xd9\xdb\x3d\xe0\x00\x30\x05\x8b\x84\x91\x2f\x09\x00\x00"
#define CODE "\xc4\xe1\x74\x58\xa5\x90\x90\x90\x90\x00\x00\xa1\x90\x90\x90\x90\x90\x90\x90\x90\xe8\x35\x64\x93\x53\x66\xe8\x35\x64\x93\x53\x8b\x45\x35\x8b\x43\x35"
//#define CODE "\x62\xf1\x6c\xbe\x58\xfc"

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
        printf("_____________________________________________\n%s mode\n",names[modeNum]);
        cs_option(capstHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
        cs_option(capstHandle, CS_OPT_DETAIL, CS_OPT_ON);
        count = cs_disasm(capstHandle, CODE, sizeof(CODE)-1, 0x640032001600, 0, &insn);
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
                printf("          rex: %02x\n",insn[j].detail->x86.rex);
                printf("     add_size: %u\n",insn[j].detail->x86.addr_size);
                printf("        modrm: %02x\n",insn[j].detail->x86.modrm);
                printf("          sib: %02x\n",insn[j].detail->x86.sib);
                printf("         disp: %08x\n",insn[j].detail->x86.disp);
                printf("     SIBindex: %s\n",cs_reg_name(capstHandle,insn[j].detail->x86.sib_index));
                printf("     SIB base: %s\n",cs_reg_name(capstHandle,insn[j].detail->x86.sib_base));
                printf("     SIBscale: %d\n",insn[j].detail->x86.sib_scale);
                printf("implicRegRead: ");
                for(k=0;k<insn[j].detail->regs_read_count;++k)
                    printf("%s ",cs_reg_name(capstHandle,insn[j].detail->regs_read[k]));
                printf("  \nimpliRegWrite: ");
                for(k=0;k<insn[j].detail->regs_write_count;++k)
                    printf("%s ",cs_reg_name(capstHandle,insn[j].detail->regs_write[k]));
                puts("");
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
