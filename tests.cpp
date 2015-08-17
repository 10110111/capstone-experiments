#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>

namespace capstone
{
#include <capstone/capstone.h>
}

std::string location;

char skipws(std::istringstream& in)
{
    char c;
    while((c=in.get())==' ');
    return c;
}

std::vector<uint8_t> readBytes(std::istringstream& in)
{
    std::string err("failed to parse instruction bytes: error ");
    char high=skipws(in);
    if(!in) throw err+"1"; // something must be present
    std::vector<uint8_t> bytes;
    while(true)
    {
        char low=in.get();
        if(!in) throw err+"2"; // second nibble must be present
        if(std::isspace(low)) throw err+"3";
        std::string str{high,low};
        std::stringstream ss(str);
        unsigned int value;
        ss >> std::hex >> value;
        if(!ss) throw err+"4";
        bytes.push_back(value);
        char separator=in.get();
        if(in.eof()) break;
        if(!in) throw err+"5";
        if(separator!=' ') throw err+"6";
        if(separator==' ')
        {
            high=in.get();
            if(in.eof()) break;
            if(!in) throw err+"7";
            if(high==' ') break; // second space ends sequence
        }
    }
    return bytes;
}

std::string formatBytes(const std::vector<uint8_t>& bytes)
{
    if(bytes.size()==0)
        return std::string();
    std::ostringstream str;
    for(uint8_t byte: bytes)
        str << std::uppercase << std::setw(2) << std::setfill('0') << std::hex << (byte&0xff) << " ";
    std::string string(str.str());
    return string.pop_back(),string;
}

void readSyntaxAndBitness(std::istringstream& in, capstone::cs_mode& mode, capstone::cs_opt_value& syntax)
{
    std::string syntaxString;
    std::getline(in,syntaxString,':');
    if(syntaxString=="Intel16")
    {
        mode=capstone::CS_MODE_16;
        syntax=capstone::CS_OPT_SYNTAX_INTEL;
    }
    else if(syntaxString=="Intel32")
    {
        mode=capstone::CS_MODE_32;
        syntax=capstone::CS_OPT_SYNTAX_INTEL;
    }
    else if(syntaxString=="Intel64")
    {
        mode=capstone::CS_MODE_64;
        syntax=capstone::CS_OPT_SYNTAX_INTEL;
    }
    else if(syntaxString=="AT&T16 ")
    {
        mode=capstone::CS_MODE_16;
        syntax=capstone::CS_OPT_SYNTAX_ATT;
    }
    else if(syntaxString=="AT&T32 ")
    {
        mode=capstone::CS_MODE_32;
        syntax=capstone::CS_OPT_SYNTAX_ATT;
    }
    else if(syntaxString=="AT&T64 ")
    {
        mode=capstone::CS_MODE_64;
        syntax=capstone::CS_OPT_SYNTAX_ATT;
    }
    else
    {
        std::ostringstream error;
        error << location << "error: failed to parse bitness and syntax token\n";
        throw error.str();
    }
}

uint64_t readAddress(std::istringstream& in)
{
    uint64_t address;
    in >> std::hex >> address;
    if(!in)
    {
        std::ostringstream error;
        error << location << "error: failed to parse address\n";
        throw error.str();
    }
    if(in.get()!=':')
    {
        std::ostringstream error;
        error << location << "error: expected colon after address. Address found was " << std::hex << address << "\n";
        throw error.str();
    }
    return address;
}

capstone::cs_insn* disassemble(const capstone::csh csh, std::vector<uint8_t> bytes, uint64_t address)
{
    capstone::cs_insn *insn;
    if(!capstone::cs_disasm(csh, bytes.data(), bytes.size(), address, 1, &insn))
    {
        std::ostringstream error;
        error << location << "error: failed to disassemble instruction\n";
    }
    return insn;
}

std::string readInstructionString(std::istringstream& in)
{
    std::string str;
    skipws(in);
    in.seekg(-1,std::ios_base::cur);
    std::getline(in,str,';');
    while(str.back()==' ') str.pop_back();
    if(str.empty()) throw std::string("Failed to read instruction string");
    return str;
}

int main(int argc, char** argv)
{
    capstone::csh csh;
    if(argc<2)
    {
        std::cerr << "Usage: " << argv[0] << " filename\n";
        return -1;
    }
    std::string filename(argv[1]);
    std::ifstream file(filename);
    if(!file)
    {
        std::cerr << "Failed to open \""<<argv[1]<<"\"\n";
        return -2;
    }

    std::string line;
    std::size_t lineNum=0;

    std::size_t errorCount=0;
    std::size_t testCount=0;
   
    while(std::getline(file,line))
    {
        location=std::string(filename)+":"+std::to_string(++lineNum)+": ";
        if(line[0]=='#')
            continue;
        if(line.size()==0)
            continue;
        try
        {
            capstone::cs_mode mode;
            capstone::cs_opt_value syntax;
            std::istringstream in(line);
            readSyntaxAndBitness(in,mode,syntax);
            if (capstone::cs_open(capstone::CS_ARCH_X86, mode, &csh) != capstone::CS_ERR_OK)
            {
                std::cerr << "cs_open failed\n";
                return -3;
            }
            capstone::cs_option(csh, capstone::CS_OPT_SYNTAX, syntax);
            capstone::cs_option(csh, capstone::CS_OPT_DETAIL, capstone::CS_OPT_ON);
            uint64_t address=readAddress(in);
            std::vector<uint8_t> bytes=readBytes(in);
            std::string expectedInsnString=readInstructionString(in);
            capstone::cs_insn *insn;
            try { insn=disassemble(csh,bytes,address); }
            catch(const std::string& error)
            {
                std::cerr << error;
                ++errorCount;
                continue;
            }
            if(insn->size < bytes.size())
            {
                std::cerr << location << "error: extra " << bytes.size()-insn->size << " bytes after instruction\n";
                std::cerr << line << "\n";
                ++errorCount;
                continue;
            }

            std::string actualInsnString=std::string(insn->mnemonic)+" "+insn->op_str;
            if(expectedInsnString!=actualInsnString)
            {
                std::cerr << location << "error: expected and actual instruction strings differ\n";
                std::cerr << line << "\n";
                std::cerr << location << "note: expected string is: " << expectedInsnString << "\n";
                std::cerr << location << "note: capstone returned : " << actualInsnString << "\n";
                ++errorCount;
            }

/*            std::size_t operandCount=insn->detail->x86.op_count;
            std::vector<capstone::x86_op_type> opTypes;
            std::vector<std::size_t> opSizes;
            bool opTypeFailure=false;
            for(std::size_t opN=0;opN<operandCount;++opN)
            {
                std::string opTypeStr;
                std::getline(in,opTypeStr,' ');
                std::string opClass(opTypeStr,0,3);
                capstone::x86_op_type type(capstone::X86_OP_INVALID);
                if(opClass=="imm")
                    type=capstone::X86_OP_IMM;
                else if(opClass=="reg")
                    type=capstone::X86_OP_REG;
                else if(opClass=="mem")
                    type=capstone::X86_OP_MEM;
                else
                {
                    std::cerr << location << "error: failed to parse operand " << opN+1 << " type\n";
                    std::cerr << line << "\n";
                    std::cerr << formatPosition(in);
                    opTypeFailure=true;
                    break;
                }
                opTypes.push_back(type);
                std::string opSize(opTypeStr,3);
                std::istringstream opSizeStr(opSize);
                std::size_t size;
                opSizeStr >> size;
                if(!opSizeStr || size%8)
                {
                    std::cerr << location << "error: failed to parse operand " << opN+1 << " size\n";
                    std::cerr << line << "\n";
                    std::cerr << formatPosition(in);
                    opTypeFailure=true;
                    break;
                }
                opSizes.push_back(size/8);
            }
            if(!opTypeFailure)
            {
                if(opSizes.size()!=opTypes.size())
                {
                    std::cerr << location << "error: internal parser error\n";
                    return -4;
                }
                if(opSizes.size()!=insn->detail->x86.op_count)
                {
                    std::cerr << location << "expected " << opSizes.size() << " operands, capstone returned " << insn->detail->x86.op_count << "\n";
                    std::cerr << line << "\n";
                    std::cerr << formatPosition(in);
                    ++errorCount;
                }
                for(std::size_t i=0;i<insn->detail->x86.op_count;++i)
                {
                    if(opSizes[i]!=insn->detail->x86.operands[i].size)
                    {
                        std::cerr << location << "error: operand #" << i+1 << ": expected size " << 8*opSizes[i] << " bit, capstone returned " << 8*insn->detail->x86.operands[i].size << " bit\n";
                        std::cerr << line << "\n";
                        ++errorCount;
                    }
                }
            }
            else ++errorCount;
*/
            ++testCount;

            capstone::cs_free(insn, 1);
            capstone::cs_close(&csh);
        }
        catch(const std::string& error)
        {
            std::cerr << location << error << "\n";
            return 127;
        }
    }

    if(errorCount)
        std::cerr << "\n" << errorCount << " tests FAILED" << " out of " << testCount << "\n";
    else
        std::cerr << "All tests PASSED\n";

    return !!errorCount;
}
