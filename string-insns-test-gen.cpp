#include <iostream>
#include <iomanip>
#include <cstdint>
#include <algorithm>
#include <array>
#include <sstream>

enum OperandType
{
    REG8,
    REG16,
    REGW,
    MEM8,
    MEMW
};

enum Segment
{
    SEG_NONE,
    ES,
    CS,
    SS,
    DS,
    FS,
    GS
};

struct Operand
{
    OperandType type;
    const char* string;
    Segment seg;
};

struct Instruction
{
    uint8_t opcode;
    const char* mnemonic;
    bool repe;
    std::array<Operand,2> operands;
};

enum Mode
{
    Use16,
    Use32,
    Use64
};

std::ostream& operator<<(std::ostream& str, Mode mode)
{
    switch(mode)
    {
    case Use16: str<<"16"; break;
    case Use32: str<<"32"; break;
    case Use64: str<<"64"; break;
    }
    return str;
}

std::ostream& operator<<(std::ostream& str, std::vector<uint8_t> vec)
{
    std::ostringstream stream;
    for(const uint8_t val: vec)
        stream << std::hex << (val&0xff) << " ";
    std::ostringstream adjusted;
    adjusted << std::setw(20) << std::left << stream.str();
    str << adjusted.str();
    return str;
}

std::string toHexString(uint64_t val, bool fill=false, char sym='\0')
{
    std::ostringstream str;
    str << std::hex << val << sym;
    std::ostringstream adjusted;
    if(fill) adjusted << std::setw(12) << std::left;
    adjusted << str.str();
    return adjusted.str();
}

std::size_t addressSize(const std::vector<uint8_t>& prefixes, Mode mode)
{
    bool overridden = std::find(prefixes.begin(),prefixes.end(),0x67)!=prefixes.end();
    switch(mode)
    {
    case Use16:
        return overridden? 32 : 16;
    case Use32:
        return overridden? 16 : 32;
    case Use64:
        return overridden? 32 : 64;
    }
    return 0;
}

std::size_t operandSize(const std::vector<uint8_t>& prefixes, Mode mode)
{
    bool overridden = std::find(prefixes.begin(),prefixes.end(),0x66)!=prefixes.end();
    bool rexW = std::find_if(prefixes.begin(),prefixes.end(), [](uint8_t pfx) { return (pfx&0xf8)==0x48; }) != prefixes.end();
    if(mode==Use64 && rexW)
        return 64;
    switch(mode)
    {
    case Use16:
        return overridden? 32 : 16;
    case Use32:
    case Use64:
        return overridden? 16 : 32;
    }
    return 0;
}

std::string segName(Segment seg)
{
    switch(seg)
    {
    case SEG_NONE: return "";
    case ES: return "es";
    case CS: return "cs";
    case SS: return "ss";
    case DS: return "ds";
    case FS: return "fs";
    case GS: return "gs";
    default: return "???";
    }
}

std::string sizeName(std::size_t size)
{
    switch(size)
    {
    case  8: return "byte";
    case 16: return "word";
    case 32: return "dword";
    case 64: return "qword";
    default: return "???";
    }
}

std::string regName(std::size_t opSize, const std::string& str)
{
    switch(opSize)
    {
    case 8:
        return str+'l';
    case 16:
        return str.size()==2? str : str+'x';
    case 32:
        return str.size()==2? 'e'+str : 'e'+str+'x';
    case 64:
        return str.size()==2? 'r'+str : 'r'+str+'x';
    default:
        return "???";
    }
}

std::string prefixNames(const std::vector<uint8_t>& prefixes, bool repe)
{
    std::stringstream str;
    for(const uint8_t pfx: prefixes)
    {
        switch(pfx)
        {
        case 0xf3: str << (repe?"repe":"rep");  break;
        case 0xf2: str << "repne"; break;
        default: break;
        }
    }
    return str.str();
}

Segment segmentOverride(const std::vector<uint8_t>& prefixes)
{
    for(const uint8_t pfx: prefixes)
    {
        switch(pfx)
        {
        case 0x26: return ES;
        case 0x2e: return CS;
        case 0x36: return SS;
        case 0x3e: return DS;
        case 0x64: return FS;
        case 0x65: return GS;
        }
    }
    return SEG_NONE;
}

std::string segOverrideStr(Segment override_, Segment default_, Mode mode)
{
    if(mode==Use64 && override_==SEG_NONE)
        return "";
    if(default_==DS && override_!=DS && override_!=SEG_NONE)
        return segName(override_)+':';
    if(default_==DS || default_==SEG_NONE)
        return "";
    return segName(default_)+':';
}

Instruction insns[]={
{0x6c, "ins", false, MEM8, "di", ES, REG16, "d", SEG_NONE},
{0x6d, "ins", false, MEMW, "di", ES, REG16, "d", SEG_NONE},
{0x6e, "outs", false, REG16, "d", SEG_NONE, MEM8, "di", ES},
{0x6f, "outs", false, REG16, "d", SEG_NONE, MEMW, "di", ES},
{0xa4, "movs", false, MEM8, "di", ES, MEM8, "si", DS},
{0xa5, "movs", false, MEMW, "di", ES, MEMW, "si", DS},
{0xa6, "cmps", true, MEM8, "si", DS, MEM8, "di", ES},
{0xa7, "cmps", true, MEMW, "si", DS, MEMW, "di", ES},
{0xaa, "stos", false, MEM8, "di", ES, REG8, "a", SEG_NONE},
{0xab, "stos", false, MEMW, "di", ES, REGW, "a", SEG_NONE},
{0xac, "lods", false, REG8, "a", SEG_NONE, MEM8, "si", DS},
{0xad, "lods", false, REGW, "a", SEG_NONE, MEMW, "si", DS},
{0xae, "scas", true, REG8, "a", SEG_NONE, MEM8, "di", ES},
{0xaf, "scas", true, REGW, "a", SEG_NONE, MEMW, "di", ES}
};
constexpr std::size_t insnCount=sizeof(insns)/sizeof(insns[0]);

int main()
{
    const std::vector<uint8_t> prefixSets[]{{0x67,0xf3},{0x66,0xf2},{0x66,0x67,0xf3},{0xf3},{},{0x66},{0x67},{0x66,0x67}};
    Mode modes[]={Use16,Use32,Use64};
    for(Mode mode: modes)
    {
        uint64_t address=0x649123ffe1ull;
        if(mode==Use16) address&=0xffffull;
        if(mode==Use32) address&=0xffffffffull;
        for(std::size_t pfxSN=0;pfxSN<sizeof(prefixSets)/sizeof(prefixSets[0]);++pfxSN)
        {
            const std::vector<uint8_t>& prefixes=prefixSets[pfxSN];
            for(const auto& insn: insns)
            {
                std::size_t addrSize=addressSize(prefixes,mode);
                std::size_t opSize  =operandSize(prefixes,mode);
                std::vector<uint8_t> hex=prefixes; hex.push_back(insn.opcode);
                std::ostringstream line;
                line << "Intel";
                line << mode;
                line << ": 0x";
                line << toHexString(address,true,':');
                line << " " << hex;
                line << "  ";

                std::size_t opNum=1;
                std::stringstream typeSizesStream;
                std::ostringstream opStream;
                char mnemonicSuffix=0;
                for(const auto& operand: insn.operands)
                {
                    std::string opName=regName(opSize, operand.string);
                    switch(operand.type)
                    {
                    case REG8:
                        opSize=8;
                        opName=regName(opSize, operand.string);
                        typeSizesStream<<"reg";
                        break;
                    case REG16:
                        opSize=16;
                        typeSizesStream<<"reg";
                        opName=regName(opSize, operand.string);
                        break;
                    case REGW:
                        typeSizesStream<<"reg";
                        // all done
                        break;
                    case MEM8:
                        opSize=8;
                        // fall through
                    case MEMW:
                    {
                        std::string seg=segOverrideStr(segmentOverride(prefixes),operand.seg,mode);
                        opName=sizeName(opSize)+" ptr "+seg+"["+regName(addrSize,operand.string)+"]";
                        typeSizesStream<<"mem";
                        mnemonicSuffix=opName[0];
                        break;
                    }
                    }
                    opStream<< opName << ", ";
                    typeSizesStream << opSize << ", ";
                    ++opNum;
                }
                std::string opString=opStream.str();
                opString.pop_back();
                opString.pop_back();
                std::ostringstream opStrAligned;
                opStrAligned << std::left << std::setw(50) << opString << ";";

                std::string typeSizes=typeSizesStream.str();
                typeSizes.pop_back();
                typeSizes.pop_back();

                std::cout << line.str() << prefixNames(prefixes,insn.repe) << " "
                          << insn.mnemonic << mnemonicSuffix << " "
                          << opStrAligned.str()
                          << typeSizes << "\n";
            }
        }
    }
}
