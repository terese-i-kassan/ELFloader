// elf2rpl.h - ELF -> RPX/RPL converter as a header-only library.
//
// This is a port of `elf2rpl` from https://github.com/devkitPro/wut-tools
// (src/elf2rpl/main.cpp, GPL-2.0, (c) the wut / decaf-emu authors). The
// conversion steps and their order are unchanged. Differences from upstream:
//   * no fmt/excmd; errors are returned as a string
//   * big-endian aware (runs natively on Wii U PPC and on little-endian hosts)
//   * stdio instead of iostream, extra bounds checks on untrusted input
//   * output is written sequentially (FAT-safe; no seeking past EOF)
//
// Needs zlib (-lz).
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <zlib.h>

namespace elf2rpl
{

// ---------------------------------------------------------------- endian

namespace detail
{
template<unsigned N> struct UInt;
template<> struct UInt<1> { typedef uint8_t type; };
template<> struct UInt<2> { typedef uint16_t type; };
template<> struct UInt<4> { typedef uint32_t type; };

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
inline uint8_t swapU(uint8_t v) { return v; }
inline uint16_t swapU(uint16_t v) { return v; }
inline uint32_t swapU(uint32_t v) { return v; }
#else
inline uint8_t swapU(uint8_t v) { return v; }
inline uint16_t swapU(uint16_t v) { return __builtin_bswap16(v); }
inline uint32_t swapU(uint32_t v) { return __builtin_bswap32(v); }
#endif
} // namespace detail

// Packed (alignment 1): ELF structures contain fields at odd offsets.
template<typename T>
struct __attribute__((packed)) be_val
{
   typedef typename detail::UInt<sizeof(T)>::type U;
   U raw;

   be_val() = default;
   be_val(T v) { set(v); }

   T get() const
   {
      U u = detail::swapU(raw);
      T t;
      std::memcpy(&t, &u, sizeof(T));
      return t;
   }

   void set(T v)
   {
      U u;
      std::memcpy(&u, &v, sizeof(T));
      raw = detail::swapU(u);
   }

   operator T() const { return get(); }
   be_val &operator=(T v) { set(v); return *this; }
   be_val &operator|=(T v) { set(static_cast<T>(get() | v)); return *this; }
   be_val &operator+=(T v) { set(static_cast<T>(get() + v)); return *this; }
};

// ------------------------------------------------------------ ELF format

namespace elf
{
#pragma pack(push, 1)

static const uint16_t EM_PPC = 20;
static const uint8_t ELFDATA2MSB = 2;
static const uint8_t ELFCLASS32 = 1;
static const uint8_t EV_CURRENT = 1;
static const uint16_t EABI_CAFE = 0xCAFE;
static const uint32_t HeaderMagic = 0x7F454C46;

static const uint32_t SHF_WRITE = 0x1;
static const uint32_t SHF_ALLOC = 0x2;
static const uint32_t SHF_EXECINSTR = 0x4;
static const uint32_t SHF_DEFLATED = 0x08000000;

static const uint32_t SHT_NULL = 0;
static const uint32_t SHT_PROGBITS = 1;
static const uint32_t SHT_SYMTAB = 2;
static const uint32_t SHT_STRTAB = 3;
static const uint32_t SHT_RELA = 4;
static const uint32_t SHT_NOBITS = 8;
static const uint32_t SHT_RPL_EXPORTS = 0x80000001;
static const uint32_t SHT_RPL_IMPORTS = 0x80000002;
static const uint32_t SHT_RPL_CRCS = 0x80000003;
static const uint32_t SHT_RPL_FILEINFO = 0x80000004;

static const uint32_t STT_OBJECT = 1;
static const uint32_t STT_FUNC = 2;
static const uint32_t STT_SECTION = 3;

static const uint32_t R_PPC_NONE = 0;
static const uint32_t R_PPC_ADDR32 = 1;
static const uint32_t R_PPC_ADDR16_LO = 4;
static const uint32_t R_PPC_ADDR16_HI = 5;
static const uint32_t R_PPC_ADDR16_HA = 6;
static const uint32_t R_PPC_REL24 = 10;
static const uint32_t R_PPC_REL14 = 11;
static const uint32_t R_PPC_REL32 = 26;
static const uint32_t R_PPC_DTPMOD32 = 68;
static const uint32_t R_PPC_DTPREL32 = 78;
static const uint32_t R_PPC_EMB_SDA21 = 109;
static const uint32_t R_PPC_EMB_RELSDA = 116;
static const uint32_t R_PPC_DIAB_SDA21_LO = 180;
static const uint32_t R_PPC_DIAB_SDA21_HI = 181;
static const uint32_t R_PPC_DIAB_SDA21_HA = 182;
static const uint32_t R_PPC_DIAB_RELSDA_LO = 183;
static const uint32_t R_PPC_DIAB_RELSDA_HI = 184;
static const uint32_t R_PPC_DIAB_RELSDA_HA = 185;
static const uint32_t R_PPC_GHS_REL16_HI = 252;
static const uint32_t R_PPC_GHS_REL16_LO = 253;

static const uint32_t RPL_IS_RPX = 0x2;

struct Header
{
   be_val<uint32_t> magic;
   be_val<uint8_t> fileClass;
   be_val<uint8_t> encoding;
   be_val<uint8_t> elfVersion;
   be_val<uint16_t> abi;
   be_val<uint8_t> pad[7];
   be_val<uint16_t> type;
   be_val<uint16_t> machine;
   be_val<uint32_t> version;
   be_val<uint32_t> entry;
   be_val<uint32_t> phoff;
   be_val<uint32_t> shoff;
   be_val<uint32_t> flags;
   be_val<uint16_t> ehsize;
   be_val<uint16_t> phentsize;
   be_val<uint16_t> phnum;
   be_val<uint16_t> shentsize;
   be_val<uint16_t> shnum;
   be_val<uint16_t> shstrndx;
};

struct SectionHeader
{
   be_val<uint32_t> name;
   be_val<uint32_t> type;
   be_val<uint32_t> flags;
   be_val<uint32_t> addr;
   be_val<uint32_t> offset;
   be_val<uint32_t> size;
   be_val<uint32_t> link;
   be_val<uint32_t> info;
   be_val<uint32_t> addralign;
   be_val<uint32_t> entsize;
};

struct Symbol
{
   be_val<uint32_t> name;
   be_val<uint32_t> value;
   be_val<uint32_t> size;
   be_val<uint8_t> info;
   be_val<uint8_t> other;
   be_val<uint16_t> shndx;
};

struct Rela
{
   be_val<uint32_t> offset;
   be_val<uint32_t> info;
   be_val<int32_t> addend;
};

struct RplFileInfo
{
   be_val<uint32_t> version;
   be_val<uint32_t> textSize;
   be_val<uint32_t> textAlign;
   be_val<uint32_t> dataSize;
   be_val<uint32_t> dataAlign;
   be_val<uint32_t> loadSize;
   be_val<uint32_t> loadAlign;
   be_val<uint32_t> tempSize;
   be_val<uint32_t> trampAdjust;
   be_val<uint32_t> sdaBase;
   be_val<uint32_t> sda2Base;
   be_val<uint32_t> stackSize;
   be_val<uint32_t> filename;
   be_val<uint32_t> flags;
   be_val<uint32_t> heapSize;
   be_val<uint32_t> tagOffset;
   be_val<uint32_t> minVersion;
   be_val<int32_t> compressionLevel;
   be_val<uint32_t> trampAddition;
   be_val<uint32_t> fileInfoPad;
   be_val<uint32_t> cafeSdkVersion;
   be_val<uint32_t> cafeSdkRevision;
   be_val<uint16_t> tlsModuleIndex;
   be_val<uint16_t> tlsAlignShift;
   be_val<uint32_t> runtimeFileInfoSize;
};

#pragma pack(pop)

static_assert(sizeof(Header) == 0x34, "Header size");
static_assert(sizeof(SectionHeader) == 0x28, "SectionHeader size");
static_assert(sizeof(Symbol) == 0x10, "Symbol size");
static_assert(sizeof(Rela) == 0x0C, "Rela size");
static_assert(sizeof(RplFileInfo) == 0x60, "RplFileInfo size");
} // namespace elf

// ------------------------------------------------------------- converter

namespace detail
{

static const uint32_t DeflateMinSectionSize = 0x18u;
static const uint32_t CodeBaseAddress = 0x02000000u;
static const uint32_t DataBaseAddress = 0x10000000u;
static const uint32_t LoadBaseAddress = 0xC0000000u;
static const uint32_t UnusedIndex = 0xFFFFFFFFu;
static const char *RplWrapPrefix = "__rplwrap_";

inline uint32_t alignUp(uint32_t value, uint32_t alignment)
{
   if (alignment == 0) {
      return value;
   }
   return static_cast<uint32_t>((static_cast<uint64_t>(value) + (alignment - 1)) & ~static_cast<uint64_t>(alignment - 1));
}

struct Section
{
   elf::SectionHeader header;
   std::string name;
   std::vector<char> data;
   uint32_t index = 0;
};

struct ElfFile
{
   elf::Header header;
   std::vector<std::unique_ptr<Section>> sections;
   size_t numDiscarded = 0;
};

inline Section *getSectionByName(ElfFile &file, const char *name)
{
   for (auto &s : file.sections) {
      if (s->index == UnusedIndex) {
         continue;
      }
      if (s->name == name) {
         return s.get();
      }
   }
   return nullptr;
}

inline bool readAt(FILE *f, uint32_t off, void *dst, size_t n)
{
   if (n == 0) {
      return true;
   }
   if (fseek(f, static_cast<long>(off), SEEK_SET) != 0) {
      return false;
   }
   return fread(dst, 1, n, f) == n;
}

// Read the .elf file generated by the compiler.
inline bool readElf(ElfFile &file, const std::string &filename, std::string &err)
{
   FILE *in = fopen(filename.c_str(), "rb");
   if (!in) {
      err = "could not open input file";
      return false;
   }

   struct Closer { FILE *f; ~Closer() { fclose(f); } } closer { in };

   fseek(in, 0, SEEK_END);
   long fsz = ftell(in);
   if (fsz < static_cast<long>(sizeof(elf::Header))) {
      err = "file too small to be an ELF";
      return false;
   }
   const uint32_t fileSize = static_cast<uint32_t>(fsz);

   if (!readAt(in, 0, &file.header, sizeof(elf::Header))) {
      err = "could not read ELF header";
      return false;
   }

   auto &h = file.header;
   if (h.magic.get() != elf::HeaderMagic) {
      err = "not an ELF file (bad magic)";
      return false;
   }
   if (h.fileClass.get() != elf::ELFCLASS32) {
      err = "ELF is not 32-bit";
      return false;
   }
   if (h.encoding.get() != elf::ELFDATA2MSB) {
      err = "ELF is not big-endian";
      return false;
   }
   if (h.machine.get() != elf::EM_PPC) {
      err = "ELF is not PowerPC";
      return false;
   }
   if (h.elfVersion.get() != elf::EV_CURRENT) {
      err = "unexpected ELF version";
      return false;
   }

   const uint32_t shnum = h.shnum.get();
   if (shnum == 0 || h.shentsize.get() != sizeof(elf::SectionHeader) ||
       static_cast<uint64_t>(h.shoff.get()) + static_cast<uint64_t>(shnum) * sizeof(elf::SectionHeader) > fileSize) {
      err = "bad section header table";
      return false;
   }
   if (h.shstrndx.get() >= shnum) {
      err = "bad section name table index";
      return false;
   }

   // Read section headers and data
   for (uint32_t i = 0; i < shnum; ++i) {
      file.sections.emplace_back(new Section());
      auto &section = *file.sections.back();

      if (!readAt(in, h.shoff.get() + i * sizeof(elf::SectionHeader), &section.header, sizeof(elf::SectionHeader))) {
         err = "could not read section header";
         return false;
      }
      section.index = 0;

      if (section.header.link.get() >= shnum) {
         err = "section link out of range";
         return false;
      }
      if (section.header.type.get() == elf::SHT_RELA && section.header.info.get() >= shnum) {
         err = "relocation target section out of range";
         return false;
      }

      if (!section.header.size.get() || section.header.type.get() == elf::SHT_NOBITS) {
         continue;
      }

      if (section.header.addr.get() >= DataBaseAddress && section.header.addr.get() < LoadBaseAddress) {
         section.header.flags |= elf::SHF_WRITE;
      }

      if (static_cast<uint64_t>(section.header.offset.get()) + section.header.size.get() > fileSize) {
         err = "section data outside of file";
         return false;
      }

      section.data.resize(section.header.size.get());
      if (!readAt(in, section.header.offset.get(), section.data.data(), section.data.size())) {
         err = "could not read section data";
         return false;
      }
   }

   // Set section header names
   {
      const auto &strtab = file.sections[h.shstrndx.get()]->data;
      for (auto &section : file.sections) {
         uint32_t off = section->header.name.get();
         if (off < strtab.size()) {
            const char *p = strtab.data() + off;
            const void *z = memchr(p, 0, strtab.size() - off);
            size_t len = z ? static_cast<size_t>(static_cast<const char *>(z) - p) : strtab.size() - off;
            section->name.assign(p, len);
         }
      }
   }

   // Mark debugging sections as discarded
   static const std::string dwarfPrefix(".debug_");
   uint32_t index = 0;
   file.numDiscarded = 0;
   for (auto &section : file.sections) {
      const std::string *name = &section->name;

      if (section->header.type.get() == elf::SHT_RELA) {
         name = &file.sections[section->header.info.get()]->name;
      }

      if (!name->compare(0, dwarfPrefix.size(), dwarfPrefix)) {
         section->header.type = elf::SHT_NULL;
         section->header.addr = 0u;
         section->header.offset = 0u;
         section->header.size = 0u;
         section->data.clear();
         section->index = UnusedIndex;
         ++file.numDiscarded;
      } else {
         section->index = index;
         ++index;
      }
   }

   return true;
}

// Generate SHT_RPL_FILEINFO section.
inline bool generateFileInfoSection(ElfFile &file, uint32_t flags)
{
   elf::RplFileInfo info;
   std::memset(&info, 0, sizeof(info));
   info.version = 0xCAFE0402u;
   info.textSize = 0u;
   info.textAlign = 32u;
   info.dataSize = 0u;
   info.dataAlign = 4096u;
   info.loadSize = 0u;
   info.loadAlign = 32u;
   info.tempSize = 0u;
   info.trampAdjust = 0u;
   info.trampAddition = 0u;
   info.sdaBase = 0u;
   info.sda2Base = 0u;
   info.stackSize = 0x10000u;
   info.heapSize = 0x8000u;
   info.filename = 0u;
   info.flags = flags;
   info.minVersion = 0x5078u;
   info.compressionLevel = 6;
   info.fileInfoPad = 0u;
   info.cafeSdkVersion = 0x5335u;
   info.cafeSdkRevision = 0x10D4Bu;
   info.tlsAlignShift = static_cast<uint16_t>(0u);
   info.tlsModuleIndex = static_cast<uint16_t>(0u);
   info.runtimeFileInfoSize = 0u;
   info.tagOffset = 0u;

   uint32_t textSize = 0, dataSize = 0, loadSize = 0, tempSize = 0;

   // Count file info textSize, dataSize, loadSize
   for (auto &section : file.sections) {
      auto size = static_cast<uint32_t>(section->data.size());

      if (section->index == UnusedIndex) {
         continue;
      }

      const uint32_t addr = section->header.addr.get();
      const uint32_t hsize = section->header.size.get();
      const uint32_t type = section->header.type.get();

      if (type == elf::SHT_NOBITS) {
         size = hsize;
      }

      if (addr >= CodeBaseAddress && addr < DataBaseAddress) {
         auto val = addr + hsize - CodeBaseAddress;
         if (val > textSize) {
            textSize = val;
         }
      } else if (addr >= DataBaseAddress && addr < LoadBaseAddress) {
         auto val = addr + hsize - DataBaseAddress;
         if (val > dataSize) {
            dataSize = val;
         }
      } else if (addr >= LoadBaseAddress) {
         auto val = addr + hsize - LoadBaseAddress;
         if (val > loadSize) {
            loadSize = val;
         }
      } else if (addr == 0 && type != elf::SHT_RPL_CRCS && type != elf::SHT_RPL_FILEINFO) {
         tempSize += (size + 128);
      }
   }

   info.textSize = alignUp(textSize, info.textAlign.get());
   info.dataSize = alignUp(dataSize, info.dataAlign.get());
   info.loadSize = alignUp(loadSize, info.loadAlign.get());
   info.tempSize = tempSize;

   std::unique_ptr<Section> section(new Section());
   std::memset(&section->header, 0, sizeof(section->header));
   section->header.type = elf::SHT_RPL_FILEINFO;
   section->header.addralign = 4u;
   section->data.insert(section->data.end(),
                        reinterpret_cast<char *>(&info),
                        reinterpret_cast<char *>(&info + 1));
   file.sections.emplace_back(std::move(section));
   return true;
}

// Generate SHT_RPL_CRCS section.
inline bool generateCrcSection(ElfFile &file)
{
   std::vector<be_val<uint32_t>> crcs;
   for (auto &section : file.sections) {
      uint32_t crc = 0u;

      if (section->index == UnusedIndex) {
         continue;
      }

      if (section->data.size()) {
         crc = static_cast<uint32_t>(crc32(0, Z_NULL, 0));
         crc = static_cast<uint32_t>(crc32(crc, reinterpret_cast<const Bytef *>(section->data.data()),
                                           static_cast<uInt>(section->data.size())));
      }

      crcs.push_back(be_val<uint32_t>(crc));
   }

   // Insert a 0 crc for this section
   crcs.insert(crcs.end() - 1, be_val<uint32_t>(0u));

   std::unique_ptr<Section> section(new Section());
   std::memset(&section->header, 0, sizeof(section->header));
   section->header.type = elf::SHT_RPL_CRCS;
   section->header.addralign = 4u;
   section->header.entsize = 4u;
   section->data.insert(section->data.end(),
                        reinterpret_cast<char *>(crcs.data()),
                        reinterpret_cast<char *>(crcs.data() + crcs.size()));

   // Insert before FILEINFO
   file.sections.insert(file.sections.end() - 1, std::move(section));
   return true;
}

// Fix relocations. The Wii U does not support every type of relocation.
inline bool fixRelocations(ElfFile &file, std::string &err)
{
   std::set<unsigned int> unsupportedTypes;
   bool result = true;

   for (auto &section : file.sections) {
      std::vector<elf::Rela> newRelocations;

      if (section->header.type.get() != elf::SHT_RELA) {
         continue;
      }

      // Clear flags
      section->header.flags = 0u;

      auto &symbolSection = file.sections[section->header.link.get()];

      auto rels = reinterpret_cast<elf::Rela *>(section->data.data());
      auto numRels = section->data.size() / sizeof(elf::Rela);
      for (size_t i = 0; i < numRels; ++i) {
         uint32_t info = rels[i].info.get();
         int32_t addend = rels[i].addend.get();
         uint32_t offset = rels[i].offset.get();
         uint32_t index = info >> 8;
         uint32_t type = info & 0xFF;

         switch (type) {
         case elf::R_PPC_NONE:
         case elf::R_PPC_ADDR32:
         case elf::R_PPC_ADDR16_LO:
         case elf::R_PPC_ADDR16_HI:
         case elf::R_PPC_ADDR16_HA:
         case elf::R_PPC_REL24:
         case elf::R_PPC_REL14:
         case elf::R_PPC_DTPMOD32:
         case elf::R_PPC_DTPREL32:
         case elf::R_PPC_EMB_SDA21:
         case elf::R_PPC_EMB_RELSDA:
         case elf::R_PPC_DIAB_SDA21_LO:
         case elf::R_PPC_DIAB_SDA21_HI:
         case elf::R_PPC_DIAB_SDA21_HA:
         case elf::R_PPC_DIAB_RELSDA_LO:
         case elf::R_PPC_DIAB_RELSDA_HI:
         case elf::R_PPC_DIAB_RELSDA_HA:
            // All valid relocations on Wii U, do nothing
            break;

         // Convert a R_PPC_REL32 into two GHS_REL16
         case elf::R_PPC_REL32:
         {
            size_t numSymbols = symbolSection->data.size() / sizeof(elf::Symbol);
            if (index >= numSymbols) {
               err = "could not find symbol for fixing a R_PPC_REL32 relocation";
               result = false;
            } else {
               newRelocations.emplace_back();
               auto &newRel = newRelocations.back();

               // Modify current relocation to R_PPC_GHS_REL16_HI
               rels[i].info = (index << 8) | elf::R_PPC_GHS_REL16_HI;
               rels[i].addend = addend;
               rels[i].offset = offset;

               // Create a R_PPC_GHS_REL16_LO
               newRel.info = (index << 8) | elf::R_PPC_GHS_REL16_LO;
               newRel.addend = addend + 2;
               newRel.offset = offset + 2;
            }
            break;
         }

         default:
            if (!unsupportedTypes.count(type)) {
               err = "unsupported relocation type " + std::to_string(type) +
                     " (ELF was probably not built for Wii U / with wut)";
               unsupportedTypes.insert(type);
            }
         }
      }

      section->data.insert(section->data.end(),
                           reinterpret_cast<char *>(newRelocations.data()),
                           reinterpret_cast<char *>(newRelocations.data() + newRelocations.size()));
   }

   return result && unsupportedTypes.size() == 0;
}

// Fix file header to look like an RPL file!
inline bool fixFileHeader(ElfFile &file)
{
   auto &h = file.header;
   h.magic = elf::HeaderMagic;
   h.fileClass = static_cast<uint8_t>(1);
   h.encoding = elf::ELFDATA2MSB;
   h.elfVersion = elf::EV_CURRENT;
   h.abi = elf::EABI_CAFE;
   std::memset(&h.pad, 0, 7);
   h.type = static_cast<uint16_t>(0xFE01);
   h.machine = elf::EM_PPC;
   h.version = 1u;
   h.flags = 0u;
   h.phoff = 0u;
   h.phentsize = static_cast<uint16_t>(0);
   h.phnum = static_cast<uint16_t>(0);
   h.shoff = alignUp(static_cast<uint32_t>(sizeof(elf::Header)), 64);
   h.shnum = static_cast<uint16_t>(file.sections.size() - file.numDiscarded);
   h.shentsize = static_cast<uint16_t>(sizeof(elf::SectionHeader));
   h.ehsize = static_cast<uint16_t>(sizeof(elf::Header));
   h.shstrndx = static_cast<uint16_t>(file.sections[h.shstrndx.get()]->index);
   return true;
}

// Relocate a section to a new address.
inline bool relocateSection(ElfFile &file, Section &section, uint32_t sectionIndex, uint32_t newSectionAddress)
{
   auto sectionSize = section.data.size() ? section.data.size() : static_cast<size_t>(section.header.size.get());
   uint32_t oldSectionAddress = section.header.addr.get();
   uint64_t oldSectionAddressEnd = static_cast<uint64_t>(oldSectionAddress) + sectionSize;

   // Relocate symbols pointing into this section
   for (auto &symSection : file.sections) {
      if (symSection->header.type.get() != elf::SHT_SYMTAB) {
         continue;
      }

      auto symbols = reinterpret_cast<elf::Symbol *>(symSection->data.data());
      auto numSymbols = symSection->data.size() / sizeof(elf::Symbol);
      for (size_t i = 0; i < numSymbols; ++i) {
         uint32_t type = symbols[i].info.get() & 0xf;
         uint32_t value = symbols[i].value.get();

         // Only relocate data, func, section symbols
         if (type != elf::STT_OBJECT && type != elf::STT_FUNC && type != elf::STT_SECTION) {
            continue;
         }

         if (value >= oldSectionAddress && value <= oldSectionAddressEnd) {
            symbols[i].value = (value - oldSectionAddress) + newSectionAddress;
         }
      }
   }

   // Relocate relocations pointing into this section
   for (auto &relaSection : file.sections) {
      if (relaSection->header.type.get() != elf::SHT_RELA || relaSection->header.info.get() != sectionIndex) {
         continue;
      }

      auto rela = reinterpret_cast<elf::Rela *>(relaSection->data.data());
      auto numRelas = relaSection->data.size() / sizeof(elf::Rela);
      for (size_t i = 0; i < numRelas; ++i) {
         uint32_t offset = rela[i].offset.get();

         if (offset >= oldSectionAddress && offset <= oldSectionAddressEnd) {
            rela[i].offset = (offset - oldSectionAddress) + newSectionAddress;
         }
      }
   }

   section.header.addr = newSectionAddress;
   return true;
}

// Rename __rplwrap_<name> to <name>, and if <name> already exists rename it to
// __rplwrap_<name>.
inline bool renameRplWrap(ElfFile &file)
{
   auto strtab = getSectionByName(file, ".strtab");
   if (strtab == nullptr || strtab->data.empty()) {
      return false;
   }
   auto strtabd = strtab->data.data();
   const size_t strtabSize = strtab->data.size();
   const std::string prefix(RplWrapPrefix);

   auto nameAt = [&](uint32_t off) -> std::string {
      if (off >= strtabSize) {
         return std::string();
      }
      const void *z = memchr(strtabd + off, 0, strtabSize - off);
      size_t len = z ? static_cast<size_t>(static_cast<const char *>(z) - (strtabd + off)) : strtabSize - off;
      return std::string(strtabd + off, len);
   };

   for (auto &symSection : file.sections) {
      if (symSection->header.type.get() != elf::SHT_SYMTAB) {
         continue;
      }

      auto symbols = reinterpret_cast<elf::Symbol *>(symSection->data.data());
      auto numSymbols = symSection->data.size() / sizeof(elf::Symbol);

      // First pass - find all the symbols prefixed with __rplwrap_
      std::vector<elf::Symbol *> foundRplWraps;

      for (size_t i = 0; i < numSymbols; ++i) {
         uint32_t type = symbols[i].info.get() & 0xf;

         // Only rename functions, data
         if (type != elf::STT_OBJECT && type != elf::STT_FUNC) {
            continue;
         }

         std::string name = nameAt(symbols[i].name.get());
         if (!name.compare(0, prefix.size(), prefix)) {
            foundRplWraps.push_back(&symbols[i]);
         }
      }

      // Second pass - swap names of conflicting symbols
      for (size_t i = 0; i < numSymbols; ++i) {
         uint32_t type = symbols[i].info.get() & 0xf;

         if (type != elf::STT_OBJECT && type != elf::STT_FUNC) {
            continue;
         }

         std::string symName = nameAt(symbols[i].name.get());

         auto rplWrap = foundRplWraps.begin();
         while (rplWrap != foundRplWraps.end()) {
            std::string wrapName = nameAt((*rplWrap)->name.get());
            std::string wrapNameBase = wrapName.substr(prefix.size());

            if (wrapNameBase == symName) {
               uint32_t a = (*rplWrap)->name.get();
               uint32_t b = symbols[i].name.get();
               (*rplWrap)->name = b;
               symbols[i].name = a;
               rplWrap = foundRplWraps.erase(rplWrap);
            } else {
               ++rplWrap;
            }
         }
      }

      // Final pass: rename any remaining (non-conflicting) symbols
      for (auto symbol : foundRplWraps) {
         symbol->name = symbol->name.get() + static_cast<uint32_t>(prefix.length());
      }
   }

   return true;
}

// Fix the loader virtual addresses. The linker script won't put symtab &
// strtab sections in the loader address range, so we must fix that.
inline bool fixLoaderVirtualAddresses(ElfFile &file)
{
   uint32_t loadMax = LoadBaseAddress;
   for (auto &section : file.sections) {
      if (section->header.addr.get() >= loadMax) {
         loadMax = section->header.addr.get() + static_cast<uint32_t>(section->data.size());
      }
   }

   // Relocate .symtab and .strtab to be in loader memory
   for (uint32_t i = 0; i < file.sections.size(); ++i) {
      auto &section = file.sections[i];
      if (section->header.type.get() == elf::SHT_SYMTAB || section->header.type.get() == elf::SHT_STRTAB) {
         loadMax = alignUp(loadMax, section->header.addralign.get());
         relocateSection(file, *section, i, loadMax);
         section->header.flags |= elf::SHF_ALLOC;
         loadMax += static_cast<uint32_t>(section->data.size());
      }
   }

   return true;
}

// zlib deflate any suitable section.
inline bool deflateSections(ElfFile &file)
{
   for (auto &section : file.sections) {
      if (section->data.size() < DeflateMinSectionSize ||
          section->header.type.get() == elf::SHT_RPL_CRCS ||
          section->header.type.get() == elf::SHT_RPL_FILEINFO) {
         continue;
      }

      z_stream stream;
      std::memset(&stream, 0, sizeof(stream));
      if (deflateInit(&stream, 6) != Z_OK) {
         return false;
      }

      // 4 bytes inflated size, followed by the zlib stream
      std::vector<char> deflated(4 + deflateBound(&stream, static_cast<uLong>(section->data.size())));

      stream.avail_in = static_cast<uInt>(section->data.size());
      stream.next_in = reinterpret_cast<Bytef *>(section->data.data());
      stream.avail_out = static_cast<uInt>(deflated.size() - 4);
      stream.next_out = reinterpret_cast<Bytef *>(deflated.data() + 4);

      int ret = deflate(&stream, Z_FINISH);
      if (ret != Z_STREAM_END) {
         deflateEnd(&stream);
         return false;
      }
      deflated.resize(4 + stream.total_out);
      deflateEnd(&stream);

      // Set the inflated size at start of section
      be_val<uint32_t> inflated(static_cast<uint32_t>(section->data.size()));
      std::memcpy(deflated.data(), &inflated, 4);

      section->data = std::move(deflated);
      section->header.flags |= elf::SHF_DEFLATED;
   }

   return true;
}

// Calculate section file offsets.
//
// Expected order:
// RPL_CRCS > RPL_FILEINFO >
// Data sections > Read sections > Text sections > Temp sections
inline bool calculateSectionOffsets(ElfFile &file, std::string &err)
{
   using namespace elf;
   uint32_t offset = file.header.shoff.get();
   offset += alignUp(static_cast<uint32_t>((file.sections.size() - file.numDiscarded) * sizeof(SectionHeader)), 64);

   // Set all offsets to 0, so we can detect sections we didn't relocate
   for (auto &section : file.sections) {
      section->header.offset = 0u;
   }

   for (auto &section : file.sections) {
      if (section->header.type.get() == SHT_NOBITS || section->header.type.get() == SHT_NULL) {
         section->header.offset = 0u;
         section->data.clear();
      }
   }

   auto place = [&](Section &s) {
      s.header.offset = offset;
      s.header.size = static_cast<uint32_t>(s.data.size());
      offset += s.header.size.get();
   };

   auto skipType = [](uint32_t t) {
      return t == SHT_RPL_FILEINFO || t == SHT_RPL_IMPORTS || t == SHT_RPL_CRCS || t == SHT_NOBITS;
   };

   for (auto &section : file.sections) {
      if (section->header.type.get() == SHT_RPL_CRCS) {
         place(*section);
      }
   }

   for (auto &section : file.sections) {
      if (section->header.type.get() == SHT_RPL_FILEINFO) {
         place(*section);
      }
   }

   // "dataMin / dataMax": !EXECINSTR, WRITE, ALLOC
   for (auto &section : file.sections) {
      const uint32_t fl = section->header.flags.get();
      if (section->header.size.get() == 0 || skipType(section->header.type.get())) {
         continue;
      }
      if (!(fl & SHF_EXECINSTR) && (fl & SHF_WRITE) && (fl & SHF_ALLOC)) {
         place(*section);
      }
   }

   // "readMin / readMax": EXPORTS/IMPORTS, or !(EXECINSTR|WRITE), ALLOC
   for (auto &section : file.sections) {
      const uint32_t fl = section->header.flags.get();
      if (section->header.size.get() > 0 && (fl & SHF_ALLOC)) {
         const uint32_t t = section->header.type.get();
         if (t == SHT_RPL_EXPORTS || t == SHT_RPL_IMPORTS || !(fl & (SHF_EXECINSTR | SHF_WRITE))) {
            place(*section);
         }
      }
   }

   // "textMin / textMax": EXECINSTR, type != EXPORTS
   for (auto &section : file.sections) {
      const uint32_t fl = section->header.flags.get();
      if (section->header.size.get() == 0 || skipType(section->header.type.get())) {
         continue;
      }
      if ((fl & SHF_EXECINSTR) && section->header.type.get() != SHT_RPL_EXPORTS) {
         place(*section);
      }
   }

   // "tempMin / tempMax": !EXECINSTR, !ALLOC
   for (auto &section : file.sections) {
      const uint32_t fl = section->header.flags.get();
      if (section->header.size.get() == 0 || skipType(section->header.type.get())) {
         continue;
      }
      if (!(fl & SHF_EXECINSTR) && !(fl & SHF_ALLOC)) {
         place(*section);
      }
   }

   for (auto &section : file.sections) {
      if (section->header.offset.get() == 0 &&
          section->header.type.get() != SHT_NULL &&
          section->header.type.get() != SHT_NOBITS) {
         err = "failed to calculate offset for section '" + section->name + "'";
         return false;
      }

      if (section->index == UnusedIndex) {
         continue;
      }

      if (section->header.link.get()) {
         section->header.link = file.sections[section->header.link.get()]->index;
      }

      if (section->header.type.get() == SHT_RELA) {
         section->header.info = file.sections[section->header.info.get()]->index;
      }
   }

   return true;
}

// Write out the final RPL. Written strictly front to back (zero-padded gaps)
// so it behaves on FAT/SD devoptabs.
inline bool writeRpl(ElfFile &file, const std::string &filename, std::string &err)
{
   struct Seg { uint32_t off; const void *ptr; size_t len; };
   std::vector<Seg> segs;

   std::vector<elf::SectionHeader> headers;
   for (const auto &s : file.sections) {
      if (s->index != UnusedIndex) {
         headers.push_back(s->header);
      }
   }

   segs.push_back({ 0, &file.header, sizeof(elf::Header) });
   segs.push_back({ file.header.shoff.get(), headers.data(), headers.size() * sizeof(elf::SectionHeader) });
   for (const auto &s : file.sections) {
      if (s->data.size()) {
         segs.push_back({ s->header.offset.get(), s->data.data(), s->data.size() });
      }
   }

   std::stable_sort(segs.begin(), segs.end(), [](const Seg &a, const Seg &b) { return a.off < b.off; });

   FILE *out = fopen(filename.c_str(), "wb");
   if (!out) {
      err = "could not open output file for writing";
      return false;
   }

   uint64_t pos = 0;
   static const char zeros[64] = { 0 };
   bool ok = true;

   for (const auto &seg : segs) {
      if (seg.off < pos) {
         err = "internal error: overlapping sections in output layout";
         ok = false;
         break;
      }
      uint64_t gap = seg.off - pos;
      while (gap) {
         size_t n = gap > sizeof(zeros) ? sizeof(zeros) : static_cast<size_t>(gap);
         if (fwrite(zeros, 1, n, out) != n) { ok = false; break; }
         gap -= n;
      }
      if (!ok) break;
      if (fwrite(seg.ptr, 1, seg.len, out) != seg.len) { ok = false; break; }
      pos = static_cast<uint64_t>(seg.off) + seg.len;
   }

   if (fclose(out) != 0) {
      ok = false;
   }
   if (!ok && err.empty()) {
      err = "write error (SD card full?)";
   }
   return ok;
}

} // namespace detail

// Convert `src` (an .elf) to `dst` (an .rpx, or .rpl if isRpl). On failure
// returns false and sets `error`.
inline bool convert(const std::string &src, const std::string &dst, bool isRpl, std::string &error)
{
   detail::ElfFile elf;
   error.clear();

   if (!detail::readElf(elf, src, error)) {
      return false;
   }
   if (!detail::fixRelocations(elf, error)) {
      if (error.empty()) error = "fixRelocations failed";
      return false;
   }
   if (!detail::renameRplWrap(elf)) {
      error = "no .strtab (ELF is stripped)";
      return false;
   }
   if (!detail::fixLoaderVirtualAddresses(elf)) {
      error = "fixLoaderVirtualAddresses failed";
      return false;
   }
   if (!detail::generateFileInfoSection(elf, isRpl ? 0 : elf::RPL_IS_RPX)) {
      error = "generateFileInfoSection failed";
      return false;
   }
   if (!detail::generateCrcSection(elf)) {
      error = "generateCrcSection failed";
      return false;
   }
   if (!detail::fixFileHeader(elf)) {
      error = "fixFileHeader failed";
      return false;
   }
   if (!detail::deflateSections(elf)) {
      error = "zlib deflate failed";
      return false;
   }
   if (!detail::calculateSectionOffsets(elf, error)) {
      return false;
   }
   return detail::writeRpl(elf, dst, error);
}

} // namespace elf2rpl
