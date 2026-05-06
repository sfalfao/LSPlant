#pragma once

#include <link.h>
#include <linux/elf.h>
#include <map>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <type_traits>

#define SHT_GNU_HASH 0x6ffffff6

namespace lsparself {

class Elf {
public:
    explicit Elf(std::string_view elf);

    template <typename T = void*>
    requires(std::is_pointer_v<T>)
    constexpr T getSymbAddress(std::string_view name) const {
        auto offset = getSymbOffset(name, GnuHash(name), ElfHash(name));
        if (offset > 0 && base_ != nullptr) {
            return reinterpret_cast<T>(static_cast<ElfW(Addr)>(
                    reinterpret_cast<uintptr_t>(base_) + offset - bias_));
        }
        return nullptr;
    }

    template <typename T = void*>
    requires(std::is_pointer_v<T>)
    constexpr T getSymbPrefixFirstAddress(std::string_view prefix) const {
        auto offset = PrefixLookupFirst(prefix);
        if (offset > 0 && base_ != nullptr) {
            return reinterpret_cast<T>(static_cast<ElfW(Addr)>(
                    reinterpret_cast<uintptr_t>(base_) + offset - bias_));
        }
        return nullptr;
    }

    ~Elf();

private:
    ElfW(Addr) getSymbOffset(std::string_view name, uint32_t gnu_hash, uint32_t elf_hash) const;
    ElfW(Addr) ElfLookup(std::string_view name, uint32_t hash) const;
    ElfW(Addr) GnuLookup(std::string_view name, uint32_t hash) const;
    ElfW(Addr) LinearLookup(std::string_view name) const;
    ElfW(Addr) PrefixLookupFirst(std::string_view prefix) const;
    void MayInitLinearMap() const;
    bool findModuleBase();

    constexpr static uint32_t ElfHash(std::string_view name) {
        uint32_t h = 0;
        for (unsigned char p : name) {
            h = (h << 4) + p;
            auto g = h & 0xf0000000;
            h ^= g;
            h ^= g >> 24;
        }
        return h;
    }

    constexpr static uint32_t GnuHash(std::string_view name) {
        uint32_t h = 5381;
        for (unsigned char p : name) {
            h += (h << 5) + p;
        }
        return h;
    }

    std::string elf_;
    void* base_ = nullptr;
    off_t size_ = 0;
    off_t bias_ = -4396;
    ElfW(Ehdr)* header_ = nullptr;
    ElfW(Shdr)* dynsym_ = nullptr;
    ElfW(Shdr)* strtab_ = nullptr;
    ElfW(Sym)* symtab_start_ = nullptr;
    ElfW(Sym)* dynsym_start_ = nullptr;
    ElfW(Sym)* strtab_start_ = nullptr;
    ElfW(Off) symtab_count_ = 0;
    ElfW(Off) symstr_offset_for_symtab_ = 0;

    uint32_t nbucket_ = 0;
    uint32_t* bucket_ = nullptr;
    uint32_t* chain_ = nullptr;

    uint32_t gnu_nbucket_ = 0;
    uint32_t gnu_symndx_ = 0;
    uint32_t gnu_bloom_size_ = 0;
    uint32_t gnu_shift2_ = 0;
    uintptr_t* gnu_bloom_filter_ = nullptr;
    uint32_t* gnu_bucket_ = nullptr;
    uint32_t* gnu_chain_ = nullptr;

    mutable std::multimap<std::string_view, ElfW(Sym)*> symtabs_;
};

}  // namespace lsparself
