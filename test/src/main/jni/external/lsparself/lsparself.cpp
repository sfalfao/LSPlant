#include "include/lsparself.h"

#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

template <typename T>
inline constexpr auto offsetOf(ElfW(Ehdr)* head, ElfW(Off) off) {
    return reinterpret_cast<std::conditional_t<std::is_pointer_v<T>, T, T*>>(
            reinterpret_cast<uintptr_t>(head) + off);
}

namespace {
constexpr bool contains(std::string_view a, std::string_view b) {
    return a.find(b) != std::string_view::npos;
}
}  // namespace

namespace lsparself {

Elf::Elf(std::string_view elf) : elf_(elf) {
    if (!findModuleBase()) return;

    int fd = open(elf_.data(), O_RDONLY);
    if (fd < 0) return;

    size_ = lseek(fd, 0, SEEK_END);
    if (size_ <= 0) {
        close(fd);
        return;
    }

    header_ = reinterpret_cast<decltype(header_)>(mmap(nullptr, size_, PROT_READ, MAP_SHARED, fd, 0));
    close(fd);
    if (header_ == MAP_FAILED) {
        header_ = nullptr;
        return;
    }

    auto* section_header = offsetOf<ElfW(Shdr)*>(header_, header_->e_shoff);
    char* section_str = offsetOf<char*>(header_, section_header[header_->e_shstrndx].sh_offset);

    for (int i = 0; i < header_->e_shnum; i++) {
        auto* section_h =
                reinterpret_cast<ElfW(Shdr)*>(reinterpret_cast<uintptr_t>(section_header) + i * header_->e_shentsize);
        char* sname = section_h->sh_name + section_str;
        auto entsize = section_h->sh_entsize;
        switch (section_h->sh_type) {
            case SHT_DYNSYM:
                if (bias_ == -4396) {
                    dynsym_ = section_h;
                    dynsym_start_ = offsetOf<decltype(dynsym_start_)>(header_, section_h->sh_offset);
                }
                break;
            case SHT_SYMTAB:
                if (strcmp(sname, ".symtab") == 0) {
                    symtab_start_ = offsetOf<decltype(symtab_start_)>(header_, section_h->sh_offset);
                    symtab_count_ = section_h->sh_size / entsize;
                }
                break;
            case SHT_STRTAB:
                if (bias_ == -4396) {
                    strtab_ = section_h;
                    strtab_start_ = offsetOf<decltype(strtab_start_)>(header_, section_h->sh_offset);
                }
                if (strcmp(sname, ".strtab") == 0) {
                    symstr_offset_for_symtab_ = section_h->sh_offset;
                }
                break;
            case SHT_PROGBITS:
                if (strtab_ != nullptr && dynsym_ != nullptr && bias_ == -4396) {
                    bias_ = static_cast<off_t>(section_h->sh_addr) - static_cast<off_t>(section_h->sh_offset);
                }
                break;
            case SHT_HASH: {
                auto* d_un = offsetOf<ElfW(Word)*>(header_, section_h->sh_offset);
                nbucket_ = d_un[0];
                bucket_ = d_un + 2;
                chain_ = bucket_ + nbucket_;
                break;
            }
            case SHT_GNU_HASH: {
                auto* d_buf = reinterpret_cast<ElfW(Word)*>(reinterpret_cast<size_t>(header_) + section_h->sh_offset);
                gnu_nbucket_ = d_buf[0];
                gnu_symndx_ = d_buf[1];
                gnu_bloom_size_ = d_buf[2];
                gnu_shift2_ = d_buf[3];
                gnu_bloom_filter_ = reinterpret_cast<decltype(gnu_bloom_filter_)>(d_buf + 4);
                gnu_bucket_ = reinterpret_cast<decltype(gnu_bucket_)>(gnu_bloom_filter_ + gnu_bloom_size_);
                gnu_chain_ = gnu_bucket_ + gnu_nbucket_ - gnu_symndx_;
                break;
            }
            default:
                break;
        }
    }
}

ElfW(Addr) Elf::ElfLookup(std::string_view name, uint32_t hash) const {
    if (nbucket_ == 0 || dynsym_start_ == nullptr || strtab_start_ == nullptr) return 0;
    char* strings = reinterpret_cast<char*>(strtab_start_);
    for (auto n = bucket_[hash % nbucket_]; n != 0; n = chain_[n]) {
        auto* sym = dynsym_start_ + n;
        if (name == strings + sym->st_name) return sym->st_value;
    }
    return 0;
}

ElfW(Addr) Elf::GnuLookup(std::string_view name, uint32_t hash) const {
    static constexpr auto bloom_mask_bits = sizeof(ElfW(Addr)) * 8;
    if (gnu_nbucket_ == 0 || gnu_bloom_size_ == 0 || dynsym_start_ == nullptr || strtab_start_ == nullptr) return 0;

    auto bloom_word = gnu_bloom_filter_[(hash / bloom_mask_bits) % gnu_bloom_size_];
    uintptr_t mask = 0 | static_cast<uintptr_t>(1) << (hash % bloom_mask_bits) |
                     static_cast<uintptr_t>(1) << ((hash >> gnu_shift2_) % bloom_mask_bits);
    if ((mask & bloom_word) != mask) return 0;

    auto sym_index = gnu_bucket_[hash % gnu_nbucket_];
    if (sym_index < gnu_symndx_) return 0;

    char* strings = reinterpret_cast<char*>(strtab_start_);
    do {
        auto* sym = dynsym_start_ + sym_index;
        if (((gnu_chain_[sym_index] ^ hash) >> 1) == 0 && name == strings + sym->st_name) return sym->st_value;
    } while ((gnu_chain_[sym_index++] & 1) == 0);
    return 0;
}

void Elf::MayInitLinearMap() const {
    if (!symtabs_.empty() || symtab_start_ == nullptr || symstr_offset_for_symtab_ == 0) return;
    for (ElfW(Off) i = 0; i < symtab_count_; i++) {
        unsigned int st_type = ELF_ST_TYPE(symtab_start_[i].st_info);
        const char* st_name =
                offsetOf<const char*>(header_, symstr_offset_for_symtab_ + symtab_start_[i].st_name);
        if ((st_type == STT_FUNC || st_type == STT_OBJECT) && symtab_start_[i].st_size) {
            symtabs_.emplace(st_name, &symtab_start_[i]);
        }
    }
}

ElfW(Addr) Elf::LinearLookup(std::string_view name) const {
    MayInitLinearMap();
    if (auto i = symtabs_.find(name); i != symtabs_.end()) return i->second->st_value;
    return 0;
}

ElfW(Addr) Elf::PrefixLookupFirst(std::string_view prefix) const {
    MayInitLinearMap();
    if (auto i = symtabs_.lower_bound(prefix); i != symtabs_.end() && i->first.starts_with(prefix)) {
        return i->second->st_value;
    }
    return 0;
}

ElfW(Addr) Elf::getSymbOffset(std::string_view name, uint32_t gnu_hash, uint32_t elf_hash) const {
    if (auto offset = GnuLookup(name, gnu_hash); offset > 0) return offset;
    if (auto offset = ElfLookup(name, elf_hash); offset > 0) return offset;
    return LinearLookup(name);
}

bool Elf::findModuleBase() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;

    char* buff = nullptr;
    size_t len = 0;
    ssize_t nread;
    bool found = false;
    off_t load_addr = 0;

    while ((nread = getline(&buff, &len, maps)) != -1) {
        std::string_view line{buff, static_cast<size_t>(nread)};
        if ((contains(line, "r-xp") || contains(line, "r--p")) && contains(line, elf_)) {
            if (auto begin = line.find_last_of(' '); begin != std::string_view::npos && line[++begin] == '/') {
                found = true;
                elf_ = line.substr(begin);
                if (!elf_.empty() && elf_.back() == '\n') elf_.pop_back();
                load_addr = strtoul(buff, nullptr, 16);
                break;
            }
        }
    }

    if (buff) free(buff);
    fclose(maps);
    if (!found) return false;

    base_ = reinterpret_cast<void*>(load_addr);
    return true;
}

Elf::~Elf() {
    if (header_ != nullptr) munmap(header_, size_);
}

}  // namespace lsparself
