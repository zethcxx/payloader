module;

export module utils;

import lbyte.stx;
import winstructs;

using namespace lbyte::stx;
using namespace win;

export template<typename T>
inline constexpr auto get_peb() {
    ptr<T> peb;
    asm volatile( "mov %0, gs:[0x60]" : "=r"(peb));
    return peb;
}

export [[nodiscard]]
inline auto ldr_entry(ptr<LIST_ENTRY> links)
{
    return ptr<LDR_DATA_TABLE_ENTRY>{ links.addr() - 0x010 };
}

export template<usize N = 2> [[nodiscard]]
inline auto module_entry(ptr<PEB> peb)
{
    auto entry = peb->Ldr->InMemoryOrderModuleList.Flink;
    for ( [[maybe_unused]] auto i : range<usize>(N) )
        entry = entry->Flink;

    return ldr_entry(entry);
}


export template<typename T> [[nodiscard]]
inline auto container_of(ptr<LIST_ENTRY> member, usize offset)
{
    return ptr<T>{ member.as<uptr>() - offset };
}

export struct FnvHash
{
    private:
        static constexpr u32 BASIS = 0xABEDB10C;
        static constexpr u32 PRIME = 0x01000193;

        [[nodiscard]] inline constexpr static auto update( u32 current_hash, u8 byte ) -> u32 {
            return ( current_hash ^ byte ) * PRIME;
        }

        template<ct::fixed_string str>
        [[nodiscard]] constexpr static auto static_hash() -> u32 {
            u32 hash = BASIS;
            for ( auto idx : range<usize>(str.size()) )
                hash = update(hash, scast<u8>(str[idx]));

            return hash;
        }

    public:

        [[nodiscard]] inline static auto cstr(const u8* str, size_t size = 0) -> u32 {
            u32 hash = BASIS;

            if (size == 0)
                while (*str)
                    hash = update(hash, *str++);
            else
                for ( auto i : range<usize>( size ))
                    hash = update(hash, str[i]);

            return hash;
        }

        template<ct::fixed_string Str>
        static constexpr u32 str = static_hash<Str>();
};

