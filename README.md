# PAYLOADER

```
  shellcode pipeline  ·  C++23 modules  ·  xmake
```

> **Disclaimer** — This project is for educational and research purposes only.
> It explores whether C++23 modules can replace assembly (nasm) for shellcode
> generation. Do not use for anything illegal or unethical.

A research project that compiles position-independent C++23 code into
a custom section, extracts it via `objcopy`, converts the raw binary to
a `constexpr` C++ header, and loads/runs it at runtime.

---

## Structure

```sh
src/
├── core/
│   ├── winstructs.cppm           # PE / PEB structure definitions (DOS_HEADER, NT_HEADERS64, EXPORT_DIRECTORY, PEB, LDR, ...)
│   │
│   └── utils.cppm                # PEB walking, FNV-1a hashing, module resolution
├── payload.cpp                   # Freestanding shellcode (hash-based API lookup)
└── loader.cpp                    # Runner: VirtualAlloc -> copy -> VirtualProtect -> CreateThread

xmake/
├── rules/
│   ├── payload_extract.lua       # objcopy --dump-section .payload -> .bin
│   └── payload_bin.lua           # Plain copy fallback for non-section targets
├── modules/
│   ├── payload_header.lua        # .bin -> C++ constexpr std::array header
│   ├── actions.lua               # configure & run hooks
│   └── cfg/
│       ├── triple.lua            # Target triple detection
│       └── flags.lua             # Per-toolchain C++23 flag generation
└── packages/l/lbyte.stx/         # Local package definition for lbyte.stx
```

---

## Flow

```
  payload.cpp
       |
       |  xmake build (C++23, freestanding, no stdlib)
       v
  payload.exe
       |
       |  llvm-objcopy --dump-section .payload
       v
  payload.bin
       |
       |  payload_header.lua  (converts to constexpr header)
       v
  include/generated/payload.hpp
       |
       |  #include "generated/payload.hpp"
       v
  loader.cpp -> loader.exe
       |
       |  VirtualAlloc -> memcpy -> VirtualProtect(PAGE_EXECUTE_READ)
       v
  CreateThread -> shellcode runs
```

During `xmake f`, a placeholder header is written so the LSP never
complains about a missing include.

---

## Modules

### `winstructs`

Portable definitions for the Windows structures needed to walk the PEB
and parse PE export tables without any system headers:

- `TEB`, `PEB`, `PEB_LDR_DATA`, `LDR_DATA_TABLE_ENTRY`
- `RTL_USER_PROCESS_PARAMETERS`
- `UNICODE_STRING`, `LIST_ENTRY`
- `DOS_HEADER`, `FILE_HEADER`, `OPTIONAL_HEADER64`, `NT_HEADERS64`
- `EXPORT_DIRECTORY`, `SECTION_HEADER`, `DATA_DIRECTORY`

### `utils`

Helper functions for positioning and API resolution:

- `get_peb<T>()` -- reads `gs:[0x60]` to get the PEB
- `ldr_entry()` -- casts `LIST_ENTRY` back to `LDR_DATA_TABLE_ENTRY`
- `module_entry<N>()` -- returns the Nth entry from `InMemoryOrderModuleList`
- `container_of<T>()` -- generic `LIST_ENTRY` back-cast
- `FnvHash` -- compile-time and runtime FNV-1a hashing

### `payload.cpp`

The actual shellcode. Freestanding, no CRT, no imports. Uses the modules above to:

1. Read the PEB via `gs:[0x60]`
2. Walk `InMemoryOrderModuleList` to find kernel32
3. Parse its PE headers to reach the export directory
4. Hash-compare exported names to find `WinExec`
5. Call `WinExec("notepad.exe", 5)`

### `loader.cpp`

A minimal PE runner:

- `VirtualAlloc` with `PAGE_READWRITE`
- `std::copy` the shellcode bytes
- `VirtualProtect` to `PAGE_EXECUTE_READ`
- `CreateThread` pointing at the allocated memory
- `WaitForSingleObject` until completion

> [!NOTE]
> ~200 KB of the generated executable size comes from \<print\>

---

## Build & Run

```bash
# Configure (cross-compile for Windows target)
xmake f --toolchain=clang -y

# Or on Linux with GCC module support
xmake f --toolchain=gcc -y

# Build everything
xmake build

# Run
xmake run loader

# Or run directly
./build/wincross/x86_64/release/loader.exe
```

---

## Dependencies

- **lbyte.stx v0.2.0** -- C++23 systems toolbelt (bit, ct, endian, fn,
  io, literals, mem, range, time) -- `github.com/zethcxx/stx`

## Requirements

- xmake >= 2.8.0
- C++23 compiler (Clang 21+ / GCC 16+)
- `llvm-objcopy` (or `objcopy` / `gobjcopy`)

---

## The `auto` Crypt Trick

A single `constexpr` function that works in two modes depending on the
type `auto` deduces:

```cpp
constexpr auto crypt(auto arr, auto key) {
    for (auto idx : range( arr.size() ))
        arr[idx] ^= key[idx % key.size() ];
    return arr;
}
```

`crypt` is a **template** — `auto` parameters are shorthand for `template<typename T, typename K>`. Each call instantiates a different specialization.

### Mode 1 — Compile time (std::array + string_view)

```cpp
constexpr auto key       = "patatas"sv;
constexpr auto shellcode = crypt(payload::data(), key);
```

- `arr` -> `std::array<u8, 206>` (copied by value, NRVO)
- `key` -> `std::string_view` (view wrapper to array literal)
- Everything is `constexpr`, so the XOR runs at compile time
- Only `shellcode` (encrypted) is materialized in `.rdata`
- The raw bytes of `payload::data()` never reach the binary

### Mode 2 — Runtime mutation (std::span)

```cpp
crypt( span{ rcast<u8*>(exec_mem.get()), shellcode.size() }, key );
```

- `arr` -> `std::span<u8, 206>` (16 bytes on stack, references `exec_mem`)
- `key` -> `std::string_view` (same as before)
- `operator[]` resolves through the span's internal pointer
- XOR mutates `exec_mem` **in-place**, no extra data copies

### Specializations the compiler generates

| Call                          | `arr` type            | Value copy                           |
|-------------------------------|-----------------------|--------------------------------------|
| `crypt(payload::data(), key)` | `std::array<u8, 206>` | 206 bytes **constexpr** (folded)     |
| `crypt(std::span{...}, key)`  | `std::span<u8, 206>`  | 16 bytes **runtime** (pointer + len) |

One function, two instantiations, zero overhead on the payload bytes.

