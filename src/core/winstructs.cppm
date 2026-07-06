// ---------------------------------------------------------------------------------------------- //
                                   export module winstructs;
// ---------------------------------------------------------------------------------------------- //

import lbyte.stx;

using namespace lbyte::stx;

export namespace win
{
    // -- Forward Declarations ---------------------------------------------------------------------
    struct PEB                        ;
    struct PEB_LDR_DATA               ;
    struct LDR_DATA_TABLE_ENTRY       ;
    struct RTL_USER_PROCESS_PARAMETERS;


    struct LIST_ENTRY {
        /* 0x00 */ ptr<LIST_ENTRY> Flink;
        /* 0x08 */ ptr<LIST_ENTRY> Blink;
    };


    struct UNICODE_STRING {
        /* 0x00 */ u16      Length       ;
        /* 0x02 */ u16      MaximumLength;
        /* 0x04 */ u32      Padding      ;
        /* 0x08 */ ptr<u16> Buffer       ;
    };


    // -- Thread Environment Block -----------------------------------------------------------------
    // x64: mov rax, gs:[0x30]  -> TEB self
    //      mov rax, gs:[0x60]  -> PEB (process environment block)
    struct TEB
    {
        /* 0x000 */ ptr<void>    ExceptionList            ; // NT_TIB
        /* 0x008 */ ptr<void>    StackBase                ;
        /* 0x010 */ ptr<void>    StackLimit               ;
        /* 0x018 */ ptr<void>    SubSystemTib             ;
        /* 0x020 */ ptr<void>    FiberData                ;
        /* 0x028 */ ptr<void>    ArbitraryUserPointer     ;
        /* 0x030 */ ptr<TEB>     Self                     ;
        /* 0x038 */ ptr<void>    EnvironmentPointer       ;
        /* 0x040 */ ptr<void>    ClientId[2]              ; // UniqueProcess, UniqueThread
        /* 0x050 */ ptr<void>    ActiveRpcHandle          ;
        /* 0x058 */ ptr<void>    ThreadLocalStoragePointer;
        /* 0x060 */ ptr<PEB>     ProcessEnvironmentBlock  ;
    };


    // -- Process Environment Block ----------------------------------------------------------------
    // mov rax, gs:[0x60] -> PEB
    struct PEB
    {
        /* 0x000 */ u8                                 InheritedAddressSpace   ;
        /* 0x001 */ u8                                 ReadImageFileExecOptions;
        /* 0x002 */ u8                                 BeingDebugged           ;  // anti-debug
        /* 0x003 */ u8                                 BitField                ;
        /* 0x004 */ u8                                 Reserved4[4]            ;
        /* 0x008 */ ptr<void>                          Mutant                  ;
        /* 0x010 */ ptr<void>                          ImageBaseAddress        ;  // base of .exe
        /* 0x018 */ ptr<PEB_LDR_DATA>                  Ldr                     ;
        /* 0x020 */ ptr<RTL_USER_PROCESS_PARAMETERS>   ProcessParameters       ;
        /* 0x028 */ ptr<void>                          SubSystemData           ;
        /* 0x030 */ ptr<void>                          ProcessHeap             ;
        /* 0x038 */ ptr<void>                          FastPebLock             ;
        /* 0x040 */ ptr<void>                          FastPebLockRoutine      ;
        /* 0x048 */ ptr<void>                          KernelCallbackTable     ;
        /* 0x050 */ u32                                SystemReserved          ;
        /* 0x054 */ u32                                AtlThunkSList32         ;
        /* 0x058 */ ptr<void>                          ApiSetMap               ;
    };


    struct PEB_LDR_DATA
    {
        /* 0x000 */ u32          Length                         ;
        /* 0x004 */ u8           Initialized                    ;
        /* 0x005 */ u8           Reserved5[3]                   ;
        /* 0x008 */ ptr<void>    SsHandle                       ;
        /* 0x010 */ LIST_ENTRY   InLoadOrderModuleList          ;
        /* 0x020 */ LIST_ENTRY   InMemoryOrderModuleList        ;
        /* 0x030 */ LIST_ENTRY   InInitializationOrderModuleList;
        /* 0x040 */ ptr<void>    EntryInProgress                ;
    };


    struct LDR_DATA_TABLE_ENTRY
    {
        /* 0x000 */ LIST_ENTRY       InLoadOrderLinks          ;
        /* 0x010 */ LIST_ENTRY       InMemoryOrderLinks        ;
        /* 0x020 */ LIST_ENTRY       InInitializationOrderLinks;
        /* 0x030 */ ptr<void>        DllBase                   ;
        /* 0x038 */ ptr<void>        EntryPoint                ;
        /* 0x040 */ u32              SizeOfImage               ;
        /* 0x044 */ u8               Reserved44[4]             ;
        /* 0x048 */ UNICODE_STRING   FullDllName               ;
        /* 0x058 */ UNICODE_STRING   BaseDllName               ;
    };


    struct RTL_USER_PROCESS_PARAMETERS
    {
        /* 0x000 */ u32             MaximumLength          ;
        /* 0x004 */ u32             Length                 ;
        /* 0x008 */ u32             Flags                  ;
        /* 0x00C */ u32             DebugFlags             ;
        /* 0x010 */ ptr<void>       ConsoleHandle          ;
        /* 0x018 */ u32             ConsoleFlags           ;
        /* 0x01C */ u8              Reserved1C[4]          ;
        /* 0x020 */ ptr<void>       StandardInput          ;
        /* 0x028 */ ptr<void>       StandardOutput         ;
        /* 0x030 */ ptr<void>       StandardError          ;
        /* 0x038 */ u8              CurrentDirectory[0x018];   // CURDIR (UNICODE_STRING + HANDLE)
        /* 0x050 */ UNICODE_STRING  DllPath                ;
        /* 0x060 */ UNICODE_STRING  ImagePathName          ;
        /* 0x070 */ UNICODE_STRING  CommandLine            ;
    };


    // ===========================================================
    //  PE Format Structures (x64)
    // ===========================================================


    // -- IMAGE_DOS_HEADER -------------------------------------------------------------------------
    struct DOS_HEADER
    {
        /* 0x000 */ u16       e_magic   ;   // "MZ"
        /* 0x002 */ u16       e_cblp    ;
        /* 0x004 */ u16       e_cp      ;
        /* 0x006 */ u16       e_crlc    ;
        /* 0x008 */ u16       e_cparhdr ;
        /* 0x00A */ u16       e_minalloc;
        /* 0x00C */ u16       e_maxalloc;
        /* 0x00E */ u16       e_ss      ;
        /* 0x010 */ u16       e_sp      ;
        /* 0x012 */ u16       e_csum    ;
        /* 0x014 */ u16       e_ip      ;
        /* 0x016 */ u16       e_cs      ;
        /* 0x018 */ u16       e_lfarlc  ;
        /* 0x01A */ u16       e_ovno    ;
        /* 0x01C */ u16       e_res[4]  ;
        /* 0x024 */ u16       e_oemid   ;
        /* 0x026 */ u16       e_oeminfo ;
        /* 0x028 */ u16       e_res2[10];
        /* 0x03C */ rva_s     e_lfanew  ;   // RVA to NT headers
    };


    // -- IMAGE_FILE_HEADER ------------------------------------------------------------------------
    struct FILE_HEADER
    {
        /* 0x000 */ u16      Machine             ;  // 0x8664 -> x64
        /* 0x002 */ u16      NumberOfSections    ;
        /* 0x004 */ u32      TimeDateStamp       ;
        /* 0x008 */ u32      PointerToSymbolTable;
        /* 0x00C */ u32      NumberOfSymbols     ;
        /* 0x010 */ u16      SizeOfOptionalHeader;
        /* 0x012 */ u16      Characteristics     ;
    };


    // -- IMAGE_EXPORT_DIRECTORY -------------------------------------------------------------------
    struct DATA_DIRECTORY {
        /* 0x000 */ rva_s   VirtualAddress;   // RVA of directory
        /* 0x004 */ u32     Size          ;
    };


    // -- IMAGE_OPTIONAL_HEADER64 ------------------------------------------------------------------
    struct OPTIONAL_HEADER64
    {
        /* 0x000 */ u16   Magic                      ; // 0x020B
        /* 0x002 */ u8    MajorLinkerVersion         ;
        /* 0x003 */ u8    MinorLinkerVersion         ;
        /* 0x004 */ u32   SizeOfCode                 ;
        /* 0x008 */ u32   SizeOfInitializedData      ;
        /* 0x00C */ u32   SizeOfUninitializedData    ;
        /* 0x010 */ u32   AddressOfEntryPoint        ;
        /* 0x014 */ u32   BaseOfCode                 ;
        /* 0x018 */ u64   ImageBase                  ;
        /* 0x020 */ u32   SectionAlignment           ;
        /* 0x024 */ u32   FileAlignment              ;
        /* 0x028 */ u16   MajorOperatingSystemVersion;
        /* 0x02A */ u16   MinorOperatingSystemVersion;
        /* 0x02C */ u16   MajorImageVersion          ;
        /* 0x02E */ u16   MinorImageVersion          ;
        /* 0x030 */ u16   MajorSubsystemVersion      ;
        /* 0x032 */ u16   MinorSubsystemVersion      ;
        /* 0x034 */ u32   Win32VersionValue          ;
        /* 0x038 */ u32   SizeOfImage                ;
        /* 0x03C */ u32   SizeOfHeaders              ;
        /* 0x040 */ u32   CheckSum                   ;
        /* 0x044 */ u16   Subsystem                  ;
        /* 0x046 */ u16   DllCharacteristics         ;
        /* 0x048 */ u64   SizeOfStackReserve         ;
        /* 0x050 */ u64   SizeOfStackCommit          ;
        /* 0x058 */ u64   SizeOfHeapReserve          ;
        /* 0x060 */ u64   SizeOfHeapCommit           ;
        /* 0x068 */ u32   LoaderFlags                ;
        /* 0x06C */ u32   NumberOfRvaAndSizes        ;

        /* 0x070 */ DATA_DIRECTORY DataDirectory[16];   // export_dir at [0], nt + 0x088
    };


    // -- IMAGE_NT_HEADERS64 -----------------------------------------------------------------------
    struct NT_HEADERS64 {
        /* 0x000 */ u32               Signature     ;   // "PE\0\0"
        /* 0x004 */ FILE_HEADER       FileHeader    ;
        /* 0x018 */ OPTIONAL_HEADER64 OptionalHeader;
    };


    // -- IMAGE_EXPORT_DIRECTORY -------------------------------------------------------------------
    struct EXPORT_DIRECTORY
    {
        /* 0x000 */ u32          Characteristics      ;
        /* 0x004 */ u32          TimeDateStamp        ;
        /* 0x008 */ u16          MajorVersion         ;
        /* 0x00A */ u16          MinorVersion         ;
        /* 0x00C */ u32          Name                 ;   // RVA of DLL name
        /* 0x010 */ u32          Base                 ;   // first ordinal
        /* 0x014 */ u32          NumberOfFunctions    ;
        /* 0x018 */ u32          NumberOfNames        ;
        /* 0x01C */ rva_s        AddressOfFunctions   ;
        /* 0x020 */ rva_s        AddressOfNames       ;
        /* 0x024 */ rva_s        AddressOfNameOrdinals;
    };


    // -- IMAGE_SECTION_HEADER ---------------------------------------------------------------------
    struct SECTION_HEADER
    {
        /* 0x000 */ u8           Name[8]             ;
        /* 0x008 */ u32          VirtualSize         ;
        /* 0x00C */ u32          VirtualAddress      ;    // RVA of section
        /* 0x010 */ u32          SizeOfRawData       ;
        /* 0x014 */ u32          PointerToRawData    ;    // file offset
        /* 0x018 */ u32          PointerToRelocations;
        /* 0x01C */ u32          PointerToLinenumbers;
        /* 0x020 */ u16          NumberOfRelocations ;
        /* 0x022 */ u16          NumberOfLinenumbers ;
        /* 0x024 */ u32          Characteristics     ;    // section flags
    };

} // namespace win

