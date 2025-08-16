#ifndef PE_PARSER_H
#define PE_PARSER_H

// =====================[ Includes ]=====================
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <imagehlp.h>
#include <math.h>   // log2
#include <string.h>

// ---------------------------------------------
// 일부 환경에서 누락될 수 있는 상수/구조 정의 보강
#ifndef IMAGE_DEBUG_TYPE_CODEVIEW
#define IMAGE_DEBUG_TYPE_CODEVIEW 2
#endif

#ifndef IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
#endif

#ifndef IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL_FLAG64 ((ULONGLONG)0x8000000000000000ULL)
#endif
#ifndef IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL_FLAG32 0x80000000UL
#endif

// 최소한의 COR20 헤더 정의(WinSDK < CorHdr.h 미포함시)
typedef struct _IMAGE_COR20_HEADER_MIN {
    DWORD  cb;
    WORD   MajorRuntimeVersion;
    WORD   MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY MetaData;
    DWORD  Flags;
    union {
        DWORD EntryPointToken;
        DWORD EntryPointRVA;
    };
    IMAGE_DATA_DIRECTORY Resources;
    IMAGE_DATA_DIRECTORY StrongNameSignature;
    IMAGE_DATA_DIRECTORY CodeManagerTable;
    IMAGE_DATA_DIRECTORY VTableFixups;
    IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
    IMAGE_DATA_DIRECTORY ManagedNativeHeader;
} IMAGE_COR20_HEADER_MIN;

// =====================[ FILE Flags ]===================
#define IMAGE_FILE_RELOCS_STRIPPED         0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE        0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED      0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED     0x0008
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM      0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE     0x0020
#define IMAGE_FILE_BYTES_REVERSED_LO       0x0080
#define IMAGE_FILE_32BIT_MACHINE           0x0100
#define IMAGE_FILE_DEBUG_STRIPPED          0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP       0x0800
#define IMAGE_FILE_SYSTEM                  0x1000
#define IMAGE_FILE_DLL                     0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY          0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI       0x8000

// =====================[ Forward Decls ]================
DWORD  rva_to_offset(DWORD rva, IMAGE_SECTION_HEADER* sections, int nSections); // 레거시 드롭인
double calculate_entropy(const BYTE* data, DWORD size);
void   free_pe_file(struct _PE_FILE* pe);
void   set_console_encoding(void);

// =========[ Core struct ]=========
typedef struct _PE_FILE {
    BYTE* data;                 // 전체 파일 raw
    DWORD size;                 // 파일 크기

    BYTE* buffer;               // (동일 포인터 연결) 전체 파일 메모리
    DWORD fileSize;             // (동일 값 연결) 파일 크기

    // --- DOS_HEADER ---
    IMAGE_DOS_HEADER* dosHeader;

    // --- DOS_STUB ---
    BYTE* dosStub;

    // --- RICH_HEADER ---
    BYTE* richHeaderStart;      // "DanS"부터
    DWORD richHeaderSize;       // "Rich"+XOR키까지 포함

    // --- NT_HEADER ---
    IMAGE_NT_HEADERS32* ntHeader32;
    IMAGE_NT_HEADERS64* ntHeader64;
    BOOL  is64Bit;

    // --- FILE_HEADER ---
    IMAGE_FILE_HEADER* fileHeader;

    // --- OPTIONAL_HEADER ---
    IMAGE_OPTIONAL_HEADER32* optionalHeader32;
    IMAGE_OPTIONAL_HEADER64* optionalHeader64;

    // --- SECTION_HEADER ---
    IMAGE_SECTION_HEADER* sectionHeaders;
    WORD numberOfSections;
} PE_FILE;

// 전역 slow mode 기본값
static int   g_slow_mode = 1;     // 기본 ON
static DWORD g_delay_line_ms = 50;    // 한 줄마다 50ms 지연
static DWORD g_delay_block_ms = 200;   // 큰 블록(테이블/섹션) 사이 200ms

static inline void slow_line(void) {
    if (!g_slow_mode) return;
    fflush(stdout);
    Sleep(g_delay_line_ms);
}

static inline void slow_block(void) {
    if (!g_slow_mode) return;
    fflush(stdout);
    Sleep(g_delay_block_ms);
}

// =====================[ Internal utils ]================
static inline DWORD align_up(DWORD value, DWORD align) {
    if (align == 0) return value;
    DWORD rem = value % align;
    return rem ? (value + align - rem) : value;
}

static const char* safe_str(const char* s) { return s ? s : "(null)"; }

// ---- 섹션 검색: RVA 포함 섹션 인덱스(없으면 -1)
static int find_section_by_rva(const PE_FILE* pe, DWORD rva) {
    if (!pe || !pe->sectionHeaders || pe->numberOfSections == 0) return -1;
    DWORD sectAlign = 0;
    if (pe->is64Bit && pe->optionalHeader64) sectAlign = pe->optionalHeader64->SectionAlignment;
    else if (!pe->is64Bit && pe->optionalHeader32) sectAlign = pe->optionalHeader32->SectionAlignment;

    for (int i = 0; i < pe->numberOfSections; ++i) {
        const IMAGE_SECTION_HEADER* s = &pe->sectionHeaders[i];
        DWORD va = s->VirtualAddress;
        DWORD vsize = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
        DWORD end = va + (sectAlign ? align_up(vsize, sectAlign) : vsize);
        if (rva >= va && rva < end) return i;
    }
    return -1;
}

// DIE 스타일의 안전한 RVA -> 파일 오프셋 (PE 컨텍스트 기반)
static DWORD rva_to_offset_pe(const PE_FILE* pe, DWORD rva) {
    if (!pe || !pe->fileHeader || !pe->sectionHeaders) return 0;

    DWORD sizeOfHeaders = 0, fileAlign = 0, sectAlign = 0;
    if (pe->is64Bit && pe->optionalHeader64) {
        sizeOfHeaders = pe->optionalHeader64->SizeOfHeaders;
        fileAlign = pe->optionalHeader64->FileAlignment;
        sectAlign = pe->optionalHeader64->SectionAlignment;
    }
    else if (!pe->is64Bit && pe->optionalHeader32) {
        sizeOfHeaders = pe->optionalHeader32->SizeOfHeaders;
        fileAlign = pe->optionalHeader32->FileAlignment;
        sectAlign = pe->optionalHeader32->SectionAlignment;
    }
    else return 0;

    if (rva < sizeOfHeaders) return (rva < pe->size) ? rva : 0;

    const IMAGE_SECTION_HEADER* sec = pe->sectionHeaders;
    const int n = (int)pe->numberOfSections;

    for (int i = 0; i < n; ++i) {
        DWORD va = sec[i].VirtualAddress;
        DWORD vsize = sec[i].Misc.VirtualSize;
        DWORD raw = sec[i].PointerToRawData;
        DWORD rawsize = sec[i].SizeOfRawData;
        if (raw == 0 && rawsize == 0) continue;

        DWORD memSpan = (vsize ? vsize : rawsize);
        DWORD vaEnd = va + align_up(memSpan, (sectAlign ? sectAlign : 1));
        DWORD rawEnd = raw + align_up(rawsize, (fileAlign ? fileAlign : 1));

        if (rva >= va && rva < vaEnd) {
            ULONGLONG off = (ULONGLONG)raw + (ULONGLONG)(rva - va);
            if (off >= rawEnd || off >= pe->size) return 0;
            return (DWORD)off;
        }
    }
    return 0;
}

// 레거시 시그니처 유지 드롭인(헤더 추정 포함, 보수적)
DWORD rva_to_offset(DWORD rva, IMAGE_SECTION_HEADER* sections, int nSections) {
    if (!sections || nSections <= 0) return 0;
    DWORD firstVA = sections[0].VirtualAddress;
    for (int i = 1; i < nSections; ++i) if (sections[i].VirtualAddress < firstVA) firstVA = sections[i].VirtualAddress;
    if (rva < firstVA) return rva;

    for (int i = 0; i < nSections; i++) {
        DWORD va = sections[i].VirtualAddress;
        DWORD vlen = sections[i].Misc.VirtualSize;
        DWORD raw = sections[i].PointerToRawData;
        DWORD rawlen = sections[i].SizeOfRawData;
        DWORD span = (vlen > rawlen) ? vlen : rawlen;
        if (span == 0) continue;
        if (rva >= va && rva < va + span) return raw + (rva - va);
    }
    return 0;
}

// =====================[ Loader / Free ]=================
int load_pe_file(const char* filepath, PE_FILE* pe) {
    if (pe == NULL) { printf("\033[1;31m[Error] PE_FILE structure is NULL.\033[0m\n"); return 0; }
    memset(pe, 0, sizeof(PE_FILE));

    FILE* fp = NULL;
    if (fopen_s(&fp, filepath, "rb") != 0 || fp == NULL) { printf("\033[1;31m[Error] Cannot open file: %s\033[0m\n", filepath); return 0; }

    fseek(fp, 0, SEEK_END);
    long fsz = ftell(fp);
    if (fsz <= 0) { fclose(fp); return 0; }
    rewind(fp);

    pe->size = (DWORD)fsz;
    pe->data = (BYTE*)malloc(pe->size);
    if (!pe->data) { fclose(fp); return 0; }

    if (fread(pe->data, 1, pe->size, fp) != pe->size) { free(pe->data); pe->data = NULL; fclose(fp); return 0; }
    fclose(fp);

    pe->buffer = pe->data;
    pe->fileSize = pe->size;

    if (pe->size < sizeof(IMAGE_DOS_HEADER)) { free(pe->data); pe->data = NULL; return 0; }
    pe->dosHeader = (IMAGE_DOS_HEADER*)(pe->data);
    if (pe->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { free(pe->data); pe->data = NULL; return 0; }

    if ((ULONGLONG)pe->dosHeader->e_lfanew + sizeof(DWORD) > pe->size) { free(pe->data); pe->data = NULL; return 0; }
    DWORD peOffset = pe->dosHeader->e_lfanew;
    DWORD peSignature = *(DWORD*)(pe->data + peOffset);
    if (peSignature != IMAGE_NT_SIGNATURE) { free(pe->data); pe->data = NULL; return 0; }

    pe->dosStub = (BYTE*)pe->dosHeader + sizeof(IMAGE_DOS_HEADER);

    // Rich Header 탐색(선택)
    {
        BYTE* p = pe->dosStub;
        DWORD stubSize = (peOffset > sizeof(IMAGE_DOS_HEADER)) ? (peOffset - sizeof(IMAGE_DOS_HEADER)) : 0;
        for (DWORD i = 0; i + 8 < stubSize; i++) {
            if (memcmp(&p[i], "DanS", 4) == 0) {
                pe->richHeaderStart = &p[i];
                for (DWORD j = i + 4; j + 4 < stubSize; j += 4) {
                    if (memcmp(&p[j], "Rich", 4) == 0) { pe->richHeaderSize = (j - i) + 8; break; }
                }
                break;
            }
        }
    }

    if ((ULONGLONG)peOffset + sizeof(IMAGE_NT_HEADERS32) > pe->size) { free(pe->data); pe->data = NULL; return 0; }
    pe->ntHeader32 = (IMAGE_NT_HEADERS32*)(pe->data + peOffset);

    WORD magic = pe->ntHeader32->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if ((ULONGLONG)peOffset + sizeof(IMAGE_NT_HEADERS64) > pe->size) { free(pe->data); pe->data = NULL; return 0; }
        pe->is64Bit = TRUE;
        pe->ntHeader64 = (IMAGE_NT_HEADERS64*)(pe->data + peOffset);
        pe->optionalHeader64 = &pe->ntHeader64->OptionalHeader;
        pe->fileHeader = &pe->ntHeader64->FileHeader;
        pe->optionalHeader32 = NULL;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        pe->is64Bit = FALSE;
        pe->optionalHeader32 = &pe->ntHeader32->OptionalHeader;
        pe->fileHeader = &pe->ntHeader32->FileHeader;
        pe->ntHeader64 = NULL;
    }
    else { free(pe->data); pe->data = NULL; return 0; }

    IMAGE_FILE_HEADER* fh = pe->fileHeader;
    BYTE* sectBase = pe->data + peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fh->SizeOfOptionalHeader;
    ULONGLONG need = (ULONGLONG)(fh->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if ((ULONGLONG)(sectBase - pe->data) + need > pe->size) { free(pe->data); pe->data = NULL; return 0; }
    pe->sectionHeaders = (IMAGE_SECTION_HEADER*)sectBase;
    pe->numberOfSections = fh->NumberOfSections;

    return 1;
}

static inline void free_pe_file(PE_FILE* pe) {
    if (!pe) return;
    if (pe->data) { free(pe->data); pe->data = NULL; }
    pe->buffer = NULL;
    pe->size = pe->fileSize = 0;
    pe->dosHeader = NULL;
    pe->dosStub = NULL;
    pe->richHeaderStart = NULL;
    pe->richHeaderSize = 0;
    pe->ntHeader32 = NULL;
    pe->ntHeader64 = NULL;
    pe->is64Bit = FALSE;
    pe->fileHeader = NULL;
    pe->optionalHeader32 = NULL;
    pe->optionalHeader64 = NULL;
    pe->sectionHeaders = NULL;
    pe->numberOfSections = 0;
}

// =====================[ Print – DOS/Rich/NT/File/Opt ]================
static void print_bytes(const BYTE* p, DWORD n) {
    for (DWORD i = 0; i < n; i++) { printf("%02X ", p[i]); slow_line(); } 
}

void print_dos_header_full(const PE_FILE* pe) {
    if (!pe || !pe->dosHeader) { printf("\033[1;31m[Error] Invalid DOS Header.\033[0m\n"); slow_line(); return; }
    const IMAGE_DOS_HEADER* dos = pe->dosHeader;
    printf("\n\033[1;36m[+] DOS HEADER (FULL)\033[0m\n\033[1;33m"); slow_line();
    printf("  e_magic   : 0x%04X ('MZ')\n", dos->e_magic); slow_line();
    printf("  e_cblp    : 0x%04X\n", dos->e_cblp); slow_line();
    printf("  e_cp      : 0x%04X\n", dos->e_cp); slow_line();
    printf("  e_crlc    : 0x%04X\n", dos->e_crlc); slow_line();
    printf("  e_cparhdr : 0x%04X\n", dos->e_cparhdr); slow_line();
    printf("  e_minalloc: 0x%04X\n", dos->e_minalloc); slow_line();
    printf("  e_maxalloc: 0x%04X\n", dos->e_maxalloc); slow_line();
    printf("  e_ss      : 0x%04X\n", dos->e_ss); slow_line();
    printf("  e_sp      : 0x%04X\n", dos->e_sp); slow_line();
    printf("  e_csum    : 0x%04X\n", dos->e_csum); slow_line();
    printf("  e_ip      : 0x%04X\n", dos->e_ip); slow_line();
    printf("  e_cs      : 0x%04X\n", dos->e_cs); slow_line();
    printf("  e_lfarlc  : 0x%04X\n", dos->e_lfarlc); slow_line();
    printf("  e_ovno    : 0x%04X\n", dos->e_ovno); slow_line();
    printf("  e_res[4]  : ");
    for (int i = 0; i < 4; i++) { printf("0x%04X ", dos->e_res[i]); slow_line(); } printf("\n");
    printf("  e_oemid   : 0x%04X\n", dos->e_oemid); slow_line();
    printf("  e_oeminfo : 0x%04X\n", dos->e_oeminfo); slow_line();
    printf("  e_res2[10]: "); for (int i = 0; i < 10; i++) printf("0x%04X ", dos->e_res2[i]); printf("\n"); slow_line();
    printf("  e_lfanew  : 0x%08X\n\033[0m", dos->e_lfanew); slow_line();
}

void print_rich_header(const PE_FILE* pe) {
    if (!pe || !pe->data || !pe->dosHeader) { printf("\033[1;31m[Error] Invalid PE_FILE or data is NULL.\033[0m\n"); slow_line(); return; }
    printf("\n\033[1;36m[+] RICH HEADER\033[0m\n"); slow_line();
    BYTE* data = pe->data;
    DWORD richOffset = 0, danSOffset = 0, signature = 0;

    for (DWORD i = 0x80; i < 0x200; i += 4) {
        if (memcmp(&data[i], "Rich", 4) == 0) { richOffset = i; signature = *(DWORD*)&data[i + 4]; break; }
    }
    if (richOffset == 0) { printf("\033[1;33m  (Not present)\033[0m\n"); slow_line(); return; }

    for (int i = (int)richOffset - 4; i >= 0x40; i -= 4) {
        DWORD val = *(DWORD*)&data[i] ^ signature;
        if (val == 0x536E6144) { danSOffset = i; break; } // "DanS"
    }
    if (danSOffset == 0) { printf("\033[1;31m[Error] DanS signature not found.\033[0m\n"); slow_line(); return; }

    printf("\033[1;33m  DanS Offset : 0x%X\n  Rich Offset : 0x%X\n  XOR Key     : 0x%08X\n  Raw Entry Count: %u\033[0m\n",
        danSOffset, richOffset, signature, (richOffset - danSOffset - 16) / 8); slow_line();

    for (DWORD i = danSOffset + 16; i < richOffset; i += 8) {
        DWORD compID = *(DWORD*)&data[i] ^ signature;
        DWORD count = *(DWORD*)&data[i + 4] ^ signature;
        WORD productId = (WORD)(compID >> 16);
        WORD toolId = (WORD)(compID & 0xFFFF);
        printf("    Tool ID: %5u | Product ID: %5u | Count: %5u\n", toolId, productId, count);
        slow_line();
    }
}

void print_nt_header32(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader32) { printf("\033[1;31m[Error] NT Header (32-bit) is NULL.\033[0m\n"); return; }
    DWORD signature = pe->ntHeader32->Signature;
    printf("\n\033[1;36m[+] NT HEADER\033[0m\n\033[1;33m  Signature : 0x%08X ('PE\\0\\0')\033[0m\n", signature); slow_line();
}
void print_nt_header64(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader64) { printf("\033[1;31m[Error] NT Header (64-bit) is NULL.\033[0m\n"); return; }
    DWORD signature = pe->ntHeader64->Signature;
    printf("\n\033[1;36m[+] NT HEADER (64-bit)\033[0m\n\033[1;33m  Signature: 0x%08X ('PE\\0\\0')\033[0m\n", signature); slow_line();
}

static void print_file_characteristics(WORD c) {
    printf("  Characteristics:      0x%04X (", c); slow_line();
    bool first = true;
#define OUT_FLAG(flag, name) do{ if (c & flag){ if(!first) printf(" | "); slow_line(); printf(name); slow_line(); first=false; } }while(0)
    OUT_FLAG(IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED");
    OUT_FLAG(IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE");
    OUT_FLAG(IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED");
    OUT_FLAG(IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED");
    OUT_FLAG(IMAGE_FILE_AGGRESSIVE_WS_TRIM, "AGGRESSIVE_WS_TRIM");
    OUT_FLAG(IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE");
    OUT_FLAG(IMAGE_FILE_BYTES_REVERSED_LO, "BYTES_REVERSED_LO");
    OUT_FLAG(IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE");
    OUT_FLAG(IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED");
    OUT_FLAG(IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP");
    OUT_FLAG(IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP");
    OUT_FLAG(IMAGE_FILE_SYSTEM, "SYSTEM");
    OUT_FLAG(IMAGE_FILE_DLL, "DLL");
    OUT_FLAG(IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY");
    OUT_FLAG(IMAGE_FILE_BYTES_REVERSED_HI, "BYTES_REVERSED_HI");
#undef OUT_FLAG
    printf(first ? "None)\n" : ")\n"); slow_line();
}

void print_file_header_full(const PE_FILE* pe) {
    if (!pe || !pe->fileHeader) { printf("\033[1;31m[Error] FILE Header is NULL.\033[0m\n"); slow_line(); return; }
    const IMAGE_FILE_HEADER* fh = pe->fileHeader;
    printf("\n\033[1;36m[+] FILE HEADER (FULL)\033[0m\n\033[1;33m"); slow_line();
    printf("  Machine:              0x%04X\n", fh->Machine); slow_line();
    printf("  NumberOfSections:     0x%04X\n", fh->NumberOfSections); slow_line();
    printf("  TimeDateStamp:        0x%08X\n", fh->TimeDateStamp); slow_line();
    printf("  PointerToSymbolTable: 0x%08X\n", fh->PointerToSymbolTable); slow_line();
    printf("  NumberOfSymbols:      0x%08X\n", fh->NumberOfSymbols); slow_line();
    printf("  SizeOfOptionalHeader: 0x%04X\n", fh->SizeOfOptionalHeader); slow_line();
    print_file_characteristics(fh->Characteristics);
    printf("\033[0m"); slow_line();
}

void print_optional_header32_full(const PE_FILE* pe) {
    if (!pe || !pe->optionalHeader32) { printf("\033[1;31m[Error] Optional Header (32-bit) is NULL.\033[0m\n"); slow_line(); return; }
    const IMAGE_OPTIONAL_HEADER32* o = pe->optionalHeader32;
    printf("\n\033[1;36m[+] OPTIONAL HEADER (32-bit, FULL)\033[0m\n\033[1;33m"); slow_line();
    printf("  Magic                         : 0x%04X\n", o->Magic); slow_line();
    printf("  MajorLinkerVersion            : 0x%02X\n", o->MajorLinkerVersion); slow_line();
    printf("  MinorLinkerVersion            : 0x%02X\n", o->MinorLinkerVersion); slow_line();
    printf("  SizeOfCode                    : 0x%08X\n", o->SizeOfCode); slow_line();
    printf("  SizeOfInitializedData         : 0x%08X\n", o->SizeOfInitializedData); slow_line();
    printf("  SizeOfUninitializedData       : 0x%08X\n", o->SizeOfUninitializedData); slow_line();
    printf("  AddressOfEntryPoint           : 0x%08X\n", o->AddressOfEntryPoint); slow_line();
    printf("  BaseOfCode                    : 0x%08X\n", o->BaseOfCode); slow_line();
    printf("  BaseOfData                    : 0x%08X\n", o->BaseOfData); slow_line();
    printf("  ImageBase                     : 0x%08X\n", o->ImageBase); slow_line();
    printf("  SectionAlignment              : 0x%08X\n", o->SectionAlignment); slow_line();
    printf("  FileAlignment                 : 0x%08X\n", o->FileAlignment); slow_line();
    printf("  MajorOperatingSystemVersion   : 0x%04X\n", o->MajorOperatingSystemVersion); slow_line();
    printf("  MinorOperatingSystemVersion   : 0x%04X\n", o->MinorOperatingSystemVersion); slow_line();
    printf("  MajorImageVersion             : 0x%04X\n", o->MajorImageVersion); slow_line();
    printf("  MinorImageVersion             : 0x%04X\n", o->MinorImageVersion); slow_line();
    printf("  MajorSubsystemVersion         : 0x%04X\n", o->MajorSubsystemVersion); slow_line();
    printf("  MinorSubsystemVersion         : 0x%04X\n", o->MinorSubsystemVersion); slow_line();
    printf("  Win32VersionValue             : 0x%08X\n", o->Win32VersionValue); slow_line();
    printf("  SizeOfImage                   : 0x%08X\n", o->SizeOfImage); slow_line();
    printf("  SizeOfHeaders                 : 0x%08X\n", o->SizeOfHeaders); slow_line();
    printf("  CheckSum                      : 0x%08X\n", o->CheckSum); slow_line();
    printf("  Subsystem                     : 0x%04X\n", o->Subsystem); slow_line();
    printf("  DllCharacteristics            : 0x%04X\n", o->DllCharacteristics); slow_line();
    printf("  SizeOfStackReserve            : 0x%08X\n", o->SizeOfStackReserve); slow_line();
    printf("  SizeOfStackCommit             : 0x%08X\n", o->SizeOfStackCommit); slow_line();
    printf("  SizeOfHeapReserve             : 0x%08X\n", o->SizeOfHeapReserve); slow_line();
    printf("  SizeOfHeapCommit              : 0x%08X\n", o->SizeOfHeapCommit); slow_line();
    printf("  LoaderFlags                   : 0x%08X\n", o->LoaderFlags); slow_line();
    printf("  NumberOfRvaAndSizes           : 0x%08X\n\033[0m", o->NumberOfRvaAndSizes); slow_line();
}

void print_optional_header64_full(const PE_FILE* pe) {
    if (!pe || !pe->optionalHeader64) { printf("\033[1;31m[Error] Optional Header (64-bit) is NULL.\033[0m\n"); slow_line(); return; }
    const IMAGE_OPTIONAL_HEADER64* o = pe->optionalHeader64;
    printf("\n\033[1;36m[+] OPTIONAL HEADER (64-bit, FULL)\033[0m\n\033[1;33m"); slow_line();
    printf("  Magic                         : 0x%04X\n", o->Magic); slow_line();
    printf("  MajorLinkerVersion            : 0x%02X\n", o->MajorLinkerVersion); slow_line();
    printf("  MinorLinkerVersion            : 0x%02X\n", o->MinorLinkerVersion); slow_line();
    printf("  SizeOfCode                    : 0x%08X\n", o->SizeOfCode); slow_line();
    printf("  SizeOfInitializedData         : 0x%08X\n", o->SizeOfInitializedData); slow_line();
    printf("  SizeOfUninitializedData       : 0x%08X\n", o->SizeOfUninitializedData); slow_line();
    printf("  AddressOfEntryPoint           : 0x%08X\n", o->AddressOfEntryPoint); slow_line();
    printf("  BaseOfCode                    : 0x%08X\n", o->BaseOfCode); slow_line();
    printf("  ImageBase                     : 0x%016llX\n", (unsigned long long)o->ImageBase); slow_line();
    printf("  SectionAlignment              : 0x%08X\n", o->SectionAlignment); slow_line();
    printf("  FileAlignment                 : 0x%08X\n", o->FileAlignment); slow_line();
    printf("  MajorOperatingSystemVersion   : 0x%04X\n", o->MajorOperatingSystemVersion); slow_line();
    printf("  MinorOperatingSystemVersion   : 0x%04X\n", o->MinorOperatingSystemVersion); slow_line();
    printf("  MajorImageVersion             : 0x%04X\n", o->MajorImageVersion); slow_line();
    printf("  MinorImageVersion             : 0x%04X\n", o->MinorImageVersion); slow_line();
    printf("  MajorSubsystemVersion         : 0x%04X\n", o->MajorSubsystemVersion); slow_line();
    printf("  MinorSubsystemVersion         : 0x%04X\n", o->MinorSubsystemVersion); slow_line();
    printf("  Win32VersionValue             : 0x%08X\n", o->Win32VersionValue); slow_line();
    printf("  SizeOfImage                   : 0x%08X\n", o->SizeOfImage); slow_line();
    printf("  SizeOfHeaders                 : 0x%08X\n", o->SizeOfHeaders); slow_line();
    printf("  CheckSum                      : 0x%08X\n", o->CheckSum); slow_line();
    printf("  Subsystem                     : 0x%04X\n", o->Subsystem); slow_line();
    printf("  DllCharacteristics            : 0x%04X\n", o->DllCharacteristics); slow_line();
    printf("  SizeOfStackReserve            : 0x%016llX\n", (unsigned long long)o->SizeOfStackReserve); slow_line();
    printf("  SizeOfStackCommit             : 0x%016llX\n", (unsigned long long)o->SizeOfStackCommit); slow_line();
    printf("  SizeOfHeapReserve             : 0x%016llX\n", (unsigned long long)o->SizeOfHeapReserve); slow_line();
    printf("  SizeOfHeapCommit              : 0x%016llX\n", (unsigned long long)o->SizeOfHeapCommit); slow_line();
    printf("  LoaderFlags                   : 0x%08X\n", o->LoaderFlags); slow_line();
    printf("  NumberOfRvaAndSizes           : 0x%08X\n\033[0m", o->NumberOfRvaAndSizes); slow_line();
}

// =====================[ Print – Sections & DataDirs ]================
static void print_section_characteristics(DWORD characteristics) {
    printf("("); slow_line();
    bool first = true;
#define ADD_FLAG(flag, desc) if (characteristics & flag) { if (!first) printf(", "); printf(desc); first = false; }
    ADD_FLAG(0x00000020, "Code");
    ADD_FLAG(0x00000040, "InitializedData");
    ADD_FLAG(0x00000080, "UninitializedData");
    ADD_FLAG(0x20000000, "Execute");
    ADD_FLAG(0x40000000, "Read");
    ADD_FLAG(0x80000000, "Write");
    ADD_FLAG(0x01000000, "Discardable");
    ADD_FLAG(0x04000000, "NotCached");
    ADD_FLAG(0x08000000, "NotPaged");
    ADD_FLAG(0x10000000, "Shared");
#undef ADD_FLAG
    printf(")"); slow_line();
}

void print_section_headers_full(const PE_FILE* pe) {
    if (!pe || !pe->sectionHeaders || !pe->fileHeader) { printf("\033[1;31m[Error] Invalid section headers.\033[0m\n"); return; }
    WORD numberOfSections = pe->numberOfSections;
    printf("\n\033[1;36m[+] SECTION HEADERS (FULL)\033[0m\n"); slow_line();
    for (int i = 0; i < numberOfSections; i++) {
        const IMAGE_SECTION_HEADER* sh = &pe->sectionHeaders[i];
        char name[9] = { 0 }; memcpy(name, sh->Name, 8);
        printf("\033[1;33m  [%d] %s\033[0m\n\033[1;35m", i, name); slow_line();
        printf("    VirtualAddress : 0x%08X\n", sh->VirtualAddress); slow_line();
        printf("    VirtualSize    : 0x%08X\n", sh->Misc.VirtualSize); slow_line();
        printf("    RawOffset      : 0x%08X\n", sh->PointerToRawData); slow_line();
        printf("    RawSize        : 0x%08X\n", sh->SizeOfRawData); slow_line();
        printf("    RelocsPtr      : 0x%08X\n", sh->PointerToRelocations); slow_line();
        printf("    LineNumsPtr    : 0x%08X\n", sh->PointerToLinenumbers); slow_line();
        printf("    NumRelocs      : 0x%04X\n", sh->NumberOfRelocations); slow_line();
        printf("    NumLinenumbers : 0x%04X\n", sh->NumberOfLinenumbers); slow_line();
        printf("    Characteristics: 0x%08X ", sh->Characteristics); slow_line(); 
        print_section_characteristics(sh->Characteristics);
        printf("\033[0m\n"); slow_line();
    }
}

static const char* get_directory_name(int index) {
    switch (index) {
    case 0: return "Export Table";
    case 1: return "Import Table";
    case 2: return "Resource Table";
    case 3: return "Exception Table";
    case 4: return "Certificate Table";
    case 5: return "Base Relocation Table";
    case 6: return "Debug Directory";
    case 7: return "Architecture";
    case 8: return "Global Ptr";
    case 9: return "TLS Table";
    case 10: return "Load Config Table";
    case 11: return "Bound Import";
    case 12: return "IAT";
    case 13: return "Delay Import Descriptor";
    case 14: return "CLR Runtime Header";
    case 15: return "Reserved";
    default: return "Unknown";
    }
}

// ---- 배너 스타일(프리뷰 포함) 단일 항목
static void print_one_directory_report(const PE_FILE* pe, int idx, BOOL preview16) {
    if (!pe || (!pe->optionalHeader32 && !pe->optionalHeader64)) return;

    IMAGE_DATA_DIRECTORY* dirs = NULL; DWORD sizeOfImage = 0;
    if (!pe->is64Bit && pe->optionalHeader32) { dirs = pe->optionalHeader32->DataDirectory; sizeOfImage = pe->optionalHeader32->SizeOfImage; }
    else if (pe->is64Bit && pe->optionalHeader64) { dirs = pe->optionalHeader64->DataDirectory; sizeOfImage = pe->optionalHeader64->SizeOfImage; }
    else return;

    const char* name = get_directory_name(idx);
    DWORD rva = dirs[idx].VirtualAddress, size = dirs[idx].Size;

    if (rva == 0 && size == 0) { printf("\033[1;33m[+] %s is empty.\033[0m\n", name); slow_line(); return; }

    DWORD off = rva_to_offset_pe(pe, rva);
    int secIdx = find_section_by_rva(pe, rva);
    const char* secName = "(none)"; char secNameBuf[9] = { 0 };
    if (secIdx >= 0) { memcpy(secNameBuf, pe->sectionHeaders[secIdx].Name, 8); secName = secNameBuf; }
    BOOL valid = (off != 0 && off < pe->size && rva < sizeOfImage);

    printf("\033[1;35m  [%2d] %-24s \033[0m", idx, name); slow_line();
    printf("RVA: 0x%08X, Size: 0x%08X, ", rva, size); slow_line();
    if (off) { printf("FileOff: 0x%08X, "); slow_line(); }
    else printf("FileOff: \033[1;31mN/A\033[0m, "); slow_line();
    printf("Section: %s, ", secName); slow_line();
    printf("Valid: %s\n", valid ? "\033[1;32mYes\033[0m" : "\033[1;31mNo\033[0m"); slow_line();

    if (preview16 && off && size && (off + 16) <= pe->size) {
        printf("       Preview: "); slow_line(); DWORD n = (size < 16) ? size : 16; print_bytes(pe->data + off, n);
        if (size > n) printf(".."); slow_line(); printf("\n"); slow_line();
    }
}

// ---- 전체 디렉토리 배너
static void print_data_directories_report(const PE_FILE* pe, BOOL preview16) {
    if (!pe || (!pe->optionalHeader32 && !pe->optionalHeader64)) { printf("\033[1;31m[Error] Invalid PE_FILE or Optional Header.\033[0m\n"); slow_line(); return; }
    DWORD dirCount = (!pe->is64Bit && pe->optionalHeader32) ? pe->optionalHeader32->NumberOfRvaAndSizes : pe->optionalHeader64->NumberOfRvaAndSizes;
    if (dirCount == 0) { printf("\n\033[1;36m[+] DATA DIRECTORIES\033[0m\n\033[1;33m[+] All data directories are empty.\033[0m\n"); slow_line(); return; }
    if (dirCount > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) dirCount = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    printf("\n\033[1;36m[+] DATA DIRECTORIES\033[0m\n"); slow_line();
    for (int i = 0; i < (int)dirCount; ++i) print_one_directory_report(pe, i, preview16);
}

void print_data_directories_smart(const PE_FILE* pe, BOOL show_empty) {
    (void)show_empty;
    print_data_directories_report(pe, TRUE);
}

// =====================[ Export / Import ]================
void print_export_table(const PE_FILE* pe) {
    if (!pe || !pe->data || !pe->sectionHeaders || (!pe->optionalHeader32 && !pe->optionalHeader64)) { printf("\033[1;31m[Error] Invalid PE_FILE structure.\033[0m\n"); slow_line();return; }
    IMAGE_DATA_DIRECTORY exportDir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) { printf("\033[1;33m[+] Export Table is empty.\033[0m\n"); slow_line(); return; }

    DWORD exportOffset = rva_to_offset_pe(pe, exportDir.VirtualAddress);
    if (exportOffset == 0 || exportOffset + sizeof(IMAGE_EXPORT_DIRECTORY) > pe->size) { printf("\033[1;31m[Error] Invalid Export Table offset.\033[0m\n"); slow_line(); return; }

    IMAGE_EXPORT_DIRECTORY* expDir = (IMAGE_EXPORT_DIRECTORY*)(pe->data + exportOffset);

    DWORD nameCount = expDir->NumberOfNames;
    DWORD funcCount = expDir->NumberOfFunctions;
    DWORD ordBase = expDir->Base;

    printf("\n\033[1;36m[+] EXPORT TABLE\033[0m\n"); slow_line();
    DWORD nameOffset = rva_to_offset_pe(pe, expDir->Name);
    const char* dllName = (nameOffset && nameOffset < pe->size) ? (char*)(pe->data + nameOffset) : "(Unknown)";
    printf("\033[1;33m  DLL Name           : %s\n  Ordinal Base       : %u\n  Number of Names    : %u\n  Number of Functions: %u\033[0m\n",
        safe_str(dllName), ordBase, nameCount, funcCount); slow_line();

    DWORD nameArrayOffset = rva_to_offset_pe(pe, expDir->AddressOfNames);
    DWORD ordinalArrayOffset = rva_to_offset_pe(pe, expDir->AddressOfNameOrdinals);
    DWORD funcArrayOffset = rva_to_offset_pe(pe, expDir->AddressOfFunctions);
    if (!nameArrayOffset || !ordinalArrayOffset || !funcArrayOffset) { printf("\033[1;31m[Error] Failed to locate export arrays.\033[0m\n"); return; }

    printf("\n\033[1;35m  %-6s %-8s %-10s %s\033[0m\n", "Index", "Ordinal", "FuncRVA", "Name"); slow_line();
    printf("  --------------------------------------------------------\n"); slow_line();

    for (DWORD i = 0; i < nameCount; i++) {
        if (ordinalArrayOffset + i * sizeof(WORD) >= pe->size) break;
        WORD ord = *(WORD*)(pe->data + ordinalArrayOffset + i * sizeof(WORD));
        DWORD ordinal = (DWORD)ord + ordBase;

        ULONGLONG funcIdxOff = (ULONGLONG)funcArrayOffset + (ULONGLONG)(ordinal - ordBase) * sizeof(DWORD);
        if (funcIdxOff + sizeof(DWORD) > pe->size) break;
        DWORD funcRVA_i = *(DWORD*)(pe->data + funcIdxOff);

        ULONGLONG namePtrOff = (ULONGLONG)nameArrayOffset + (ULONGLONG)i * sizeof(DWORD);
        if (namePtrOff + sizeof(DWORD) > pe->size) break;
        DWORD nameStrRVA = *(DWORD*)(pe->data + namePtrOff);
        DWORD nameStrOff = rva_to_offset_pe(pe, nameStrRVA);
        const char* fname = (nameStrOff && nameStrOff < pe->size) ? (const char*)(pe->data + nameStrOff) : "(Invalid)";

        printf("\033[1;33m  %-6u %-8u 0x%08X %s\033[0m\n", i, ordinal, funcRVA_i, safe_str(fname)); slow_line();
    }
}

void print_import_table(const PE_FILE* pe) {
    if (!pe || !pe->data || !pe->sectionHeaders || (!pe->optionalHeader32 && !pe->optionalHeader64)) { printf("\033[1;31m[Error] Invalid PE_FILE structure.\033[0m\n"); return; }
    IMAGE_DATA_DIRECTORY impDir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0 || impDir.Size == 0) { printf("\033[1;33m[+] Import Table is empty.\033[0m\n"); slow_line(); return; }

    DWORD impOff = rva_to_offset_pe(pe, impDir.VirtualAddress);
    if (impOff == 0 || impOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe->size) { printf("\033[1;31m[Error] Invalid Import Table offset.\033[0m\n"); slow_line(); return; }

    printf("\n\033[1;36m[+] IMPORT TABLE\033[0m\n"); slow_line();
    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(pe->data + impOff);
    for (;; desc++) {
        if ((BYTE*)desc + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe->data + pe->size) break;
        if (desc->Name == 0) break;

        DWORD nameOff = rva_to_offset_pe(pe, desc->Name);
        const char* dllName = (nameOff && nameOff < pe->size) ? (const char*)(pe->data + nameOff) : "(Unknown)";
        printf("\n\033[1;33m  DLL: %s\033[0m\n", safe_str(dllName)); slow_line();

        DWORD oftRVA = desc->OriginalFirstThunk; // INT
        DWORD ftRVA = desc->FirstThunk;         // IAT
        DWORD thunkRVA = oftRVA ? oftRVA : ftRVA;
        DWORD thunkOff = rva_to_offset_pe(pe, thunkRVA);
        if (!thunkOff) { printf("    (Invalid thunk array)\n"); slow_line(); continue; }

        printf("    %-6s %-12s %-8s  %s\n", "Index", "ThunkRVA", "By", "Name/Ordinal"); slow_line();

        if (pe->is64Bit) {
            IMAGE_THUNK_DATA64* th = (IMAGE_THUNK_DATA64*)(pe->data + thunkOff);
            for (DWORD idx = 0; ; ++idx, ++th) {
                if ((BYTE*)th + sizeof(IMAGE_THUNK_DATA64) > pe->data + pe->size) break;
                if (th->u1.AddressOfData == 0) break;
                if (th->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    WORD ord = (WORD)(th->u1.Ordinal & 0xFFFF);
                    printf("    %-6u 0x%010llX Ord      %u\n", idx, (unsigned long long)(thunkRVA + idx * sizeof(IMAGE_THUNK_DATA64)), ord); slow_line();
                }
                else {
                    DWORD ibnRVA = (DWORD)th->u1.AddressOfData;
                    DWORD ibnOff = rva_to_offset_pe(pe, ibnRVA);
                    if (ibnOff && ibnOff + sizeof(IMAGE_IMPORT_BY_NAME) <= pe->size) {
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(pe->data + ibnOff);
                        printf("    %-6u 0x%010llX Name     %s (hint: %u)\n",
                            idx, (unsigned long long)(thunkRVA + idx * sizeof(IMAGE_THUNK_DATA64)),
                            (const char*)ibn->Name, ibn->Hint); slow_line();
                    }
                    else {
                        printf("    %-6u 0x%010llX Name     (invalid)\n",
                            idx, (unsigned long long)(thunkRVA + idx * sizeof(IMAGE_THUNK_DATA64))); slow_line();
                    }
                }
            }
        }
        else {
            IMAGE_THUNK_DATA32* th = (IMAGE_THUNK_DATA32*)(pe->data + thunkOff);
            for (DWORD idx = 0; ; ++idx, ++th) {
                if ((BYTE*)th + sizeof(IMAGE_THUNK_DATA32) > pe->data + pe->size) break;
                if (th->u1.AddressOfData == 0) break;
                if (th->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                    WORD ord = (WORD)(th->u1.Ordinal & 0xFFFF);
                    printf("    %-6u 0x%08X   Ord      %u\n", idx, thunkRVA + idx * sizeof(IMAGE_THUNK_DATA32), ord); slow_line();
                }
                else {
                    DWORD ibnRVA = th->u1.AddressOfData;
                    DWORD ibnOff = rva_to_offset_pe(pe, ibnRVA);
                    if (ibnOff && ibnOff + sizeof(IMAGE_IMPORT_BY_NAME) <= pe->size) {
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(pe->data + ibnOff);
                        printf("    %-6u 0x%08X   Name     %s (hint: %u)\n", idx, thunkRVA + idx * sizeof(IMAGE_THUNK_DATA32), (const char*)ibn->Name, ibn->Hint); slow_line();
                    }
                    else {
                        printf("    %-6u 0x%08X   Name     (invalid)\n", idx, thunkRVA + idx * sizeof(IMAGE_THUNK_DATA32)); slow_line();
                    }
                }
            }
        }
    }
}

// =====================[ Other Tables ]==================

// Debug Directory
void print_debug_directory(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Debug Directory is empty.\033[0m\n"); slow_line(); return; }
    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off || off + sizeof(IMAGE_DEBUG_DIRECTORY) > pe->size) { printf("\033[1;31m[Error] Debug directory invalid.\033[0m\n"); slow_line(); return; }

    printf("\n\033[1;36m[+] DEBUG DIRECTORY\033[0m\n"); slow_line();
    DWORD count = dir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (DWORD i = 0; i < count; i++) {
        IMAGE_DEBUG_DIRECTORY* d = (IMAGE_DEBUG_DIRECTORY*)(pe->data + off + i * sizeof(IMAGE_DEBUG_DIRECTORY));
        if ((BYTE*)d + sizeof(*d) > pe->data + pe->size) break;
        printf("\033[1;33m  [%lu]\033[0m\n", (unsigned long)i); slow_line();
        printf("    Characteristics : 0x%08X\n", d->Characteristics); slow_line();
        printf("    TimeDateStamp   : 0x%08X\n", d->TimeDateStamp); slow_line();
        printf("    MajorVersion    : 0x%04X\n", d->MajorVersion); slow_line();
        printf("    MinorVersion    : 0x%04X\n", d->MinorVersion); slow_line();
        printf("    Type            : %u\n", d->Type); slow_line();
        printf("    SizeOfData      : 0x%08X\n", d->SizeOfData); slow_line();
        printf("    AddressOfRawData: 0x%08X\n", d->AddressOfRawData); slow_line();
        printf("    PointerToRawData: 0x%08X\n", d->PointerToRawData); slow_line();
    }
}

// TLS
void print_tls_table(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] TLS Table is empty.\033[0m\n"); slow_line(); return; }
    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off) { printf("\033[1;31m[Error] TLS offset invalid.\033[0m\n"); slow_line(); return; }

    printf("\n\033[1;36m[+] TLS TABLE\033[0m\n");
    if (pe->is64Bit) {
        if (off + sizeof(IMAGE_TLS_DIRECTORY64) > pe->size) { printf("\033[1;31m[Error] TLS64 out of range.\033[0m\n"); slow_line(); return; }
        IMAGE_TLS_DIRECTORY64* t = (IMAGE_TLS_DIRECTORY64*)(pe->data + off);
        printf("  StartAddressOfRawData : 0x%016llX\n", (unsigned long long)t->StartAddressOfRawData); slow_line();
        printf("  EndAddressOfRawData   : 0x%016llX\n", (unsigned long long)t->EndAddressOfRawData); slow_line();
        printf("  AddressOfIndex        : 0x%016llX\n", (unsigned long long)t->AddressOfIndex); slow_line();
        printf("  AddressOfCallBacks    : 0x%016llX\n", (unsigned long long)t->AddressOfCallBacks); slow_line();
        printf("  SizeOfZeroFill        : 0x%08X\n", t->SizeOfZeroFill); slow_line();
        printf("  Characteristics       : 0x%08X\n", t->Characteristics); slow_line();
    }
    else {
        if (off + sizeof(IMAGE_TLS_DIRECTORY32) > pe->size) { printf("\033[1;31m[Error] TLS32 out of range.\033[0m\n"); slow_line(); return; }
        IMAGE_TLS_DIRECTORY32* t = (IMAGE_TLS_DIRECTORY32*)(pe->data + off);
        printf("  StartAddressOfRawData : 0x%08X\n", t->StartAddressOfRawData); slow_line();
        printf("  EndAddressOfRawData   : 0x%08X\n", t->EndAddressOfRawData); slow_line();
        printf("  AddressOfIndex        : 0x%08X\n", t->AddressOfIndex); slow_line();
        printf("  AddressOfCallBacks    : 0x%08X\n", t->AddressOfCallBacks); slow_line();
        printf("  SizeOfZeroFill        : 0x%08X\n", t->SizeOfZeroFill); slow_line();
        printf("  Characteristics       : 0x%08X\n", t->Characteristics); slow_line();
    }
}

// Relocations
void print_base_relocations(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Base Relocation Table is empty.\033[0m\n"); slow_line(); return; }
    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off) { printf("\033[1;31m[Error] Reloc offset invalid.\033[0m\n"); slow_line(); return; }

    printf("\n\033[1;36m[+] BASE RELOCATION TABLE\033[0m\n"); slow_line();
    DWORD cur = off, end = off + dir.Size;
    while (cur + sizeof(IMAGE_BASE_RELOCATION) <= end && cur + sizeof(IMAGE_BASE_RELOCATION) <= pe->size) {
        IMAGE_BASE_RELOCATION* b = (IMAGE_BASE_RELOCATION*)(pe->data + cur);
        if (b->SizeOfBlock == 0) break;
        DWORD entries = (b->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        printf("\033[1;33m  Block VA: 0x%08X, SizeOfBlock: 0x%08X, Entries: %u\033[0m\n", b->VirtualAddress, b->SizeOfBlock, entries); slow_line();

        // 간단 통계(타입별 카운트)
        unsigned counts[16] = { 0 };
        WORD* w = (WORD*)(pe->data + cur + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < entries && (BYTE*)(w + i) < pe->data + pe->size; i++) counts[(w[i] >> 12) & 0xF]++;

        printf("    Types: ABS=%u, HIGH=%u, LOW=%u, HIGHLOW=%u, DIR64=%u, OTHERS=%u\n",
            counts[0], counts[1], counts[2], counts[3], counts[10], entries - (counts[0] + counts[1] + counts[2] + counts[3] + counts[10])); slow_line();
        cur += b->SizeOfBlock;
    }
}

// Load Config
void print_load_config(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Load Config Table is empty.\033[0m\n"); return; }
    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off) { printf("\033[1;31m[Error] LoadConfig offset invalid.\033[0m\n"); slow_line(); return; }

    printf("\n\033[1;36m[+] LOAD CONFIG TABLE (%s)\033[0m\n", pe->is64Bit ? "64" : "32"); slow_line();
    if (pe->is64Bit) {
        IMAGE_LOAD_CONFIG_DIRECTORY64* lc = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(pe->data + off);
        if ((BYTE*)lc + sizeof(*lc) > pe->data + pe->size) { printf("\033[1;31m[Error] LoadConfig64 out of range.\033[0m\n"); slow_line(); return; }
        printf("  Size                      : 0x%08X\n", lc->Size); slow_line();
        printf("  TimeDateStamp             : 0x%08X\n", lc->TimeDateStamp); slow_line();
        printf("  GuardFlags                : 0x%08X\n", lc->GuardFlags); slow_line();
        printf("  SecurityCookie            : 0x%016llX\n", (unsigned long long)lc->SecurityCookie); slow_line();
        printf("  SEHandlerTable            : 0x%016llX (Count: %u)\n", (unsigned long long)lc->SEHandlerTable, lc->SEHandlerCount); slow_line();
        printf("  GuardCFCheckFunctionPtr   : 0x%016llX\n", (unsigned long long)lc->GuardCFCheckFunctionPointer); slow_line();
        printf("  GuardCFFunctionTable      : 0x%016llX (Count: %u)\n", (unsigned long long)lc->GuardCFFunctionTable, lc->GuardCFFunctionCount); slow_line();
    }
    else {
        IMAGE_LOAD_CONFIG_DIRECTORY32* lc = (IMAGE_LOAD_CONFIG_DIRECTORY32*)(pe->data + off);
        if ((BYTE*)lc + sizeof(*lc) > pe->data + pe->size) { printf("\033[1;31m[Error] LoadConfig32 out of range.\033[0m\n"); slow_line(); return; }
        printf("  Size                      : 0x%08X\n", lc->Size); slow_line();
        printf("  TimeDateStamp             : 0x%08X\n", lc->TimeDateStamp); slow_line();
        printf("  GuardFlags                : 0x%08X\n", lc->GuardFlags); slow_line();
        printf("  SecurityCookie            : 0x%08X\n", lc->SecurityCookie); slow_line();
        printf("  SEHandlerTable            : 0x%08X (Count: %u)\n", lc->SEHandlerTable, lc->SEHandlerCount); slow_line();
        printf("  GuardCFCheckFunctionPtr   : 0x%08X\n", lc->GuardCFCheckFunctionPointer); slow_line();
        printf("  GuardCFFunctionTable      : 0x%08X (Count: %u)\n", lc->GuardCFFunctionTable, lc->GuardCFFunctionCount); slow_line();
    }
}

// Bound Import
void print_bound_imports(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Bound Import is empty.\033[0m\n"); slow_line(); return; }

    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off) { printf("\033[1;31m[Error] BoundImport offset invalid.\033[0m\n"); slow_line(); return; }
    printf("\n\033[1;36m[+] BOUND IMPORT\033[0m\n"); slow_line();

    DWORD cur = off;
    while (cur + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) <= off + dir.Size && cur + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) <= pe->size) {
        IMAGE_BOUND_IMPORT_DESCRIPTOR* d = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(pe->data + cur);
        if (d->OffsetModuleName == 0 && d->NumberOfModuleForwarderRefs == 0) break;

        const char* mod = "(unknown)";
        if (d->OffsetModuleName) {
            DWORD nameOff = off + d->OffsetModuleName;
            if (nameOff < pe->size) mod = (const char*)(pe->data + nameOff);
        }
        printf("  Module: %s | TimeDateStamp: 0x%08X | Forwarders: %u\n", safe_str(mod), d->TimeDateStamp, d->NumberOfModuleForwarderRefs); slow_line();
        cur += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);
    }
}

// Delay Import
void print_delay_imports(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Delay Import is empty.\033[0m\n"); return; }

    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off) { printf("\033[1;31m[Error] DelayImport offset invalid.\033[0m\n"); slow_line(); return; }
    printf("\n\033[1;36m[+] DELAY IMPORT\033[0m\n"); slow_line();

    IMAGE_DELAYLOAD_DESCRIPTOR* d = (IMAGE_DELAYLOAD_DESCRIPTOR*)(pe->data + off);
    for (; (BYTE*)d + sizeof(*d) <= pe->data + pe->size; ++d) {
        if (d->DllNameRVA == 0) break;

        DWORD nameOff = rva_to_offset_pe(pe, d->DllNameRVA);
        const char* dll = nameOff ? (const char*)(pe->data + nameOff) : "(unknown)";

        DWORD attrs =
#if defined(_MSC_VER)
            d->Attributes.AllAttributes;
#else
            /* 일부 헤더는 union 없이 DWORD로 정의될 수 있음 */
            ((DWORD)d->Attributes);
#endif

        printf("  DLL: %s | TimeDateStamp: 0x%08X | Attr: 0x%08X\n",
            dll ? dll : "(unknown)", d->TimeDateStamp, attrs); slow_line();

        printf("    ModuleHandleRVA        : 0x%08X\n", d->ModuleHandleRVA); slow_line();
        printf("    ImportAddressTableRVA  : 0x%08X\n", d->ImportAddressTableRVA); slow_line();
        printf("    ImportNameTableRVA     : 0x%08X\n", d->ImportNameTableRVA); slow_line();
        printf("    BoundImportAddressTable: 0x%08X\n", d->BoundImportAddressTableRVA); slow_line();
        printf("    UnloadInformationTable : 0x%08X\n", d->UnloadInformationTableRVA); slow_line();
    }
}

// Resources (상위 레벨 요약)
typedef struct _IMAGE_RESOURCE_DIR {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    WORD  NumberOfNamedEntries;
    WORD  NumberOfIdEntries;
} IMAGE_RESOURCE_DIR;

void print_resources_summary(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Resource Table is empty.\033[0m\n"); slow_line(); return; }
    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off || off + sizeof(IMAGE_RESOURCE_DIR) > pe->size) { printf("\033[1;31m[Error] Resource root invalid.\033[0m\n"); slow_line(); return; }

    printf("\n\033[1;36m[+] RESOURCE DIRECTORY (Root summary)\033[0m\n"); slow_line();
    IMAGE_RESOURCE_DIR* r = (IMAGE_RESOURCE_DIR*)(pe->data + off);
    printf("  TimeDateStamp      : 0x%08X\n", r->TimeDateStamp); slow_line();
    printf("  MajorVersion       : 0x%04X\n", r->MajorVersion); slow_line();
    printf("  MinorVersion       : 0x%04X\n", r->MinorVersion); slow_line();
    printf("  NamedEntries       : %u\n", r->NumberOfNamedEntries); slow_line();
    printf("  IdEntries          : %u\n", r->NumberOfIdEntries); slow_line();
}

// CLR/.NET
void print_clr_header(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] CLR (.NET) Header is empty.\033[0m\n"); slow_line(); return; }

    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off || off + sizeof(IMAGE_COR20_HEADER_MIN) > pe->size) { printf("\033[1;31m[Error] CLR header invalid.\033[0m\n"); slow_line(); return; }

    IMAGE_COR20_HEADER_MIN* c = (IMAGE_COR20_HEADER_MIN*)(pe->data + off);
    printf("\n\033[1;36m[+] CLR (.NET) HEADER\033[0m\n"); slow_line();
    printf("  cb                     : 0x%08X\n", c->cb); slow_line();
    printf("  RuntimeVersion         : %u.%u\n", c->MajorRuntimeVersion, c->MinorRuntimeVersion); slow_line();
    printf("  MetaData               : RVA=0x%08X, Size=0x%08X\n", c->MetaData.VirtualAddress, c->MetaData.Size); slow_line();
    printf("  Flags                  : 0x%08X\n", c->Flags); slow_line();
    printf("  EntryPoint             : 0x%08X\n", c->EntryPointToken); slow_line();
    printf("  Resources              : RVA=0x%08X, Size=0x%08X\n", c->Resources.VirtualAddress, c->Resources.Size); slow_line();
    printf("  StrongNameSignature    : RVA=0x%08X, Size=0x%08X\n", c->StrongNameSignature.VirtualAddress, c->StrongNameSignature.Size); slow_line();
    printf("  VTableFixups           : RVA=0x%08X, Size=0x%08X\n", c->VTableFixups.VirtualAddress, c->VTableFixups.Size); slow_line();
    printf("  ManagedNativeHeader    : RVA=0x%08X, Size=0x%08X\n", c->ManagedNativeHeader.VirtualAddress, c->ManagedNativeHeader.Size); slow_line();
}

// =====================[ Utilities ]====================
double calculate_entropy(const BYTE* data, DWORD size) {
    if (!data || size == 0) return 0.0;
    double freq[256] = { 0.0 };
    for (DWORD i = 0; i < size; ++i) freq[data[i]] += 1.0;
    double ent = 0.0, invSize = 1.0 / (double)size;
    for (int i = 0; i < 256; ++i) if (freq[i] > 0.0) { double p = freq[i] * invSize; ent += -p * log2(p); }
    return ent;
}

// --------------------- PE 타입 판별 ---------------------
int detect_pe_type(const char* filepath, char* out_ext, size_t ext_bufsize) {
    FILE* fp = NULL;
    if (fopen_s(&fp, filepath, "rb") != 0 || fp == NULL) { printf("\033[1;31m[Error] Cannot open file for PE type detection: %s\033[0m\n", filepath); slow_line(); return 0; }
    BYTE mz[2] = { 0 };
    if (fread(mz, 1, 2, fp) != 2 || mz[0] != 'M' || mz[1] != 'Z') { fclose(fp); return 0; }

    DWORD pe_offset = 0; fseek(fp, 0x3C, SEEK_SET); if (fread(&pe_offset, sizeof(DWORD), 1, fp) != 1) { fclose(fp); return 0; }
    fseek(fp, pe_offset, SEEK_SET);
    BYTE pe_sig[4] = { 0 };
    if (fread(pe_sig, 1, 4, fp) != 4 || pe_sig[0] != 'P' || pe_sig[1] != 'E' || pe_sig[2] != 0 || pe_sig[3] != 0) { fclose(fp); return 0; }

    IMAGE_FILE_HEADER fileHeader; if (fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, fp) != 1) { fclose(fp); return 0; }
    const char* type = "unknown";
    if (fileHeader.Characteristics & IMAGE_FILE_DLL) type = "dll";
    else if (fileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) type = "exe";
    else if (fileHeader.Characteristics & 0x1000) type = "sys";
    if (out_ext && ext_bufsize > 0) strcpy_s(out_ext, ext_bufsize, type);
    fclose(fp);
    return 1;
}

// --------------------- 인코딩 ---------------------
void set_console_encoding() { SetConsoleOutputCP(CP_UTF8); SetConsoleCP(CP_UTF8); }

// --- 추출 안내(스피너 + 짧은 지연) [ADDED]
static inline void feature_extraction_banner(int ms /*milliseconds*/) {
    static const char spin[] = "|/-\\";
    printf("\n\033[1;36m[>] PE Feature Extracting...\033[0m "); slow_line();
    fflush(stdout);
    int steps = (ms <= 0) ? 0 : (ms / 90);
    if (steps < 8) steps = 8;              // 최소 몇 바퀴는 돌려서 “있어 보이게”
    for (int i = 0; i < steps; ++i) {
        printf("\b%c", spin[i % 4]); slow_line();
        fflush(stdout);
        Sleep(90);
    }
    printf("\b \n"); slow_line();// 스피너 지우고 줄바꿈
}

// =====================[ Orchestrator ]==================
// 한 방에 전부 보기
void print_everything(const PE_FILE* pe, BOOL preview16) {
    print_dos_header_full(pe);
    print_rich_header(pe);
    if (pe->ntHeader32) {
        WORD magic = pe->ntHeader32->OptionalHeader.Magic;
        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            print_nt_header32(pe);
            print_file_header_full(pe);
            print_optional_header32_full(pe);
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            print_nt_header64(pe);
            print_file_header_full(pe);
            print_optional_header64_full(pe);
        }
        else {
            printf("\033[1;31m[Error] Unknown OptionalHeader.Magic: 0x%X\033[0m\n", magic); slow_line();
        }
    }
    print_section_headers_full(pe);
    print_data_directories_report(pe, preview16);
    // 각 테이블
    print_export_table(pe);
    print_import_table(pe);
    print_debug_directory(pe);
    print_tls_table(pe);
    print_base_relocations(pe);
    print_load_config(pe);
    print_bound_imports(pe);
    print_delay_imports(pe);
    print_resources_summary(pe);
    print_clr_header(pe);
}


// =====================[ Feature Extraction ]====================
// 요구서 기반: 고충실도 PE Feature 벡터 추출 + CSV 출력

#ifndef IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE    0x0040
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NX_COMPAT
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT       0x0100
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF        0x4000
#endif
#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE                    0x20000000
#endif
#ifndef IMAGE_SCN_MEM_WRITE
#define IMAGE_SCN_MEM_WRITE                      0x80000000
#endif
#ifndef IMAGE_GUARD_CF_INSTRUMENTED
#define IMAGE_GUARD_CF_INSTRUMENTED              0x00000100
#endif

// (msvc/환경에 따라 strnlen 미존재 대비)
static inline size_t s_strnlen(const char* s, size_t max) {
    if (!s) return 0;
    const char* p = s;
    while (max && *p) { ++p; --max; }
    return (size_t)(p - s);
}

// 리소스 디렉토리 엔트리(필요 멤버만)
#pragma pack(push, 1)
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY_MIN {
    union {
        struct { DWORD NameOffset : 31; DWORD NameIsString : 1; };
        DWORD Name;
        WORD  Id;
    } u;
    union {
        DWORD OffsetToData;
        struct { DWORD OffsetToDirectory : 31; DWORD DataIsDirectory : 1; };
    } v;
} IMAGE_RESOURCE_DIRECTORY_ENTRY_MIN;
typedef struct _IMAGE_RESOURCE_DATA_ENTRY_MIN {
    DWORD OffsetToData;
    DWORD Size;
    DWORD CodePage;
    DWORD Reserved;
} IMAGE_RESOURCE_DATA_ENTRY_MIN;
#pragma pack(pop)

// ---- Feature 벡터
typedef struct _PE_FEATURES {
    // General / FILE / OPTIONAL
    DWORD      TimeDateStamp;
    WORD       NumberOfSections;
    WORD       Characteristics;
    WORD       Subsystem;
    WORD       DllCharacteristics;
    DWORD      AddressOfEntryPoint;
    ULONGLONG  ImageBase;
    DWORD      SizeOfImage;
    DWORD      SizeOfHeaders;
    DWORD      SectionAlignment;
    DWORD      FileAlignment;
    DWORD      SizeOfCode;
    DWORD      SizeOfInitializedData;
    DWORD      SizeOfUninitializedData;
    BYTE       MajorLinkerVersion, MinorLinkerVersion;
    WORD       MajorOSVersion, MinorOSVersion;
    WORD       MajorSSVersion, MinorSSVersion;

    // DOS/NT
    DWORD      DOS_e_lfanew, DOS_e_cblp, DOS_e_cp;
    DWORD      NT_Signature;

    // DataDirectory Sizes
    DWORD dd_ImportSize, dd_ExportSize, dd_ResourceSize, dd_IATSize;
    DWORD dd_TLSSize, dd_DebugSize, dd_SecuritySize;

    // Section summary
    WORD   sec_exec_count, sec_write_count;
    double sec_entropy_mean, sec_entropy_max, sec_entropy_std;
    double text_entropy, rsrc_entropy;
    double sec_vsraw_mean, sec_vsraw_max;
    double ratio_std_names;           // (.text/.rdata/.data/.rsrc/.reloc) / n_sections
    int    packed_like;               // max_entropy > 7.2

    // Import summary
    DWORD  num_imported_dlls;
    DWORD  num_imported_funcs;
    int    has_KERNEL32, has_ADVAPI32, has_WS2_32, has_NTDLL, has_USER32, has_SHELL32;

    // Export summary
    int    has_exports;
    DWORD  num_exported_funcs;
    DWORD  num_forwarded_exports;

    // Resource summary
    DWORD  res_root_entries;
    int    res_has_versioninfo;
    DWORD  res_icon_count;

    // TLS / Load Config
    int    tls_has_callbacks;
    DWORD  tls_callback_count;
    int    lc_has_cfg;
    int    lc_has_safeseh;
    int    lc_has_security_cookie;

    // Debug / PDB / Rich
    int    dbg_present;
    int    dbg_has_codeview;
    int    pdb_present;
    DWORD  pdb_path_len;
    DWORD  pdb_djb2;
    int    rich_present;
    DWORD  rich_xor_key;
    DWORD  rich_hash_djb2;

    // Security / Certificate
    DWORD  security_size;
    int    security_present;

    // Overlay / misc
    DWORD  overlay_size;

    // Derived
    double AOE_norm;
    double Hdr_to_Image;
    double Align_ratio;
    int    dlc_ASLR, dlc_NX, dlc_CFG, dlc_SafeSEH;
    int    large_image;
    int    is64;
} PE_FEATURES;

// --- 사람이 읽기 쉬운 전체 Feature 리포트 [ADDED]
static void print_features_pretty(const char* filepath, const PE_FEATURES* f) {
    if (!f) { printf("\033[1;31m[Error] Feature is NULL.\033[0m\n"); slow_line(); return; }

    printf("\n\033[1;36m[+] PE FEATURES (Detailed Report)\033[0m\n"); slow_line();
    printf("\033[1;35m  Target              : \033[0m%s\n", filepath ? filepath : ""); slow_line();
    printf("\033[1;35m  Architecture        : \033[0m%s\n", f->is64 ? "PE32+" : "PE32"); slow_line();

    // ---- General / Headers
    printf("\n\033[1;36m[=] General / Headers\033[0m\n"); slow_line();
    printf("  TimeDateStamp       : 0x%08X\n", f->TimeDateStamp); slow_line();
    printf("  NumberOfSections    : %u\n", f->NumberOfSections); slow_line();
    printf("  Characteristics     : 0x%04X\n", f->Characteristics); slow_line();
    printf("  Subsystem           : 0x%04X\n", f->Subsystem); slow_line();
    printf("  DllCharacteristics  : 0x%04X\n", f->DllCharacteristics); slow_line();
    printf("  AddressOfEntryPoint : 0x%08X  (AOE_norm=%.6f)\n", f->AddressOfEntryPoint, f->AOE_norm); slow_line();
    printf("  ImageBase           : 0x%016llX\n", (unsigned long long)f->ImageBase); slow_line();
    printf("  SizeOfImage         : %u  (large_image=%d)\n", f->SizeOfImage, f->large_image); slow_line();
    printf("  SizeOfHeaders       : %u  (Hdr_to_Image=%.6f)\n", f->SizeOfHeaders, f->Hdr_to_Image); slow_line();
    printf("  SectionAlignment    : %u\n", f->SectionAlignment); slow_line();
    printf("  FileAlignment       : %u  (Align_ratio=%.6f)\n", f->FileAlignment, f->Align_ratio); slow_line();
    printf("  SizeOfCode          : %u\n", f->SizeOfCode); slow_line();
    printf("  SizeOfInitData      : %u\n", f->SizeOfInitializedData); slow_line();
    printf("  SizeOfUninitData    : %u\n", f->SizeOfUninitializedData); slow_line();
    printf("  LinkerVersion       : %u.%u\n", f->MajorLinkerVersion, f->MinorLinkerVersion); slow_line();
    printf("  OSVersion           : %u.%u\n", f->MajorOSVersion, f->MinorOSVersion); slow_line();
    printf("  SubsystemVersion    : %u.%u\n", f->MajorSSVersion, f->MinorSSVersion); slow_line();

    // ---- DataDirectory Sizes
    printf("\n\033[1;36m[=] Data Directories (Sizes)\033[0m\n"); slow_line();
    printf("  Import    : %u\n", f->dd_ImportSize); slow_line();
    printf("  Export    : %u\n", f->dd_ExportSize); slow_line();
    printf("  Resource  : %u\n", f->dd_ResourceSize); slow_line();
    printf("  IAT       : %u\n", f->dd_IATSize); slow_line();
    printf("  TLS       : %u\n", f->dd_TLSSize); slow_line();
    printf("  Debug     : %u\n", f->dd_DebugSize); slow_line();
    printf("  Security  : %u\n", f->dd_SecuritySize); slow_line();

    // ---- Sections summary
    printf("\n\033[1;36m[=] Sections Summary\033[0m\n"); slow_line();
    printf("  ExecSections        : %u\n", f->sec_exec_count); slow_line();
    printf("  WriteSections       : %u\n", f->sec_write_count); slow_line();
    printf("  Entropy(mean/max/sd): %.6f / %.6f / %.6f\n",
        f->sec_entropy_mean, f->sec_entropy_max, f->sec_entropy_std); slow_line();
    printf("  .text entropy       : %.6f\n", f->text_entropy); slow_line();
    printf("  .rsrc entropy       : %.6f\n", f->rsrc_entropy); slow_line();
    printf("  VS/RAW (mean/max)   : %.6f / %.6f\n", f->sec_vsraw_mean, f->sec_vsraw_max); slow_line();
    printf("  StdNameRatio        : %.6f\n", f->ratio_std_names); slow_line();
    printf("  Packed-like         : %s\n", f->packed_like ? "Yes" : "No"); slow_line();

    // ---- Imports
    printf("\n\033[1;36m[=] Imports\033[0m\n"); slow_line();
    printf("  Imported DLLs       : %u\n", f->num_imported_dlls); slow_line();
    printf("  Imported Funcs      : %u\n", f->num_imported_funcs); slow_line();
    printf("  KERNEL32/ADVAPI32   : %d / %d\n", f->has_KERNEL32, f->has_ADVAPI32); slow_line();
    printf("  WS2_32/NTDLL        : %d / %d\n", f->has_WS2_32, f->has_NTDLL); slow_line();
    printf("  USER32/SHELL32      : %d / %d\n", f->has_USER32, f->has_SHELL32); slow_line();

    // ---- Exports
    printf("\n\033[1;36m[=] Exports\033[0m\n"); slow_line();
    printf("  Has Exports         : %d\n", f->has_exports); slow_line();
    printf("  Exported Funcs      : %u\n", f->num_exported_funcs); slow_line();
    printf("  Forwarded Exports   : %u\n", f->num_forwarded_exports); slow_line();

    // ---- Resources
    printf("\n\033[1;36m[=] Resources\033[0m\n"); slow_line();
    printf("  Root Entries        : %u\n", f->res_root_entries); slow_line();
    printf("  Has VersionInfo     : %d\n", f->res_has_versioninfo); slow_line();
    printf("  Icons (groups/items): %u\n", f->res_icon_count); slow_line();

    // ---- TLS / Load Config
    printf("\n\033[1;36m[=] TLS / Load Config\033[0m\n"); slow_line();
    printf("  TLS has callbacks   : %d (count=%u)\n", f->tls_has_callbacks, f->tls_callback_count); slow_line();
    printf("  CFG / SafeSEH / Cookie : %d / %d / %d\n",
        f->lc_has_cfg, f->lc_has_safeseh, f->lc_has_security_cookie); slow_line();

    // ---- Debug / PDB / Rich
    printf("\n\033[1;36m[=] Debug / PDB / Rich\033[0m\n"); slow_line();
    printf("  DebugPresent        : %d (CodeView=%d)\n", f->dbg_present, f->dbg_has_codeview); slow_line();
    printf("  PDB Present         : %d (len=%u, djb2=0x%08X)\n", f->pdb_present, f->pdb_path_len, f->pdb_djb2); slow_line();
    printf("  Rich Present        : %d (xor=0x%08X, djb2=0x%08X)\n", f->rich_present, f->rich_xor_key, f->rich_hash_djb2); slow_line();

    // ---- Security / Overlay
    printf("\n\033[1;36m[=] Security / Overlay\033[0m\n"); slow_line();
    printf("  Security Size       : %u (present=%d)\n", f->security_size, f->security_present); slow_line();
    printf("  Overlay Size        : %u\n", f->overlay_size); slow_line();

    // ---- Derived / Protections
    printf("\n\033[1;36m[=] Protections (DllCharacteristics)\033[0m\n"); slow_line();
    printf("  ASLR / NX / CFG / SafeSEH : %d / %d / %d / %d\n",
        f->dlc_ASLR, f->dlc_NX, f->dlc_CFG, f->dlc_SafeSEH); slow_line();

    printf("\n"); slow_line();
}

static int ieq(const char* a, const char* b) {
#ifdef _MSC_VER
    return _stricmp(a ? a : "", b ? b : "") == 0;
#else
    return strcasecmp(a ? a : "", b ? b : "") == 0;
#endif
}
static void dll_basename_upper(const char* in, char out[64]) {
    out[0] = 0;
    if (!in) return;
    const char* p = in;
    for (const char* q = in; *q; ++q) if (*q == '\\' || *q == '/') p = q + 1;
    size_t n = 0;
    while (p[n] && p[n] != '.' && n < 63) { char c = p[n]; out[n] = (char)toupper((unsigned char)c); n++; }
    out[n] = 0;
}
static DWORD djb2_hash(const BYTE* s, size_t n) {
    unsigned long h = 5381;
    for (size_t i = 0; i < n; ++i) h = ((h << 5) + h) + s[i];
    return (DWORD)h;
}

// ---- 섹션 통계
static void compute_section_stats(const PE_FILE* pe, PE_FEATURES* f) {
    f->NumberOfSections = pe->numberOfSections;
    if (!pe->sectionHeaders || pe->numberOfSections == 0) return;

    const char* stds[] = { ".TEXT", ".RDATA", ".DATA", ".RSRC", ".RELOC" };
    int std_cnt = 0;
    double sumE = 0.0, sumE2 = 0.0, maxE = 0.0;
    double sumR = 0.0, maxR = 0.0;
    f->sec_exec_count = f->sec_write_count = 0;
    f->text_entropy = 0.0; f->rsrc_entropy = 0.0;

    for (int i = 0; i < pe->numberOfSections; ++i) {
        const IMAGE_SECTION_HEADER* s = &pe->sectionHeaders[i];
        char name[9] = { 0 }; memcpy(name, s->Name, 8);
        for (int k = 0; k < 8; ++k) name[k] = (char)toupper((unsigned char)name[k]);

        for (int k = 0; k < 5; ++k) if (ieq(name, stds[k])) { std_cnt++; break; }

        if (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) f->sec_exec_count++;
        if (s->Characteristics & IMAGE_SCN_MEM_WRITE)   f->sec_write_count++;

        DWORD off = s->PointerToRawData, sz = s->SizeOfRawData;
        if (sz && off && (ULONGLONG)off + sz <= pe->size) {
            double e = calculate_entropy(pe->data + off, sz);
            sumE += e; sumE2 += e * e; if (e > maxE) maxE = e;
            if (ieq(name, ".TEXT"))  f->text_entropy = e;
            if (ieq(name, ".RSRC"))  f->rsrc_entropy = e;
        }

        double vs = (double)(s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData);
        double rs = (double)(s->SizeOfRawData ? s->SizeOfRawData : 1);
        double r = vs / rs;
        sumR += r; if (r > maxR) maxR = r;
    }

    int n = pe->numberOfSections;
    if (n > 0) {
        f->sec_entropy_mean = sumE / n;
        f->sec_entropy_max = maxE;
        double var = (sumE2 / n) - (f->sec_entropy_mean * f->sec_entropy_mean);
        f->sec_entropy_std = (var > 0.0) ? sqrt(var) : 0.0;
        f->sec_vsraw_mean = sumR / n;
        f->sec_vsraw_max = maxR;
        f->ratio_std_names = (double)std_cnt / (double)n;
        f->packed_like = (f->sec_entropy_max > 7.2) ? 1 : 0;
    }
}

// ---- Import
static void compute_imports(const PE_FILE* pe, PE_FEATURES* f) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    f->dd_ImportSize = dir.Size;
    if (!dir.VirtualAddress || !dir.Size) return;

    DWORD impOff = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!impOff || impOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe->size) return;

    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(pe->data + impOff);
    for (;; ++desc) {
        if ((BYTE*)desc + sizeof(*desc) > pe->data + pe->size) break;
        if (desc->Name == 0) break;
        f->num_imported_dlls++;

        DWORD nameOff = rva_to_offset_pe(pe, desc->Name);
        const char* dllName = (nameOff && nameOff < pe->size) ? (const char*)(pe->data + nameOff) : NULL;

        char base[64]; dll_basename_upper(dllName, base);
        if (ieq(base, "KERNEL32")) f->has_KERNEL32 = 1;
        if (ieq(base, "ADVAPI32")) f->has_ADVAPI32 = 1;
        if (ieq(base, "WS2_32"))   f->has_WS2_32 = 1;
        if (ieq(base, "NTDLL"))    f->has_NTDLL = 1;
        if (ieq(base, "USER32"))   f->has_USER32 = 1;
        if (ieq(base, "SHELL32"))  f->has_SHELL32 = 1;

        DWORD oftRVA = desc->OriginalFirstThunk; // INT
        DWORD ftRVA = desc->FirstThunk;         // IAT
        DWORD thunkRVA = oftRVA ? oftRVA : ftRVA;
        DWORD thunkOff = rva_to_offset_pe(pe, thunkRVA);
        if (!thunkOff) continue;

        if (pe->is64Bit) {
            IMAGE_THUNK_DATA64* th = (IMAGE_THUNK_DATA64*)(pe->data + thunkOff);
            for (;; ++th) {
                if ((BYTE*)th + sizeof(*th) > pe->data + pe->size) break;
                if (th->u1.AddressOfData == 0) break;
                f->num_imported_funcs++;
            }
        }
        else {
            IMAGE_THUNK_DATA32* th = (IMAGE_THUNK_DATA32*)(pe->data + thunkOff);
            for (;; ++th) {
                if ((BYTE*)th + sizeof(*th) > pe->data + pe->size) break;
                if (th->u1.AddressOfData == 0) break;
                f->num_imported_funcs++;
            }
        }
    }
}

// ---- Export
static void compute_exports(const PE_FILE* pe, PE_FEATURES* f) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    f->dd_ExportSize = dir.Size;
    if (!dir.VirtualAddress || !dir.Size) return;

    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off || off + sizeof(IMAGE_EXPORT_DIRECTORY) > pe->size) return;

    f->has_exports = 1;
    IMAGE_EXPORT_DIRECTORY* e = (IMAGE_EXPORT_DIRECTORY*)(pe->data + off);
    f->num_exported_funcs = e->NumberOfFunctions;

    DWORD funcArrayOff = rva_to_offset_pe(pe, e->AddressOfFunctions);
    if (!funcArrayOff) return;

    DWORD start = dir.VirtualAddress, end = dir.VirtualAddress + dir.Size;
    for (DWORD i = 0; i < e->NumberOfFunctions; ++i) {
        DWORD rva = *(DWORD*)(pe->data + funcArrayOff + i * sizeof(DWORD));
        if (rva >= start && rva < end) f->num_forwarded_exports++;
    }
}

// ---- Resources
static void compute_resources(const PE_FILE* pe, PE_FEATURES* f) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    f->dd_ResourceSize = dir.Size;
    if (!dir.VirtualAddress || !dir.Size) return;

    DWORD base = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!base || base + sizeof(IMAGE_RESOURCE_DIR) > pe->size) return;

    IMAGE_RESOURCE_DIR* root = (IMAGE_RESOURCE_DIR*)(pe->data + base);
    WORD total = root->NumberOfNamedEntries + root->NumberOfIdEntries;
    f->res_root_entries = total;

    IMAGE_RESOURCE_DIRECTORY_ENTRY_MIN* ent = (IMAGE_RESOURCE_DIRECTORY_ENTRY_MIN*)(pe->data + base + sizeof(IMAGE_RESOURCE_DIR));
    for (WORD i = 0; i < total; ++i) {
        if ((BYTE*)(ent + i) > pe->data + pe->size - sizeof(*ent)) break;
        if (ent[i].u.NameIsString) continue; // 이름기반 엔트리는 스킵
        WORD typeId = ent[i].u.Id;

        if (ent[i].v.DataIsDirectory) {
            DWORD subdirRVA = (dir.VirtualAddress + (ent[i].v.OffsetToDirectory & 0x7FFFFFFF));
            DWORD subdirOff = rva_to_offset_pe(pe, subdirRVA);
            if (!subdirOff || subdirOff + sizeof(IMAGE_RESOURCE_DIR) > pe->size) continue;

            if (typeId == 16 /* RT_VERSION */) f->res_has_versioninfo = 1;
            if (typeId == 3 /* RT_ICON */ || typeId == 14 /* RT_GROUP_ICON */) {
                IMAGE_RESOURCE_DIR* sub = (IMAGE_RESOURCE_DIR*)(pe->data + subdirOff);
                f->res_icon_count += (sub->NumberOfNamedEntries + sub->NumberOfIdEntries);
            }
        }
    }
}

// ---- TLS / LoadConfig
static void compute_tls_loadcfg(const PE_FILE* pe, PE_FEATURES* f) {
    // TLS
    IMAGE_DATA_DIRECTORY tdir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    f->dd_TLSSize = tdir.Size;
    if (tdir.VirtualAddress && tdir.Size) {
        DWORD off = rva_to_offset_pe(pe, tdir.VirtualAddress);
        if (off) {
            if (pe->is64Bit) {
                if (off + sizeof(IMAGE_TLS_DIRECTORY64) <= pe->size) {
                    IMAGE_TLS_DIRECTORY64* t = (IMAGE_TLS_DIRECTORY64*)(pe->data + off);
                    ULONGLONG cbVA = t->AddressOfCallBacks;
                    if (cbVA) {
                        ULONGLONG ib = pe->optionalHeader64->ImageBase;
                        if (cbVA >= ib && (cbVA - ib) <= pe->optionalHeader64->SizeOfImage) {
                            DWORD cbRVA = (DWORD)(cbVA - ib);
                            DWORD cbOff = rva_to_offset_pe(pe, cbRVA);
                            if (cbOff && cbOff + sizeof(ULONGLONG) <= pe->size) {
                                f->tls_has_callbacks = 1;
                                for (DWORD i = 0; ; ++i) {
                                    if (cbOff + (i + 1) * sizeof(ULONGLONG) > pe->size) break;
                                    ULONGLONG p = *(ULONGLONG*)(pe->data + cbOff + i * sizeof(ULONGLONG));
                                    if (p == 0) break;
                                    f->tls_callback_count++;
                                }
                            }
                        }
                    }
                }
            }
            else {
                if (off + sizeof(IMAGE_TLS_DIRECTORY32) <= pe->size) {
                    IMAGE_TLS_DIRECTORY32* t = (IMAGE_TLS_DIRECTORY32*)(pe->data + off);
                    DWORD cbVA = t->AddressOfCallBacks;
                    if (cbVA) {
                        DWORD ib = pe->optionalHeader32->ImageBase;
                        if (cbVA >= ib && (cbVA - ib) <= pe->optionalHeader32->SizeOfImage) {
                            DWORD cbRVA = cbVA - ib;
                            DWORD cbOff = rva_to_offset_pe(pe, cbRVA);
                            if (cbOff && cbOff + sizeof(DWORD) <= pe->size) {
                                f->tls_has_callbacks = 1;
                                for (DWORD i = 0; ; ++i) {
                                    if (cbOff + (i + 1) * sizeof(DWORD) > pe->size) break;
                                    DWORD p = *(DWORD*)(pe->data + cbOff + i * sizeof(DWORD));
                                    if (p == 0) break;
                                    f->tls_callback_count++;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Load Config
    IMAGE_DATA_DIRECTORY ldir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (ldir.VirtualAddress && ldir.Size) {
        DWORD off = rva_to_offset_pe(pe, ldir.VirtualAddress);
        if (off) {
            if (pe->is64Bit && off + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64) <= pe->size) {
                IMAGE_LOAD_CONFIG_DIRECTORY64* lc = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(pe->data + off);
                if (lc->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) f->lc_has_cfg = 1;
                if (lc->SecurityCookie) f->lc_has_security_cookie = 1;
            }
            else if (!pe->is64Bit && off + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32) <= pe->size) {
                IMAGE_LOAD_CONFIG_DIRECTORY32* lc = (IMAGE_LOAD_CONFIG_DIRECTORY32*)(pe->data + off);
                if (lc->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) f->lc_has_cfg = 1;
                if (lc->SecurityCookie) f->lc_has_security_cookie = 1;
                if (lc->SEHandlerTable && lc->SEHandlerCount) f->lc_has_safeseh = 1;
            }
        }
    }
}

// ---- Debug / PDB / Rich
static void compute_debug_pdb_rich(const PE_FILE* pe, PE_FEATURES* f) {
    // Debug
    IMAGE_DATA_DIRECTORY ddir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    f->dd_DebugSize = ddir.Size;
    if (ddir.VirtualAddress && ddir.Size) {
        DWORD off = rva_to_offset_pe(pe, ddir.VirtualAddress);
        if (off && off + sizeof(IMAGE_DEBUG_DIRECTORY) <= pe->size) {
            f->dbg_present = 1;
            DWORD count = ddir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
            for (DWORD i = 0; i < count; ++i) {
                IMAGE_DEBUG_DIRECTORY* d = (IMAGE_DEBUG_DIRECTORY*)(pe->data + off + i * sizeof(IMAGE_DEBUG_DIRECTORY));
                if ((BYTE*)d + sizeof(*d) > pe->data + pe->size) break;
                if (d->Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
                    f->dbg_has_codeview = 1;
                    DWORD p = d->PointerToRawData, n = d->SizeOfData;
                    if (p && n && (ULONGLONG)p + n <= pe->size) {
                        const BYTE* s = pe->data + p;
                        if (n >= 24 && memcmp(s, "RSDS", 4) == 0) {
                            const char* path = (const char*)(s + 24);
                            size_t L = s_strnlen(path, n - 24);
                            f->pdb_present = (L > 0);
                            f->pdb_path_len = (DWORD)L;
                            f->pdb_djb2 = djb2_hash((const BYTE*)path, L);
                        }
                        else if (n >= 16 && memcmp(s, "NB10", 4) == 0) {
                            const char* path = (const char*)(s + 16);
                            size_t L = s_strnlen(path, n - 16);
                            f->pdb_present = (L > 0);
                            f->pdb_path_len = (DWORD)L;
                            f->pdb_djb2 = djb2_hash((const BYTE*)path, L);
                        }
                    }
                }
            }
        }
    }

    // Rich
    if (!pe->dosHeader || !pe->data) return;
    BYTE* data = pe->data;
    DWORD peOffset = pe->dosHeader->e_lfanew;
    if (peOffset >= 0x80) {
        DWORD richOffset = 0, danSOffset = 0, signature = 0;
        for (DWORD i = 0x80; i < 0x200 && i + 8 <= peOffset; i += 4) {
            if (memcmp(&data[i], "Rich", 4) == 0) { richOffset = i; signature = *(DWORD*)&data[i + 4]; break; }
        }
        if (richOffset) {
            for (int i = (int)richOffset - 4; i >= 0x40; i -= 4) {
                DWORD val = *(DWORD*)&data[i] ^ signature;
                if (val == 0x536E6144) { danSOffset = i; break; } // "DanS"
            }
            if (danSOffset) {
                f->rich_present = 1;
                f->rich_xor_key = signature;
                unsigned long h = 5381;
                for (DWORD i = danSOffset + 16; i < richOffset; i += 4) {
                    DWORD v = *(DWORD*)&data[i] ^ signature;
                    BYTE b[4]; memcpy(b, &v, 4);
                    for (int k = 0; k < 4; ++k) h = ((h << 5) + h) + b[k];
                }
                f->rich_hash_djb2 = (DWORD)h;
            }
        }
    }
}

// ---- Security / Overlay
static void compute_security_overlay(const PE_FILE* pe, PE_FEATURES* f) {
    IMAGE_DATA_DIRECTORY sdir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    f->dd_SecuritySize = sdir.Size;
    f->security_size = sdir.Size;
    f->security_present = (sdir.Size > 0);

    DWORD lastEnd = 0;
    for (int i = 0; i < pe->numberOfSections; ++i) {
        DWORD end = pe->sectionHeaders[i].PointerToRawData + pe->sectionHeaders[i].SizeOfRawData;
        if (end > lastEnd) lastEnd = end;
    }
    f->overlay_size = (pe->size > lastEnd) ? (pe->size - lastEnd) : 0;
}

// ---- General & Derived
static void fill_general(const PE_FILE* pe, PE_FEATURES* f) {
    memset(f, 0, sizeof(*f));
    f->is64 = pe->is64Bit ? 1 : 0;

    if (pe->dosHeader) {
        f->DOS_e_lfanew = pe->dosHeader->e_lfanew;
        f->DOS_e_cblp = pe->dosHeader->e_cblp;
        f->DOS_e_cp = pe->dosHeader->e_cp;
    }
    if (pe->ntHeader32) f->NT_Signature = pe->ntHeader32->Signature;

    if (pe->fileHeader) {
        f->TimeDateStamp = pe->fileHeader->TimeDateStamp;
        f->Characteristics = pe->fileHeader->Characteristics;
        f->NumberOfSections = pe->fileHeader->NumberOfSections;
    }

    if (pe->is64Bit && pe->optionalHeader64) {
        const IMAGE_OPTIONAL_HEADER64* o = pe->optionalHeader64;
        f->AddressOfEntryPoint = o->AddressOfEntryPoint;
        f->ImageBase = o->ImageBase;
        f->SectionAlignment = o->SectionAlignment;
        f->FileAlignment = o->FileAlignment;
        f->SizeOfImage = o->SizeOfImage;
        f->SizeOfHeaders = o->SizeOfHeaders;
        f->SizeOfCode = o->SizeOfCode;
        f->SizeOfInitializedData = o->SizeOfInitializedData;
        f->SizeOfUninitializedData = o->SizeOfUninitializedData;
        f->MajorLinkerVersion = o->MajorLinkerVersion;
        f->MinorLinkerVersion = o->MinorLinkerVersion;
        f->MajorOSVersion = o->MajorOperatingSystemVersion;
        f->MinorOSVersion = o->MinorOperatingSystemVersion;
        f->MajorSSVersion = o->MajorSubsystemVersion;
        f->MinorSSVersion = o->MinorSubsystemVersion;
        f->Subsystem = o->Subsystem;
        f->DllCharacteristics = o->DllCharacteristics;
    }
    else if (!pe->is64Bit && pe->optionalHeader32) {
        const IMAGE_OPTIONAL_HEADER32* o = pe->optionalHeader32;
        f->AddressOfEntryPoint = o->AddressOfEntryPoint;
        f->ImageBase = o->ImageBase;
        f->SectionAlignment = o->SectionAlignment;
        f->FileAlignment = o->FileAlignment;
        f->SizeOfImage = o->SizeOfImage;
        f->SizeOfHeaders = o->SizeOfHeaders;
        f->SizeOfCode = o->SizeOfCode;
        f->SizeOfInitializedData = o->SizeOfInitializedData;
        f->SizeOfUninitializedData = o->SizeOfUninitializedData;
        f->MajorLinkerVersion = o->MajorLinkerVersion;
        f->MinorLinkerVersion = o->MinorLinkerVersion;
        f->MajorOSVersion = o->MajorOperatingSystemVersion;
        f->MinorOSVersion = o->MinorOperatingSystemVersion;
        f->MajorSSVersion = o->MajorSubsystemVersion;
        f->MinorSSVersion = o->MinorSubsystemVersion;
        f->Subsystem = o->Subsystem;
        f->DllCharacteristics = o->DllCharacteristics;
    }

    IMAGE_DATA_DIRECTORY* dd = pe->is64Bit ? pe->optionalHeader64->DataDirectory
        : pe->optionalHeader32->DataDirectory;
    if (dd) {
        f->dd_IATSize = dd[IMAGE_DIRECTORY_ENTRY_IAT].Size;
        f->dd_ExportSize = dd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        f->dd_ImportSize = dd[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        f->dd_ResourceSize = dd[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        f->dd_DebugSize = dd[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        f->dd_TLSSize = dd[IMAGE_DIRECTORY_ENTRY_TLS].Size;
        f->dd_SecuritySize = dd[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    }

    if (f->SizeOfImage) {
        f->AOE_norm = (double)f->AddressOfEntryPoint / (double)f->SizeOfImage;
        f->Hdr_to_Image = (double)f->SizeOfHeaders / (double)f->SizeOfImage;
    }
    if (f->FileAlignment) f->Align_ratio = (double)f->SectionAlignment / (double)f->FileAlignment;
    f->dlc_ASLR = (f->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) ? 1 : 0;
    f->dlc_NX = (f->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) ? 1 : 0;
    f->dlc_CFG = (f->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) ? 1 : 0;
    f->large_image = (f->SizeOfImage >= (50u * 1024u * 1024u)) ? 1 : 0;
}

// ---- 메인 진입점
static int extract_pe_features(const PE_FILE* pe, PE_FEATURES* out_feat) {
    if (!pe || !out_feat) return 0;
    fill_general(pe, out_feat);
    compute_section_stats(pe, out_feat);
    compute_imports(pe, out_feat);
    compute_exports(pe, out_feat);
    compute_resources(pe, out_feat);
    compute_tls_loadcfg(pe, out_feat);
    compute_debug_pdb_rich(pe, out_feat);
    compute_security_overlay(pe, out_feat);
    if (out_feat->lc_has_safeseh) out_feat->dlc_SafeSEH = 1;
    if (out_feat->lc_has_cfg)     out_feat->dlc_CFG = 1;
    return 1;
}

// ---- CSV 출력 (헤더 1회 + 행)
static void print_features_csv_header_once(void) {
    static int printed = 0; if (printed) return; printed = 1;
    printf("filepath,is64,TimeDateStamp,NumberOfSections,Characteristics,Subsystem,DllCharacteristics,AddressOfEntryPoint,ImageBase,SizeOfImage,SizeOfHeaders,SectionAlignment,FileAlignment,SizeOfCode,SizeOfInitializedData,SizeOfUninitializedData,MajorLinker,MinorLinker,MajorOS,MinorOS,MajorSS,MinorSS,ImportSize,ExportSize,ResourceSize,IATSize,TLSSize,DebugSize,SecuritySize,sec_exec_count,sec_write_count,sec_entropy_mean,sec_entropy_max,sec_entropy_std,text_entropy,rsrc_entropy,sec_vsraw_mean,sec_vsraw_max,ratio_std_names,packed_like,num_imported_dlls,num_imported_funcs,has_KERNEL32,has_ADVAPI32,has_WS2_32,has_NTDLL,has_USER32,has_SHELL32,has_exports,num_exported_funcs,num_forwarded_exports,res_root_entries,res_has_versioninfo,res_icon_count,tls_has_callbacks,tls_callback_count,lc_has_cfg,lc_has_safeseh,lc_has_security_cookie,dbg_present,dbg_has_codeview,pdb_present,pdb_path_len,pdb_djb2,rich_present,rich_xor_key,rich_hash_djb2,security_size,security_present,overlay_size,AOE_norm,Hdr_to_Image,Align_ratio,dlc_ASLR,dlc_NX,dlc_CFG,dlc_SafeSEH,large_image\n"); slow_line();
}
static void print_features_csv_row(const char* filepath, const PE_FEATURES* f) {
    printf("\"%s\",%d,%u,%u,%u,%u,%u,%u,%llu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%u,%u,%u,%u,%u\n",
        filepath ? filepath : "",
        f->is64,
        f->TimeDateStamp, f->NumberOfSections, f->Characteristics, f->Subsystem, f->DllCharacteristics,
        f->AddressOfEntryPoint, (unsigned long long)f->ImageBase, f->SizeOfImage, f->SizeOfHeaders, f->SectionAlignment, f->FileAlignment,
        f->SizeOfCode, f->SizeOfInitializedData, f->SizeOfUninitializedData,
        f->MajorLinkerVersion, f->MinorLinkerVersion, f->MajorOSVersion, f->MinorOSVersion, f->MajorSSVersion, f->MinorSSVersion,
        f->dd_ImportSize, f->dd_ExportSize, f->dd_ResourceSize, f->dd_IATSize, f->dd_TLSSize, f->dd_DebugSize, f->dd_SecuritySize,
        f->sec_exec_count, f->sec_write_count,
        f->sec_entropy_mean, f->sec_entropy_max, f->sec_entropy_std, f->text_entropy, f->rsrc_entropy,
        f->sec_vsraw_mean, f->sec_vsraw_max, f->ratio_std_names, f->packed_like,
        f->num_imported_dlls, f->num_imported_funcs,
        f->has_KERNEL32, f->has_ADVAPI32, f->has_WS2_32, f->has_NTDLL, f->has_USER32, f->has_SHELL32,
        f->has_exports, f->num_exported_funcs, f->num_forwarded_exports,
        f->res_root_entries, f->res_has_versioninfo, f->res_icon_count,
        f->tls_has_callbacks, f->tls_callback_count,
        f->lc_has_cfg, f->lc_has_safeseh, f->lc_has_security_cookie,
        f->dbg_present, f->dbg_has_codeview, f->pdb_present, f->pdb_path_len, f->pdb_djb2,
        f->rich_present, f->rich_xor_key, f->rich_hash_djb2,
        f->security_size, f->security_present, f->overlay_size,
        f->AOE_norm, f->Hdr_to_Image, f->Align_ratio,
        f->dlc_ASLR, f->dlc_NX, f->dlc_CFG, f->dlc_SafeSEH, f->large_image
    ); slow_line();
}
static int write_features_csv(const char* out_csv_path,
    const char* sample_filepath,
    const PE_FEATURES* f)
{
    if (!out_csv_path || !*out_csv_path || !f) return 0;

    FILE* fp = NULL;
    // 파일 존재 여부 확인
    int existed = 0;
    {
        FILE* tmp = NULL;
        if (fopen_s(&tmp, out_csv_path, "rb") == 0 && tmp) { existed = 1; fclose(tmp); }
    }
    if (fopen_s(&fp, out_csv_path, "ab") != 0 || !fp) return 0;

    // 새 파일이면 헤더 먼저
    if (!existed) {
        // 콘솔 헤더와 동일
        fprintf(fp,
            "filepath,is64,TimeDateStamp,NumberOfSections,Characteristics,Subsystem,DllCharacteristics,AddressOfEntryPoint,ImageBase,SizeOfImage,SizeOfHeaders,SectionAlignment,FileAlignment,SizeOfCode,SizeOfInitializedData,SizeOfUninitializedData,MajorLinker,MinorLinker,MajorOS,MinorOS,MajorSS,MinorSS,ImportSize,ExportSize,ResourceSize,IATSize,TLSSize,DebugSize,SecuritySize,sec_exec_count,sec_write_count,sec_entropy_mean,sec_entropy_max,sec_entropy_std,text_entropy,rsrc_entropy,sec_vsraw_mean,sec_vsraw_max,ratio_std_names,packed_like,num_imported_dlls,num_imported_funcs,has_KERNEL32,has_ADVAPI32,has_WS2_32,has_NTDLL,has_USER32,has_SHELL32,has_exports,num_exported_funcs,num_forwarded_exports,res_root_entries,res_has_versioninfo,res_icon_count,tls_has_callbacks,tls_callback_count,lc_has_cfg,lc_has_safeseh,lc_has_security_cookie,dbg_present,dbg_has_codeview,pdb_present,pdb_path_len,pdb_djb2,rich_present,rich_xor_key,rich_hash_djb2,security_size,security_present,overlay_size,AOE_norm,Hdr_to_Image,Align_ratio,dlc_ASLR,dlc_NX,dlc_CFG,dlc_SafeSEH,large_image\n"); slow_line();
    }

    // 행 쓰기(콘솔용 포맷과 동일)
    fprintf(fp,
        "\"%s\",%d,%u,%u,%u,%u,%u,%u,%llu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.6f,%.6f,%.6f,%u,%u,%u,%u,%u\n",
        sample_filepath ? sample_filepath : "",
        f->is64,
        f->TimeDateStamp, f->NumberOfSections, f->Characteristics, f->Subsystem, f->DllCharacteristics,
        f->AddressOfEntryPoint, (unsigned long long)f->ImageBase, f->SizeOfImage, f->SizeOfHeaders, f->SectionAlignment, f->FileAlignment,
        f->SizeOfCode, f->SizeOfInitializedData, f->SizeOfUninitializedData,
        f->MajorLinkerVersion, f->MinorLinkerVersion, f->MajorOSVersion, f->MinorOSVersion, f->MajorSSVersion, f->MinorSSVersion,
        f->dd_ImportSize, f->dd_ExportSize, f->dd_ResourceSize, f->dd_IATSize, f->dd_TLSSize, f->dd_DebugSize, f->dd_SecuritySize,
        f->sec_exec_count, f->sec_write_count,
        f->sec_entropy_mean, f->sec_entropy_max, f->sec_entropy_std, f->text_entropy, f->rsrc_entropy,
        f->sec_vsraw_mean, f->sec_vsraw_max, f->ratio_std_names, f->packed_like,
        f->num_imported_dlls, f->num_imported_funcs,
        f->has_KERNEL32, f->has_ADVAPI32, f->has_WS2_32, f->has_NTDLL, f->has_USER32, f->has_SHELL32,
        f->has_exports, f->num_exported_funcs, f->num_forwarded_exports,
        f->res_root_entries, f->res_has_versioninfo, f->res_icon_count,
        f->tls_has_callbacks, f->tls_callback_count,
        f->lc_has_cfg, f->lc_has_safeseh, f->lc_has_security_cookie,
        f->dbg_present, f->dbg_has_codeview, f->pdb_present, f->pdb_path_len, f->pdb_djb2,
        f->rich_present, f->rich_xor_key, f->rich_hash_djb2,
        f->security_size, f->security_present, f->overlay_size,
        f->AOE_norm, f->Hdr_to_Image, f->Align_ratio,
        f->dlc_ASLR, f->dlc_NX, f->dlc_CFG, f->dlc_SafeSEH, f->large_image
    ); slow_line();

    fclose(fp);
    return 1;
}

#endif // PE_PARSER_H
