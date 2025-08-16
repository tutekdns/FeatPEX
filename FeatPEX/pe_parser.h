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
    for (DWORD i = 0; i < n; i++) { printf("%02X ", p[i]); }
}

void print_dos_header_full(const PE_FILE* pe) {
    if (!pe || !pe->dosHeader) { printf("\033[1;31m[Error] Invalid DOS Header.\033[0m\n"); return; }
    const IMAGE_DOS_HEADER* dos = pe->dosHeader;
    printf("\n\033[1;36m[+] DOS HEADER (FULL)\033[0m\n\033[1;33m");
    printf("  e_magic   : 0x%04X ('MZ')\n", dos->e_magic);
    printf("  e_cblp    : 0x%04X\n", dos->e_cblp);
    printf("  e_cp      : 0x%04X\n", dos->e_cp);
    printf("  e_crlc    : 0x%04X\n", dos->e_crlc);
    printf("  e_cparhdr : 0x%04X\n", dos->e_cparhdr);
    printf("  e_minalloc: 0x%04X\n", dos->e_minalloc);
    printf("  e_maxalloc: 0x%04X\n", dos->e_maxalloc);
    printf("  e_ss      : 0x%04X\n", dos->e_ss);
    printf("  e_sp      : 0x%04X\n", dos->e_sp);
    printf("  e_csum    : 0x%04X\n", dos->e_csum);
    printf("  e_ip      : 0x%04X\n", dos->e_ip);
    printf("  e_cs      : 0x%04X\n", dos->e_cs);
    printf("  e_lfarlc  : 0x%04X\n", dos->e_lfarlc);
    printf("  e_ovno    : 0x%04X\n", dos->e_ovno);
    printf("  e_res[4]  : ");
    for (int i = 0; i < 4; i++) printf("0x%04X ", dos->e_res[i]); printf("\n");
    printf("  e_oemid   : 0x%04X\n", dos->e_oemid);
    printf("  e_oeminfo : 0x%04X\n", dos->e_oeminfo);
    printf("  e_res2[10]: "); for (int i = 0; i < 10; i++) printf("0x%04X ", dos->e_res2[i]); printf("\n");
    printf("  e_lfanew  : 0x%08X\n\033[0m", dos->e_lfanew);
}

void print_rich_header(const PE_FILE* pe) {
    if (!pe || !pe->data || !pe->dosHeader) { printf("\033[1;31m[Error] Invalid PE_FILE or data is NULL.\033[0m\n"); return; }
    printf("\n\033[1;36m[+] RICH HEADER\033[0m\n");
    BYTE* data = pe->data;
    DWORD richOffset = 0, danSOffset = 0, signature = 0;

    for (DWORD i = 0x80; i < 0x200; i += 4) {
        if (memcmp(&data[i], "Rich", 4) == 0) { richOffset = i; signature = *(DWORD*)&data[i + 4]; break; }
    }
    if (richOffset == 0) { printf("\033[1;33m  (Not present)\033[0m\n"); return; }

    for (int i = (int)richOffset - 4; i >= 0x40; i -= 4) {
        DWORD val = *(DWORD*)&data[i] ^ signature;
        if (val == 0x536E6144) { danSOffset = i; break; } // "DanS"
    }
    if (danSOffset == 0) { printf("\033[1;31m[Error] DanS signature not found.\033[0m\n"); return; }

    printf("\033[1;33m  DanS Offset : 0x%X\n  Rich Offset : 0x%X\n  XOR Key     : 0x%08X\n  Raw Entry Count: %u\033[0m\n",
        danSOffset, richOffset, signature, (richOffset - danSOffset - 16) / 8);

    for (DWORD i = danSOffset + 16; i < richOffset; i += 8) {
        DWORD compID = *(DWORD*)&data[i] ^ signature;
        DWORD count = *(DWORD*)&data[i + 4] ^ signature;
        WORD productId = (WORD)(compID >> 16);
        WORD toolId = (WORD)(compID & 0xFFFF);
        printf("    Tool ID: %5u | Product ID: %5u | Count: %5u\n", toolId, productId, count);
    }
}

void print_nt_header32(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader32) { printf("\033[1;31m[Error] NT Header (32-bit) is NULL.\033[0m\n"); return; }
    DWORD signature = pe->ntHeader32->Signature;
    printf("\n\033[1;36m[+] NT HEADER\033[0m\n\033[1;33m  Signature : 0x%08X ('PE\\0\\0')\033[0m\n", signature);
}
void print_nt_header64(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader64) { printf("\033[1;31m[Error] NT Header (64-bit) is NULL.\033[0m\n"); return; }
    DWORD signature = pe->ntHeader64->Signature;
    printf("\n\033[1;36m[+] NT HEADER (64-bit)\033[0m\n\033[1;33m  Signature: 0x%08X ('PE\\0\\0')\033[0m\n", signature);
}

static void print_file_characteristics(WORD c) {
    printf("  Characteristics:      0x%04X (", c);
    bool first = true;
#define OUT_FLAG(flag, name) do{ if (c & flag){ if(!first) printf(" | "); printf(name); first=false; } }while(0)
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
    printf(first ? "None)\n" : ")\n");
}

void print_file_header_full(const PE_FILE* pe) {
    if (!pe || !pe->fileHeader) { printf("\033[1;31m[Error] FILE Header is NULL.\033[0m\n"); return; }
    const IMAGE_FILE_HEADER* fh = pe->fileHeader;
    printf("\n\033[1;36m[+] FILE HEADER (FULL)\033[0m\n\033[1;33m");
    printf("  Machine:              0x%04X\n", fh->Machine);
    printf("  NumberOfSections:     0x%04X\n", fh->NumberOfSections);
    printf("  TimeDateStamp:        0x%08X\n", fh->TimeDateStamp);
    printf("  PointerToSymbolTable: 0x%08X\n", fh->PointerToSymbolTable);
    printf("  NumberOfSymbols:      0x%08X\n", fh->NumberOfSymbols);
    printf("  SizeOfOptionalHeader: 0x%04X\n", fh->SizeOfOptionalHeader);
    print_file_characteristics(fh->Characteristics);
    printf("\033[0m");
}

void print_optional_header32_full(const PE_FILE* pe) {
    if (!pe || !pe->optionalHeader32) { printf("\033[1;31m[Error] Optional Header (32-bit) is NULL.\033[0m\n"); return; }
    const IMAGE_OPTIONAL_HEADER32* o = pe->optionalHeader32;
    printf("\n\033[1;36m[+] OPTIONAL HEADER (32-bit, FULL)\033[0m\n\033[1;33m");
    printf("  Magic                         : 0x%04X\n", o->Magic);
    printf("  MajorLinkerVersion            : 0x%02X\n", o->MajorLinkerVersion);
    printf("  MinorLinkerVersion            : 0x%02X\n", o->MinorLinkerVersion);
    printf("  SizeOfCode                    : 0x%08X\n", o->SizeOfCode);
    printf("  SizeOfInitializedData         : 0x%08X\n", o->SizeOfInitializedData);
    printf("  SizeOfUninitializedData       : 0x%08X\n", o->SizeOfUninitializedData);
    printf("  AddressOfEntryPoint           : 0x%08X\n", o->AddressOfEntryPoint);
    printf("  BaseOfCode                    : 0x%08X\n", o->BaseOfCode);
    printf("  BaseOfData                    : 0x%08X\n", o->BaseOfData);
    printf("  ImageBase                     : 0x%08X\n", o->ImageBase);
    printf("  SectionAlignment              : 0x%08X\n", o->SectionAlignment);
    printf("  FileAlignment                 : 0x%08X\n", o->FileAlignment);
    printf("  MajorOperatingSystemVersion   : 0x%04X\n", o->MajorOperatingSystemVersion);
    printf("  MinorOperatingSystemVersion   : 0x%04X\n", o->MinorOperatingSystemVersion);
    printf("  MajorImageVersion             : 0x%04X\n", o->MajorImageVersion);
    printf("  MinorImageVersion             : 0x%04X\n", o->MinorImageVersion);
    printf("  MajorSubsystemVersion         : 0x%04X\n", o->MajorSubsystemVersion);
    printf("  MinorSubsystemVersion         : 0x%04X\n", o->MinorSubsystemVersion);
    printf("  Win32VersionValue             : 0x%08X\n", o->Win32VersionValue);
    printf("  SizeOfImage                   : 0x%08X\n", o->SizeOfImage);
    printf("  SizeOfHeaders                 : 0x%08X\n", o->SizeOfHeaders);
    printf("  CheckSum                      : 0x%08X\n", o->CheckSum);
    printf("  Subsystem                     : 0x%04X\n", o->Subsystem);
    printf("  DllCharacteristics            : 0x%04X\n", o->DllCharacteristics);
    printf("  SizeOfStackReserve            : 0x%08X\n", o->SizeOfStackReserve);
    printf("  SizeOfStackCommit             : 0x%08X\n", o->SizeOfStackCommit);
    printf("  SizeOfHeapReserve             : 0x%08X\n", o->SizeOfHeapReserve);
    printf("  SizeOfHeapCommit              : 0x%08X\n", o->SizeOfHeapCommit);
    printf("  LoaderFlags                   : 0x%08X\n", o->LoaderFlags);
    printf("  NumberOfRvaAndSizes           : 0x%08X\n\033[0m", o->NumberOfRvaAndSizes);
}

void print_optional_header64_full(const PE_FILE* pe) {
    if (!pe || !pe->optionalHeader64) { printf("\033[1;31m[Error] Optional Header (64-bit) is NULL.\033[0m\n"); return; }
    const IMAGE_OPTIONAL_HEADER64* o = pe->optionalHeader64;
    printf("\n\033[1;36m[+] OPTIONAL HEADER (64-bit, FULL)\033[0m\n\033[1;33m");
    printf("  Magic                         : 0x%04X\n", o->Magic);
    printf("  MajorLinkerVersion            : 0x%02X\n", o->MajorLinkerVersion);
    printf("  MinorLinkerVersion            : 0x%02X\n", o->MinorLinkerVersion);
    printf("  SizeOfCode                    : 0x%08X\n", o->SizeOfCode);
    printf("  SizeOfInitializedData         : 0x%08X\n", o->SizeOfInitializedData);
    printf("  SizeOfUninitializedData       : 0x%08X\n", o->SizeOfUninitializedData);
    printf("  AddressOfEntryPoint           : 0x%08X\n", o->AddressOfEntryPoint);
    printf("  BaseOfCode                    : 0x%08X\n", o->BaseOfCode);
    printf("  ImageBase                     : 0x%016llX\n", (unsigned long long)o->ImageBase);
    printf("  SectionAlignment              : 0x%08X\n", o->SectionAlignment);
    printf("  FileAlignment                 : 0x%08X\n", o->FileAlignment);
    printf("  MajorOperatingSystemVersion   : 0x%04X\n", o->MajorOperatingSystemVersion);
    printf("  MinorOperatingSystemVersion   : 0x%04X\n", o->MinorOperatingSystemVersion);
    printf("  MajorImageVersion             : 0x%04X\n", o->MajorImageVersion);
    printf("  MinorImageVersion             : 0x%04X\n", o->MinorImageVersion);
    printf("  MajorSubsystemVersion         : 0x%04X\n", o->MajorSubsystemVersion);
    printf("  MinorSubsystemVersion         : 0x%04X\n", o->MinorSubsystemVersion);
    printf("  Win32VersionValue             : 0x%08X\n", o->Win32VersionValue);
    printf("  SizeOfImage                   : 0x%08X\n", o->SizeOfImage);
    printf("  SizeOfHeaders                 : 0x%08X\n", o->SizeOfHeaders);
    printf("  CheckSum                      : 0x%08X\n", o->CheckSum);
    printf("  Subsystem                     : 0x%04X\n", o->Subsystem);
    printf("  DllCharacteristics            : 0x%04X\n", o->DllCharacteristics);
    printf("  SizeOfStackReserve            : 0x%016llX\n", (unsigned long long)o->SizeOfStackReserve);
    printf("  SizeOfStackCommit             : 0x%016llX\n", (unsigned long long)o->SizeOfStackCommit);
    printf("  SizeOfHeapReserve             : 0x%016llX\n", (unsigned long long)o->SizeOfHeapReserve);
    printf("  SizeOfHeapCommit              : 0x%016llX\n", (unsigned long long)o->SizeOfHeapCommit);
    printf("  LoaderFlags                   : 0x%08X\n", o->LoaderFlags);
    printf("  NumberOfRvaAndSizes           : 0x%08X\n\033[0m", o->NumberOfRvaAndSizes);
}

// =====================[ Print – Sections & DataDirs ]================
static void print_section_characteristics(DWORD characteristics) {
    printf("(");
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
    printf(")");
}

void print_section_headers_full(const PE_FILE* pe) {
    if (!pe || !pe->sectionHeaders || !pe->fileHeader) { printf("\033[1;31m[Error] Invalid section headers.\033[0m\n"); return; }
    WORD numberOfSections = pe->numberOfSections;
    printf("\n\033[1;36m[+] SECTION HEADERS (FULL)\033[0m\n");
    for (int i = 0; i < numberOfSections; i++) {
        const IMAGE_SECTION_HEADER* sh = &pe->sectionHeaders[i];
        char name[9] = { 0 }; memcpy(name, sh->Name, 8);
        printf("\033[1;33m  [%d] %s\033[0m\n\033[1;35m", i, name);
        printf("    VirtualAddress : 0x%08X\n", sh->VirtualAddress);
        printf("    VirtualSize    : 0x%08X\n", sh->Misc.VirtualSize);
        printf("    RawOffset      : 0x%08X\n", sh->PointerToRawData);
        printf("    RawSize        : 0x%08X\n", sh->SizeOfRawData);
        printf("    RelocsPtr      : 0x%08X\n", sh->PointerToRelocations);
        printf("    LineNumsPtr    : 0x%08X\n", sh->PointerToLinenumbers);
        printf("    NumRelocs      : 0x%04X\n", sh->NumberOfRelocations);
        printf("    NumLinenumbers : 0x%04X\n", sh->NumberOfLinenumbers);
        printf("    Characteristics: 0x%08X ", sh->Characteristics); print_section_characteristics(sh->Characteristics); printf("\033[0m\n");
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

    if (rva == 0 && size == 0) { printf("\033[1;33m[+] %s is empty.\033[0m\n", name); return; }

    DWORD off = rva_to_offset_pe(pe, rva);
    int secIdx = find_section_by_rva(pe, rva);
    const char* secName = "(none)"; char secNameBuf[9] = { 0 };
    if (secIdx >= 0) { memcpy(secNameBuf, pe->sectionHeaders[secIdx].Name, 8); secName = secNameBuf; }
    BOOL valid = (off != 0 && off < pe->size && rva < sizeOfImage);

    printf("\033[1;35m  [%2d] %-24s \033[0m", idx, name);
    printf("RVA: 0x%08X, Size: 0x%08X, ", rva, size);
    if (off) printf("FileOff: 0x%08X, ", off); else printf("FileOff: \033[1;31mN/A\033[0m, ");
    printf("Section: %s, ", secName);
    printf("Valid: %s\n", valid ? "\033[1;32mYes\033[0m" : "\033[1;31mNo\033[0m");

    if (preview16 && off && size && (off + 16) <= pe->size) {
        printf("       Preview: "); DWORD n = (size < 16) ? size : 16; print_bytes(pe->data + off, n);
        if (size > n) printf(".."); printf("\n");
    }
}

// ---- 전체 디렉토리 배너
static void print_data_directories_report(const PE_FILE* pe, BOOL preview16) {
    if (!pe || (!pe->optionalHeader32 && !pe->optionalHeader64)) { printf("\033[1;31m[Error] Invalid PE_FILE or Optional Header.\033[0m\n"); return; }
    DWORD dirCount = (!pe->is64Bit && pe->optionalHeader32) ? pe->optionalHeader32->NumberOfRvaAndSizes : pe->optionalHeader64->NumberOfRvaAndSizes;
    if (dirCount == 0) { printf("\n\033[1;36m[+] DATA DIRECTORIES\033[0m\n\033[1;33m[+] All data directories are empty.\033[0m\n"); return; }
    if (dirCount > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) dirCount = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    printf("\n\033[1;36m[+] DATA DIRECTORIES\033[0m\n");
    for (int i = 0; i < (int)dirCount; ++i) print_one_directory_report(pe, i, preview16);
}

void print_data_directories_smart(const PE_FILE* pe, BOOL show_empty) {
    (void)show_empty;
    print_data_directories_report(pe, TRUE);
}

// =====================[ Export / Import ]================
void print_export_table(const PE_FILE* pe) {
    if (!pe || !pe->data || !pe->sectionHeaders || (!pe->optionalHeader32 && !pe->optionalHeader64)) { printf("\033[1;31m[Error] Invalid PE_FILE structure.\033[0m\n"); return; }
    IMAGE_DATA_DIRECTORY exportDir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) { printf("\033[1;33m[+] Export Table is empty.\033[0m\n"); return; }

    DWORD exportOffset = rva_to_offset_pe(pe, exportDir.VirtualAddress);
    if (exportOffset == 0 || exportOffset + sizeof(IMAGE_EXPORT_DIRECTORY) > pe->size) { printf("\033[1;31m[Error] Invalid Export Table offset.\033[0m\n"); return; }

    IMAGE_EXPORT_DIRECTORY* expDir = (IMAGE_EXPORT_DIRECTORY*)(pe->data + exportOffset);

    DWORD nameCount = expDir->NumberOfNames;
    DWORD funcCount = expDir->NumberOfFunctions;
    DWORD ordBase = expDir->Base;

    printf("\n\033[1;36m[+] EXPORT TABLE\033[0m\n");
    DWORD nameOffset = rva_to_offset_pe(pe, expDir->Name);
    const char* dllName = (nameOffset && nameOffset < pe->size) ? (char*)(pe->data + nameOffset) : "(Unknown)";
    printf("\033[1;33m  DLL Name           : %s\n  Ordinal Base       : %u\n  Number of Names    : %u\n  Number of Functions: %u\033[0m\n",
        safe_str(dllName), ordBase, nameCount, funcCount);

    DWORD nameArrayOffset = rva_to_offset_pe(pe, expDir->AddressOfNames);
    DWORD ordinalArrayOffset = rva_to_offset_pe(pe, expDir->AddressOfNameOrdinals);
    DWORD funcArrayOffset = rva_to_offset_pe(pe, expDir->AddressOfFunctions);
    if (!nameArrayOffset || !ordinalArrayOffset || !funcArrayOffset) { printf("\033[1;31m[Error] Failed to locate export arrays.\033[0m\n"); return; }

    printf("\n\033[1;35m  %-6s %-8s %-10s %s\033[0m\n", "Index", "Ordinal", "FuncRVA", "Name");
    printf("  --------------------------------------------------------\n");

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

        printf("\033[1;33m  %-6u %-8u 0x%08X %s\033[0m\n", i, ordinal, funcRVA_i, safe_str(fname));
    }
}

void print_import_table(const PE_FILE* pe) {
    if (!pe || !pe->data || !pe->sectionHeaders || (!pe->optionalHeader32 && !pe->optionalHeader64)) { printf("\033[1;31m[Error] Invalid PE_FILE structure.\033[0m\n"); return; }
    IMAGE_DATA_DIRECTORY impDir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0 || impDir.Size == 0) { printf("\033[1;33m[+] Import Table is empty.\033[0m\n"); return; }

    DWORD impOff = rva_to_offset_pe(pe, impDir.VirtualAddress);
    if (impOff == 0 || impOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe->size) { printf("\033[1;31m[Error] Invalid Import Table offset.\033[0m\n"); return; }

    printf("\n\033[1;36m[+] IMPORT TABLE\033[0m\n");
    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(pe->data + impOff);
    for (;; desc++) {
        if ((BYTE*)desc + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe->data + pe->size) break;
        if (desc->Name == 0) break;

        DWORD nameOff = rva_to_offset_pe(pe, desc->Name);
        const char* dllName = (nameOff && nameOff < pe->size) ? (const char*)(pe->data + nameOff) : "(Unknown)";
        printf("\n\033[1;33m  DLL: %s\033[0m\n", safe_str(dllName));

        DWORD oftRVA = desc->OriginalFirstThunk; // INT
        DWORD ftRVA = desc->FirstThunk;         // IAT
        DWORD thunkRVA = oftRVA ? oftRVA : ftRVA;
        DWORD thunkOff = rva_to_offset_pe(pe, thunkRVA);
        if (!thunkOff) { printf("    (Invalid thunk array)\n"); continue; }

        printf("    %-6s %-12s %-8s  %s\n", "Index", "ThunkRVA", "By", "Name/Ordinal");

        if (pe->is64Bit) {
            IMAGE_THUNK_DATA64* th = (IMAGE_THUNK_DATA64*)(pe->data + thunkOff);
            for (DWORD idx = 0; ; ++idx, ++th) {
                if ((BYTE*)th + sizeof(IMAGE_THUNK_DATA64) > pe->data + pe->size) break;
                if (th->u1.AddressOfData == 0) break;
                if (th->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    WORD ord = (WORD)(th->u1.Ordinal & 0xFFFF);
                    printf("    %-6u 0x%010llX Ord      %u\n", idx, (unsigned long long)(thunkRVA + idx * sizeof(IMAGE_THUNK_DATA64)), ord);
                }
                else {
                    DWORD ibnRVA = (DWORD)th->u1.AddressOfData;
                    DWORD ibnOff = rva_to_offset_pe(pe, ibnRVA);
                    if (ibnOff && ibnOff + sizeof(IMAGE_IMPORT_BY_NAME) <= pe->size) {
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(pe->data + ibnOff);
                        printf("    %-6u 0x%010llX Name     %s (hint: %u)\n",
                            idx, (unsigned long long)(thunkRVA + idx * sizeof(IMAGE_THUNK_DATA64)),
                            (const char*)ibn->Name, ibn->Hint);
                    }
                    else {
                        printf("    %-6u 0x%010llX Name     (invalid)\n",
                            idx, (unsigned long long)(thunkRVA + idx * sizeof(IMAGE_THUNK_DATA64)));
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
                    printf("    %-6u 0x%08X   Ord      %u\n", idx, thunkRVA + idx * sizeof(IMAGE_THUNK_DATA32), ord);
                }
                else {
                    DWORD ibnRVA = th->u1.AddressOfData;
                    DWORD ibnOff = rva_to_offset_pe(pe, ibnRVA);
                    if (ibnOff && ibnOff + sizeof(IMAGE_IMPORT_BY_NAME) <= pe->size) {
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(pe->data + ibnOff);
                        printf("    %-6u 0x%08X   Name     %s (hint: %u)\n", idx, thunkRVA + idx * sizeof(IMAGE_THUNK_DATA32), (const char*)ibn->Name, ibn->Hint);
                    }
                    else {
                        printf("    %-6u 0x%08X   Name     (invalid)\n", idx, thunkRVA + idx * sizeof(IMAGE_THUNK_DATA32));
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
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Debug Directory is empty.\033[0m\n"); return; }
    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off || off + sizeof(IMAGE_DEBUG_DIRECTORY) > pe->size) { printf("\033[1;31m[Error] Debug directory invalid.\033[0m\n"); return; }

    printf("\n\033[1;36m[+] DEBUG DIRECTORY\033[0m\n");
    DWORD count = dir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (DWORD i = 0; i < count; i++) {
        IMAGE_DEBUG_DIRECTORY* d = (IMAGE_DEBUG_DIRECTORY*)(pe->data + off + i * sizeof(IMAGE_DEBUG_DIRECTORY));
        if ((BYTE*)d + sizeof(*d) > pe->data + pe->size) break;
        printf("\033[1;33m  [%lu]\033[0m\n", (unsigned long)i);
        printf("    Characteristics : 0x%08X\n", d->Characteristics);
        printf("    TimeDateStamp   : 0x%08X\n", d->TimeDateStamp);
        printf("    MajorVersion    : 0x%04X\n", d->MajorVersion);
        printf("    MinorVersion    : 0x%04X\n", d->MinorVersion);
        printf("    Type            : %u\n", d->Type);
        printf("    SizeOfData      : 0x%08X\n", d->SizeOfData);
        printf("    AddressOfRawData: 0x%08X\n", d->AddressOfRawData);
        printf("    PointerToRawData: 0x%08X\n", d->PointerToRawData);
    }
}

// TLS
void print_tls_table(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] TLS Table is empty.\033[0m\n"); return; }
    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off) { printf("\033[1;31m[Error] TLS offset invalid.\033[0m\n"); return; }

    printf("\n\033[1;36m[+] TLS TABLE\033[0m\n");
    if (pe->is64Bit) {
        if (off + sizeof(IMAGE_TLS_DIRECTORY64) > pe->size) { printf("\033[1;31m[Error] TLS64 out of range.\033[0m\n"); return; }
        IMAGE_TLS_DIRECTORY64* t = (IMAGE_TLS_DIRECTORY64*)(pe->data + off);
        printf("  StartAddressOfRawData : 0x%016llX\n", (unsigned long long)t->StartAddressOfRawData);
        printf("  EndAddressOfRawData   : 0x%016llX\n", (unsigned long long)t->EndAddressOfRawData);
        printf("  AddressOfIndex        : 0x%016llX\n", (unsigned long long)t->AddressOfIndex);
        printf("  AddressOfCallBacks    : 0x%016llX\n", (unsigned long long)t->AddressOfCallBacks);
        printf("  SizeOfZeroFill        : 0x%08X\n", t->SizeOfZeroFill);
        printf("  Characteristics       : 0x%08X\n", t->Characteristics);
    }
    else {
        if (off + sizeof(IMAGE_TLS_DIRECTORY32) > pe->size) { printf("\033[1;31m[Error] TLS32 out of range.\033[0m\n"); return; }
        IMAGE_TLS_DIRECTORY32* t = (IMAGE_TLS_DIRECTORY32*)(pe->data + off);
        printf("  StartAddressOfRawData : 0x%08X\n", t->StartAddressOfRawData);
        printf("  EndAddressOfRawData   : 0x%08X\n", t->EndAddressOfRawData);
        printf("  AddressOfIndex        : 0x%08X\n", t->AddressOfIndex);
        printf("  AddressOfCallBacks    : 0x%08X\n", t->AddressOfCallBacks);
        printf("  SizeOfZeroFill        : 0x%08X\n", t->SizeOfZeroFill);
        printf("  Characteristics       : 0x%08X\n", t->Characteristics);
    }
}

// Relocations
void print_base_relocations(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Base Relocation Table is empty.\033[0m\n"); return; }
    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off) { printf("\033[1;31m[Error] Reloc offset invalid.\033[0m\n"); return; }

    printf("\n\033[1;36m[+] BASE RELOCATION TABLE\033[0m\n");
    DWORD cur = off, end = off + dir.Size;
    while (cur + sizeof(IMAGE_BASE_RELOCATION) <= end && cur + sizeof(IMAGE_BASE_RELOCATION) <= pe->size) {
        IMAGE_BASE_RELOCATION* b = (IMAGE_BASE_RELOCATION*)(pe->data + cur);
        if (b->SizeOfBlock == 0) break;
        DWORD entries = (b->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        printf("\033[1;33m  Block VA: 0x%08X, SizeOfBlock: 0x%08X, Entries: %u\033[0m\n", b->VirtualAddress, b->SizeOfBlock, entries);

        // 간단 통계(타입별 카운트)
        unsigned counts[16] = { 0 };
        WORD* w = (WORD*)(pe->data + cur + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < entries && (BYTE*)(w + i) < pe->data + pe->size; i++) counts[(w[i] >> 12) & 0xF]++;

        printf("    Types: ABS=%u, HIGH=%u, LOW=%u, HIGHLOW=%u, DIR64=%u, OTHERS=%u\n",
            counts[0], counts[1], counts[2], counts[3], counts[10], entries - (counts[0] + counts[1] + counts[2] + counts[3] + counts[10]));
        cur += b->SizeOfBlock;
    }
}

// Load Config
void print_load_config(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Load Config Table is empty.\033[0m\n"); return; }
    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off) { printf("\033[1;31m[Error] LoadConfig offset invalid.\033[0m\n"); return; }

    printf("\n\033[1;36m[+] LOAD CONFIG TABLE (%s)\033[0m\n", pe->is64Bit ? "64" : "32");
    if (pe->is64Bit) {
        IMAGE_LOAD_CONFIG_DIRECTORY64* lc = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(pe->data + off);
        if ((BYTE*)lc + sizeof(*lc) > pe->data + pe->size) { printf("\033[1;31m[Error] LoadConfig64 out of range.\033[0m\n"); return; }
        printf("  Size                      : 0x%08X\n", lc->Size);
        printf("  TimeDateStamp             : 0x%08X\n", lc->TimeDateStamp);
        printf("  GuardFlags                : 0x%08X\n", lc->GuardFlags);
        printf("  SecurityCookie            : 0x%016llX\n", (unsigned long long)lc->SecurityCookie);
        printf("  SEHandlerTable            : 0x%016llX (Count: %u)\n", (unsigned long long)lc->SEHandlerTable, lc->SEHandlerCount);
        printf("  GuardCFCheckFunctionPtr   : 0x%016llX\n", (unsigned long long)lc->GuardCFCheckFunctionPointer);
        printf("  GuardCFFunctionTable      : 0x%016llX (Count: %u)\n", (unsigned long long)lc->GuardCFFunctionTable, lc->GuardCFFunctionCount);
    }
    else {
        IMAGE_LOAD_CONFIG_DIRECTORY32* lc = (IMAGE_LOAD_CONFIG_DIRECTORY32*)(pe->data + off);
        if ((BYTE*)lc + sizeof(*lc) > pe->data + pe->size) { printf("\033[1;31m[Error] LoadConfig32 out of range.\033[0m\n"); return; }
        printf("  Size                      : 0x%08X\n", lc->Size);
        printf("  TimeDateStamp             : 0x%08X\n", lc->TimeDateStamp);
        printf("  GuardFlags                : 0x%08X\n", lc->GuardFlags);
        printf("  SecurityCookie            : 0x%08X\n", lc->SecurityCookie);
        printf("  SEHandlerTable            : 0x%08X (Count: %u)\n", lc->SEHandlerTable, lc->SEHandlerCount);
        printf("  GuardCFCheckFunctionPtr   : 0x%08X\n", lc->GuardCFCheckFunctionPointer);
        printf("  GuardCFFunctionTable      : 0x%08X (Count: %u)\n", lc->GuardCFFunctionTable, lc->GuardCFFunctionCount);
    }
}

// Bound Import
void print_bound_imports(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Bound Import is empty.\033[0m\n"); return; }

    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off) { printf("\033[1;31m[Error] BoundImport offset invalid.\033[0m\n"); return; }
    printf("\n\033[1;36m[+] BOUND IMPORT\033[0m\n");

    DWORD cur = off;
    while (cur + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) <= off + dir.Size && cur + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) <= pe->size) {
        IMAGE_BOUND_IMPORT_DESCRIPTOR* d = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(pe->data + cur);
        if (d->OffsetModuleName == 0 && d->NumberOfModuleForwarderRefs == 0) break;

        const char* mod = "(unknown)";
        if (d->OffsetModuleName) {
            DWORD nameOff = off + d->OffsetModuleName;
            if (nameOff < pe->size) mod = (const char*)(pe->data + nameOff);
        }
        printf("  Module: %s | TimeDateStamp: 0x%08X | Forwarders: %u\n", safe_str(mod), d->TimeDateStamp, d->NumberOfModuleForwarderRefs);
        cur += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);
    }
}

// Delay Import
void print_delay_imports(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Delay Import is empty.\033[0m\n"); return; }

    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off) { printf("\033[1;31m[Error] DelayImport offset invalid.\033[0m\n"); return; }
    printf("\n\033[1;36m[+] DELAY IMPORT\033[0m\n");

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
            dll ? dll : "(unknown)", d->TimeDateStamp, attrs);

        printf("    ModuleHandleRVA        : 0x%08X\n", d->ModuleHandleRVA);
        printf("    ImportAddressTableRVA  : 0x%08X\n", d->ImportAddressTableRVA);
        printf("    ImportNameTableRVA     : 0x%08X\n", d->ImportNameTableRVA);
        printf("    BoundImportAddressTable: 0x%08X\n", d->BoundImportAddressTableRVA);
        printf("    UnloadInformationTable : 0x%08X\n", d->UnloadInformationTableRVA);
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
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] Resource Table is empty.\033[0m\n"); return; }
    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off || off + sizeof(IMAGE_RESOURCE_DIR) > pe->size) { printf("\033[1;31m[Error] Resource root invalid.\033[0m\n"); return; }

    printf("\n\033[1;36m[+] RESOURCE DIRECTORY (Root summary)\033[0m\n");
    IMAGE_RESOURCE_DIR* r = (IMAGE_RESOURCE_DIR*)(pe->data + off);
    printf("  TimeDateStamp      : 0x%08X\n", r->TimeDateStamp);
    printf("  MajorVersion       : 0x%04X\n", r->MajorVersion);
    printf("  MinorVersion       : 0x%04X\n", r->MinorVersion);
    printf("  NamedEntries       : %u\n", r->NumberOfNamedEntries);
    printf("  IdEntries          : %u\n", r->NumberOfIdEntries);
}

// CLR/.NET
void print_clr_header(const PE_FILE* pe) {
    IMAGE_DATA_DIRECTORY dir = pe->is64Bit ? pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
        : pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    if (!dir.VirtualAddress || !dir.Size) { printf("\033[1;33m[+] CLR (.NET) Header is empty.\033[0m\n"); return; }

    DWORD off = rva_to_offset_pe(pe, dir.VirtualAddress);
    if (!off || off + sizeof(IMAGE_COR20_HEADER_MIN) > pe->size) { printf("\033[1;31m[Error] CLR header invalid.\033[0m\n"); return; }

    IMAGE_COR20_HEADER_MIN* c = (IMAGE_COR20_HEADER_MIN*)(pe->data + off);
    printf("\n\033[1;36m[+] CLR (.NET) HEADER\033[0m\n");
    printf("  cb                     : 0x%08X\n", c->cb);
    printf("  RuntimeVersion         : %u.%u\n", c->MajorRuntimeVersion, c->MinorRuntimeVersion);
    printf("  MetaData               : RVA=0x%08X, Size=0x%08X\n", c->MetaData.VirtualAddress, c->MetaData.Size);
    printf("  Flags                  : 0x%08X\n", c->Flags);
    printf("  EntryPoint             : 0x%08X\n", c->EntryPointToken);
    printf("  Resources              : RVA=0x%08X, Size=0x%08X\n", c->Resources.VirtualAddress, c->Resources.Size);
    printf("  StrongNameSignature    : RVA=0x%08X, Size=0x%08X\n", c->StrongNameSignature.VirtualAddress, c->StrongNameSignature.Size);
    printf("  VTableFixups           : RVA=0x%08X, Size=0x%08X\n", c->VTableFixups.VirtualAddress, c->VTableFixups.Size);
    printf("  ManagedNativeHeader    : RVA=0x%08X, Size=0x%08X\n", c->ManagedNativeHeader.VirtualAddress, c->ManagedNativeHeader.Size);
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
    if (fopen_s(&fp, filepath, "rb") != 0 || fp == NULL) { printf("\033[1;31m[Error] Cannot open file for PE type detection: %s\033[0m\n", filepath); return 0; }
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
            printf("\033[1;31m[Error] Unknown OptionalHeader.Magic: 0x%X\033[0m\n", magic);
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

#endif // PE_PARSER_H
