#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <Windows.h>
#include <stdio.h>
#include <ctype.h>
#include <imagehlp.h>

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

DWORD rva_to_offset(DWORD rva, IMAGE_SECTION_HEADER* sections, int nSections);               // RVA�� ���� ���������� ��ȯ�ϴ� �Լ�

// --------------------- ����ü ---------------------
typedef struct _PE_FILE {
    BYTE* data;                                                                     // ��ü PE ������ raw ������
    DWORD size;                                                                     // ���� ũ��

    BYTE* buffer;                                                                   // ��ü ���� ������ �޸𸮿� ����
    DWORD fileSize;                                                                 // ���� ũ��

    // --- DOS_HEADER ---
    IMAGE_DOS_HEADER* dosHeader;                                                    // MZ ��� (IMAGE_DOS_HEADER)

    // --- DOS_STUB ---
    BYTE* dosStub;                                                                  // DOS Stub (MZ ���� ~ PE Signature ��)

    // --- RICH_HEADER ---
    BYTE* richHeaderStart;                                                          // Rich Header ���� ���� ("DanS"���� ����)
    DWORD richHeaderSize;                                                           // Rich Header ũ�� ("Rich"+XOR Ű���� ����)

    // --- NT_HEADER ---
    IMAGE_NT_HEADERS32* ntHeader32;                                                 // NT ��� (32��Ʈ��)
    IMAGE_NT_HEADERS64* ntHeader64;                                                 // NT ��� (64��Ʈ��)
    BOOL is64Bit;                                                                   // 64��Ʈ ���� �÷���

    // --- FILE_HEADER ---
    IMAGE_FILE_HEADER* fileHeader;                                                  // ���� FILE HEADER

    // --- OPTIONAL_HEADER ---
    IMAGE_OPTIONAL_HEADER32* optionalHeader32;                                      // Optional Header (32��Ʈ��)
    IMAGE_OPTIONAL_HEADER64* optionalHeader64;                                      // Optional Header (64��Ʈ��)

    // --- SECTION_HEADER ---
    IMAGE_SECTION_HEADER* sectionHeaders;                                           // Section Header �迭 ������
	WORD numberOfSections;                                                          // ���� ����
} PE_FILE;

// --------------------- �ε� �� �ʱ�ȭ ---------------------
int load_pe_file(const char* filepath, PE_FILE* pe) {
    if (pe == NULL) {
        printf("\033[1;31m[Error] PE_FILE structure is NULL.\033[0m\n");
        return 0;
    }

    memset(pe, 0, sizeof(PE_FILE)); // ����ü �ʱ�ȭ

    FILE* fp = NULL;
    if (fopen_s(&fp, filepath, "rb") != 0 || fp == NULL) {
        printf("\033[1;31m[Error] Cannot open file: %s\033[0m\n", filepath);
        return 0;
    }

    // ���� ũ�� ���ϱ�
    fseek(fp, 0, SEEK_END);
    pe->size = ftell(fp);
    rewind(fp);

    // �޸� �Ҵ� �� �б�
    pe->data = (BYTE*)malloc(pe->size);
    if (!pe->data) {
        printf("\033[1;31m[Error] Memory allocation failed.\033[0m\n");
        fclose(fp);
        return 0;
    }

    if (fread(pe->data, 1, pe->size, fp) != pe->size) {
        printf("\033[1;31m[Error] File read error.\033[0m\n");
        free(pe->data);
        fclose(fp);
        return 0;
    }

    fclose(fp); // ���� �ݱ�
    // -----------------------------
    // PE ����ü ���� ������ ����
    // -----------------------------
    // DOS Header
    pe->dosHeader = (IMAGE_DOS_HEADER*)(pe->data);
    if (pe->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("\033[1;31m[Error] Invalid MZ signature.\033[0m\n");
        free(pe->data);
        return 0;
    }

    DWORD peOffset = pe->dosHeader->e_lfanew;
    DWORD peSignature = *(DWORD*)(pe->data + peOffset);
    if (peSignature != IMAGE_NT_SIGNATURE) {
        printf("\033[1;31m[Error] Invalid PE signature.\033[0m\n");
        free(pe->data);
        return 0;
    }

	// DOS Stub
    pe->dosStub = (BYTE*)pe->dosHeader + sizeof(IMAGE_DOS_HEADER);

    // Rich Header Ž��
    BYTE* p = pe->dosStub;
    DWORD stubSize = peOffset - sizeof(IMAGE_DOS_HEADER);
    for (DWORD i = 0; i < stubSize - 8; i++) {
        if (memcmp(&p[i], "DanS", 4) == 0) {
            pe->richHeaderStart = &p[i];
            for (DWORD j = i + 4; j < stubSize - 4; j += 4) {
                if (memcmp(&p[j], "Rich", 4) == 0) {
                    pe->richHeaderSize = (j - i) + 8;
                    break;
                }
            }
            break;
        }
    }

    // NT Header
    pe->ntHeader32 = (IMAGE_NT_HEADERS32*)(pe->data + peOffset);

    // Bitness �Ǵ�
    WORD magic = pe->ntHeader32->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        pe->is64Bit = TRUE;
        pe->ntHeader64 = (IMAGE_NT_HEADERS64*)(pe->data + peOffset);
        pe->optionalHeader64 = &pe->ntHeader64->OptionalHeader;
        pe->fileHeader = &pe->ntHeader64->FileHeader;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        pe->is64Bit = FALSE;
        pe->optionalHeader32 = &pe->ntHeader32->OptionalHeader;
        pe->fileHeader = &pe->ntHeader32->FileHeader;
    }
    else {
        printf("\033[1;31m[Error] Unknown PE optional header magic: 0x%X\033[0m\n", magic);
        free(pe->data);
        return 0;
    }

    if (pe->is64Bit) {
        pe->numberOfSections = pe->ntHeader64->FileHeader.NumberOfSections;
    }
    else {
        pe->numberOfSections = pe->ntHeader32->FileHeader.NumberOfSections;
    }

    // Section Headers
    IMAGE_FILE_HEADER* fileHeader = pe->fileHeader;
    pe->sectionHeaders = (IMAGE_SECTION_HEADER*)(
        pe->data + peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader->SizeOfOptionalHeader
        );

    return 1;
}                        // PE ���� �ε� �� �ʱ�ȭ      
void free_pe_file(PE_FILE* pe);                                                     // PE ���� �޸� ����

// --------------------- ���� ��� ---------------------
// DOS ��� ���
void print_dos_header(const PE_FILE* pe) {
    if (!pe || !pe->dosHeader) {
        printf("\033[1;31m[Error] Invalid PE_FILE or DOS Header is NULL.\033[0m\n");
        return;
    }

    const IMAGE_DOS_HEADER* dos = pe->dosHeader;

    printf("\n\033[1;36m[+] DOS HEADER\033[0m\n");
    printf("\033[1;33m");  // ����� ����

    printf("  e_magic:      0x%04X (Magic number: 'MZ')\n", dos->e_magic);
    printf("  e_cblp:       0x%04X (Bytes on last page of file)\n", dos->e_cblp);
    printf("  e_cp:         0x%04X (Pages in file)\n", dos->e_cp);
    printf("  e_crlc:       0x%04X (Relocations)\n", dos->e_crlc);
    printf("  e_cparhdr:    0x%04X (Size of header in paragraphs)\n", dos->e_cparhdr);
    printf("  e_minalloc:   0x%04X (Minimum extra paragraphs needed)\n", dos->e_minalloc);
    printf("  e_maxalloc:   0x%04X (Maximum extra paragraphs needed)\n", dos->e_maxalloc);
    printf("  e_ss:         0x%04X (Initial (relative) SS value)\n", dos->e_ss);
    printf("  e_sp:         0x%04X (Initial SP value)\n", dos->e_sp);
    printf("  e_csum:       0x%04X (Checksum)\n", dos->e_csum);
    printf("  e_ip:         0x%04X (Initial IP value)\n", dos->e_ip);
    printf("  e_cs:         0x%04X (Initial (relative) CS value)\n", dos->e_cs);
    printf("  e_lfarlc:     0x%04X (File address of relocation table)\n", dos->e_lfarlc);
    printf("  e_ovno:       0x%04X (Overlay number)\n", dos->e_ovno);

    printf("  e_res[4]:     ");
    for (int i = 0; i < 4; i++) {
        printf("0x%04X ", dos->e_res[i]);
    }
    printf("(Reserved words)\n");

    printf("  e_oemid:      0x%04X (OEM identifier)\n", dos->e_oemid);
    printf("  e_oeminfo:    0x%04X (OEM information)\n", dos->e_oeminfo);

    printf("  e_res2[10]:   ");
    for (int i = 0; i < 10; i++) {
        printf("0x%04X ", dos->e_res2[i]);
    }
    printf("(Reserved words)\n");

    printf("  e_lfanew:     0x%08X (File address of new exe header)\n", dos->e_lfanew);

    printf("\033[0m");  // ���� �ʱ�ȭ
}
// Rich ��� ���
void print_rich_header(const PE_FILE* pe) {
    if (!pe || !pe->data || !pe->dosHeader) {
        printf("\033[1;31m[Error] Invalid PE_FILE or data is NULL.\033[0m\n");
        return;
    }

    printf("\n\033[1;36m[+] RICH HEADER\033[0m\n");

    BYTE* data = pe->data;
    DWORD richOffset = 0;
    DWORD danSOffset = 0;
    DWORD signature = 0;

    for (DWORD i = 0x80; i < 0x200; i += 4) {
        if (memcmp(&data[i], "Rich", 4) == 0) {
            richOffset = i;
            signature = *(DWORD*)&data[i + 4];
            break;
        }
    }

    if (richOffset == 0) {
        printf("\033[1;31m[Error] Rich header not found.\033[0m\n");
        return;
    }

    for (int i = richOffset - 4; i >= 0x40; i -= 4) {
        DWORD val = *(DWORD*)&data[i] ^ signature;
        if (val == 0x536E6144) { // "DanS"
            danSOffset = i;
            break;
        }
    }

    if (danSOffset == 0) {
        printf("\033[1;31m[Error] DanS signature not found.\033[0m\n");
        return;
    }

    printf("\033[1;33m");
    printf("  DanS Offset : 0x%X\n", danSOffset);
    printf("  Rich Offset : 0x%X\n", richOffset);
    printf("  XOR Key     : 0x%08X\n", signature);
    printf("  Raw Entry Count: %d\n", (richOffset - danSOffset - 16) / 8);
    printf("\033[0m");

    printf("\033[1;33m");
    for (DWORD i = danSOffset + 16; i < richOffset; i += 8) {
        DWORD compID = *(DWORD*)&data[i] ^ signature;
        DWORD count = *(DWORD*)&data[i + 4] ^ signature;

        WORD productId = compID >> 16;
        WORD toolId = compID & 0xFFFF;

        printf("\033[1;33m");
        printf("    Tool ID: %5d | Product ID: %5d | Count: %5d\n", toolId, productId, count);
        printf("\033[0m");
    }
    printf("\033[0m");
}
// NT ��� ��� (32��Ʈ)
void print_nt_header32(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader32) {
        printf("\033[1;31m[Error] Invalid PE_FILE or NT Header (32-bit) is NULL.\033[0m\n");
        return;
    }

    DWORD signature = pe->ntHeader32->Signature;

    printf("\n\033[1;36m[+] NT HEADER\033[0m\n");
    printf("\033[1;33m");
    printf("  Signature : 0x%08X (", signature);

    // 'PE\0\0' ���
    char sigBytes[5] = { 0 };
    memcpy(sigBytes, &signature, 4);
    for (int i = 0; i < 4; i++) {
        if (isprint(sigBytes[i]))
            printf("%c", sigBytes[i]);
        else
            printf(".");
    }
    printf(")\n");
    printf("\033[0m");
}
// NT ��� ��� (64��Ʈ)
void print_nt_header64(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader32) {
        printf("\033[1;31m[Error] Invalid PE_FILE or NT Header (64-bit) is NULL.\033[0m\n");
        return;
    }

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(pe->ntHeader32);  // reinterpret cast

    DWORD signature = nt->Signature;

    printf("\n\033[1;36m[+] NT HEADER (64-bit)\033[0m\n");
    printf("\033[1;33m");
    printf("  Signature: 0x%08X (", signature);

    // 'PE\0\0' ���
    char sigBytes[5] = { 0 };
    memcpy(sigBytes, &signature, 4);
    for (int i = 0; i < 4; i++) {
        if (isprint((unsigned char)sigBytes[i]))
            printf("%c", sigBytes[i]);
        else
            printf(".");
    }
    printf(")\n");
    printf("\033[0m");
}
// file characteristics ���
void print_file_characteristics(WORD characteristics) {
    printf("  Characteristics:      0x%04X ", characteristics);

    // Ȱ��ȭ�� �÷��׸� ���
    printf("(");
    bool first = true;

    if (characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        printf("%sRELOCS_STRIPPED", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        printf("%sEXECUTABLE_IMAGE", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) {
        printf("%sLINE_NUMS_STRIPPED", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) {
        printf("%sLOCAL_SYMS_STRIPPED", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_AGGRESSIVE_WS_TRIM) {
        printf("%sAGGRESSIVE_WS_TRIM", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) {
        printf("%sLARGE_ADDRESS_AWARE", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_BYTES_REVERSED_LO) {
        printf("%sBYTES_REVERSED_LO", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_32BIT_MACHINE) {
        printf("%s32BIT_MACHINE", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_DEBUG_STRIPPED) {
        printf("%sDEBUG_STRIPPED", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) {
        printf("%sREMOVABLE_RUN_FROM_SWAP", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) {
        printf("%sNET_RUN_FROM_SWAP", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_SYSTEM) {
        printf("%sSYSTEM", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_DLL) {
        printf("%sDLL", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) {
        printf("%sUP_SYSTEM_ONLY", first ? "" : " | ");
        first = false;
    }
    if (characteristics & IMAGE_FILE_BYTES_REVERSED_HI) {
        printf("%sBYTES_REVERSED_HI", first ? "" : " | ");
        first = false;
    }

    if (first) {
        printf("None");
    }

    printf(")\n");
}
// File ��� ���
void print_file_header(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader32) {
        printf("\033[1;31m[Error] Invalid PE_FILE or NT Header is NULL.\033[0m\n");
        return;
    }

    const IMAGE_FILE_HEADER* fh = &(pe->ntHeader32->FileHeader);  // 32/64 ����

    printf("\n\033[1;36m[+] FILE HEADER\033[0m\n");
    printf("\033[1;33m");
    printf("  Machine:              0x%04X\n", fh->Machine);
    printf("  NumberOfSections:     0x%04X\n", fh->NumberOfSections);
    printf("  TimeDateStamp:        0x%08X\n", fh->TimeDateStamp);
    printf("  PointerToSymbolTable: 0x%08X\n", fh->PointerToSymbolTable);
    printf("  NumberOfSymbols:      0x%08X\n", fh->NumberOfSymbols);
    printf("  SizeOfOptionalHeader: 0x%04X\n", fh->SizeOfOptionalHeader);
    // Characteristics �÷��� �� ���
    printf("  Characteristics:      0x%04X ", fh->Characteristics);
    print_file_characteristics(fh->Characteristics);  // ���⿡ �÷��� �ؼ� �߰�
    printf("\033[0m");

    printf("\033[0m");
}
// Optional ��� ��� (32��Ʈ)
void print_optional_header32(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader32) {
        printf("\033[1;31m[Error] Invalid PE_FILE or NT Header (32-bit) is NULL.\033[0m\n");
        return;
    }

    const IMAGE_OPTIONAL_HEADER32* opt = &pe->ntHeader32->OptionalHeader;

    printf("\n\033[1;36m[+] OPTIONAL HEADER (32-bit)\033[0m\n");
    printf("\033[1;33m");
    printf("  Magic:                         0x%04X\n", opt->Magic);
    printf("  MajorLinkerVersion:           0x%02X\n", opt->MajorLinkerVersion);
    printf("  MinorLinkerVersion:           0x%02X\n", opt->MinorLinkerVersion);
    printf("  SizeOfCode:                   0x%08X\n", opt->SizeOfCode);
    printf("  SizeOfInitializedData:        0x%08X\n", opt->SizeOfInitializedData);
    printf("  SizeOfUninitializedData:      0x%08X\n", opt->SizeOfUninitializedData);
    printf("  AddressOfEntryPoint:          0x%08X\n", opt->AddressOfEntryPoint);
    printf("  BaseOfCode:                   0x%08X\n", opt->BaseOfCode);
    printf("  BaseOfData:                   0x%08X\n", opt->BaseOfData);
    printf("  ImageBase:                    0x%08X\n", opt->ImageBase);
    printf("  SectionAlignment:             0x%08X\n", opt->SectionAlignment);
    printf("  FileAlignment:                0x%08X\n", opt->FileAlignment);
    printf("  MajorOperatingSystemVersion:  0x%04X\n", opt->MajorOperatingSystemVersion);
    printf("  MinorOperatingSystemVersion:  0x%04X\n", opt->MinorOperatingSystemVersion);
    printf("  MajorImageVersion:            0x%04X\n", opt->MajorImageVersion);
    printf("  MinorImageVersion:            0x%04X\n", opt->MinorImageVersion);
    printf("  MajorSubsystemVersion:        0x%04X\n", opt->MajorSubsystemVersion);
    printf("  MinorSubsystemVersion:        0x%04X\n", opt->MinorSubsystemVersion);
    printf("  Win32VersionValue:            0x%08X\n", opt->Win32VersionValue);
    printf("  SizeOfImage:                  0x%08X\n", opt->SizeOfImage);
    printf("  SizeOfHeaders:                0x%08X\n", opt->SizeOfHeaders);
    printf("  CheckSum:                     0x%08X\n", opt->CheckSum);
    printf("  Subsystem:                    0x%04X\n", opt->Subsystem);
    printf("  DllCharacteristics:           0x%04X\n", opt->DllCharacteristics);
    printf("  SizeOfStackReserve:           0x%08X\n", opt->SizeOfStackReserve);
    printf("  SizeOfStackCommit:            0x%08X\n", opt->SizeOfStackCommit);
    printf("  SizeOfHeapReserve:            0x%08X\n", opt->SizeOfHeapReserve);
    printf("  SizeOfHeapCommit:             0x%08X\n", opt->SizeOfHeapCommit);
    printf("  LoaderFlags:                  0x%08X\n", opt->LoaderFlags);
    printf("  NumberOfRvaAndSizes:          0x%08X\n", opt->NumberOfRvaAndSizes);
    printf("\033[0m");
}
// Optional ��� ��� (64��Ʈ)
void print_optional_header64(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader64) {
        printf("\033[1;31m[Error] Invalid PE_FILE or NT Header (64-bit) is NULL.\033[0m\n");
        return;
    }

    const IMAGE_OPTIONAL_HEADER64* opt = &pe->ntHeader64->OptionalHeader;

    printf("\n\033[1;36m[+] OPTIONAL HEADER (64-bit)\033[0m\n");
    printf("\033[1;33m");
    printf("  Magic:                         0x%04X\n", opt->Magic);
    printf("  MajorLinkerVersion:           0x%02X\n", opt->MajorLinkerVersion);
    printf("  MinorLinkerVersion:           0x%02X\n", opt->MinorLinkerVersion);
    printf("  SizeOfCode:                   0x%08X\n", opt->SizeOfCode);
    printf("  SizeOfInitializedData:        0x%08X\n", opt->SizeOfInitializedData);
    printf("  SizeOfUninitializedData:      0x%08X\n", opt->SizeOfUninitializedData);
    printf("  AddressOfEntryPoint:          0x%08X\n", opt->AddressOfEntryPoint);
    printf("  BaseOfCode:                   0x%08X\n", opt->BaseOfCode);
    printf("  ImageBase:                    0x%016llX\n", (unsigned long long)opt->ImageBase);
    printf("  SectionAlignment:             0x%08X\n", opt->SectionAlignment);
    printf("  FileAlignment:                0x%08X\n", opt->FileAlignment);
    printf("  MajorOperatingSystemVersion:  0x%04X\n", opt->MajorOperatingSystemVersion);
    printf("  MinorOperatingSystemVersion:  0x%04X\n", opt->MinorOperatingSystemVersion);
    printf("  MajorImageVersion:            0x%04X\n", opt->MajorImageVersion);
    printf("  MinorImageVersion:            0x%04X\n", opt->MinorImageVersion);
    printf("  MajorSubsystemVersion:        0x%04X\n", opt->MajorSubsystemVersion);
    printf("  MinorSubsystemVersion:        0x%04X\n", opt->MinorSubsystemVersion);
    printf("  Win32VersionValue:            0x%08X\n", opt->Win32VersionValue);
    printf("  SizeOfImage:                  0x%08X\n", opt->SizeOfImage);
    printf("  SizeOfHeaders:                0x%08X\n", opt->SizeOfHeaders);
    printf("  CheckSum:                     0x%08X\n", opt->CheckSum);
    printf("  Subsystem:                    0x%04X\n", opt->Subsystem);
    printf("  DllCharacteristics:           0x%04X\n", opt->DllCharacteristics);
    printf("  SizeOfStackReserve:           0x%016llX\n", (unsigned long long)opt->SizeOfStackReserve);
    printf("  SizeOfStackCommit:            0x%016llX\n", (unsigned long long)opt->SizeOfStackCommit);
    printf("  SizeOfHeapReserve:            0x%016llX\n", (unsigned long long)opt->SizeOfHeapReserve);
    printf("  SizeOfHeapCommit:             0x%016llX\n", (unsigned long long)opt->SizeOfHeapCommit);
    printf("  LoaderFlags:                  0x%08X\n", opt->LoaderFlags);
    printf("  NumberOfRvaAndSizes:          0x%08X\n", opt->NumberOfRvaAndSizes);
    printf("\033[0m");
}
// Section Characteristics ���
void print_section_characteristics(DWORD characteristics) {
    printf("(");
    bool first = true;

#define ADD_FLAG(flag, desc) \
        if (characteristics & flag) { \
            if (!first) printf(", "); \
            printf(desc); \
            first = false; \
        }

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

    printf(")");
}
// Section ��� ���
void print_section_headers(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader32 || !pe->sectionHeaders) {
        printf("\033[1;31m[Error] Invalid PE_FILE or section headers.\033[0m\n");
        return;
    }

    WORD numberOfSections = pe->ntHeader32->FileHeader.NumberOfSections;

    printf("\n\033[1;36m[+] SECTION HEADERS\033[0m\n");

    for (int i = 0; i < numberOfSections; i++) {
        const IMAGE_SECTION_HEADER* sh = &pe->sectionHeaders[i];

        char name[9] = { 0 };
        memcpy(name, sh->Name, 8);

        printf("\033[1;33m  [%d] %s\033[0m\n", i, name);
        printf("\033[1;35m");
        printf("    VirtualAddress : 0x%08X\n", sh->VirtualAddress);
        printf("    VirtualSize    : 0x%08X\n", sh->Misc.VirtualSize);
        printf("    RawOffset      : 0x%08X\n", sh->PointerToRawData);
        printf("    RawSize        : 0x%08X\n", sh->SizeOfRawData);
        printf("    Characteristics: 0x%08X ", sh->Characteristics);
        print_section_characteristics(sh->Characteristics);  // �� ���⼭ �ǹ� �ؼ�
        printf("\033[0m\n");
    }
}
// Data Directory �̸� ���� �Լ�
const char* get_directory_name(int index) {
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
// Data ���丮 ���
void print_data_directories(const PE_FILE* pe) {
    if (!pe || !pe->ntHeader32) {
        printf("\033[1;31m[Error] Invalid PE_FILE or NT Header.\033[0m\n");
        return;
    }

    IMAGE_DATA_DIRECTORY* dirs = NULL;
    int dirCount = 0;

    // 32��Ʈ �Ǵ� 64��Ʈ�� ���� Data Directory ���� ����
    WORD magic = pe->ntHeader32->OptionalHeader.Magic;
    if (magic == 0x10B) { // PE32
        dirs = pe->ntHeader32->OptionalHeader.DataDirectory;
        dirCount = pe->ntHeader32->OptionalHeader.NumberOfRvaAndSizes;
    }
    else if (magic == 0x20B && pe->ntHeader64) { // PE32+
        dirs = pe->ntHeader64->OptionalHeader.DataDirectory;
        dirCount = pe->ntHeader64->OptionalHeader.NumberOfRvaAndSizes;
    }
    else {
        printf("\033[1;31m[Error] Unknown OptionalHeader.Magic: 0x%X\033[0m\n", magic);
        return;
    }

    printf("\n\033[1;36m[+] DATA DIRECTORIES\033[0m\n");

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        const char* name = get_directory_name(i);
        DWORD rva = dirs[i].VirtualAddress;
        DWORD size = dirs[i].Size;

        printf("\033[1;35m");
        printf("  [%2d] %-24s ", i, name);

        if (rva == 0 && size == 0) {
            printf("RVA: 0x%08X, Size: 0x%08X  \033[1;31m[Empty]\033[0m\n", rva, size);
        }
        else {
            printf("RVA: 0x%08X, Size: 0x%08X\n", rva, size);
        }
        printf("\033[0m");
    }
}
// Export Table ���
void print_export_table(const PE_FILE* pe) {
    if (!pe || !pe->data || !pe->sectionHeaders) {
        printf("\033[1;31m[Error] Invalid PE_FILE structure.\033[0m\n");
        return;
    }

    IMAGE_DATA_DIRECTORY exportDir;
    if (pe->is64Bit) {
        if (!pe->optionalHeader64) {
            printf("\033[1;31m[Error] 64-bit Optional Header is NULL.\033[0m\n");
            return;
        }
        exportDir = pe->optionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else {
        if (!pe->optionalHeader32) {
            printf("\033[1;31m[Error] 32-bit Optional Header is NULL.\033[0m\n");
            return;
        }
        exportDir = pe->optionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    if (exportDir.VirtualAddress == 0) {
        printf("\033[1;33m[+] Export Table is empty.\033[0m\n");
        return;
    }

    DWORD exportOffset = rva_to_offset(exportDir.VirtualAddress, pe->sectionHeaders, pe->numberOfSections);
    if (exportOffset == 0 || exportOffset >= pe->size) {
        printf("\033[1;31m[Error] Invalid Export Table offset.\033[0m\n");
        return;
    }

    IMAGE_EXPORT_DIRECTORY* expDir = (IMAGE_EXPORT_DIRECTORY*)(pe->data + exportOffset);

    DWORD nameCount = expDir->NumberOfNames;
    DWORD funcCount = expDir->NumberOfFunctions;
    DWORD ordBase = expDir->Base;

    DWORD nameRVA = expDir->AddressOfNames;
    DWORD ordinalRVA = expDir->AddressOfNameOrdinals;
    DWORD funcRVA = expDir->AddressOfFunctions;

    printf("\n\033[1;36m[+] EXPORT TABLE\033[0m\n");
    printf("\033[1;33m");
    DWORD nameOffset = rva_to_offset(expDir->Name, pe->sectionHeaders, pe->numberOfSections);
    const char* dllName = (nameOffset && nameOffset < pe->size) ? (char*)(pe->data + nameOffset) : "(Unknown)";
    printf("  DLL Name           : %s\n", dllName);
    printf("  Ordinal Base       : %u\n", ordBase);
    printf("  Number of Names    : %u\n", nameCount);
    printf("  Number of Functions: %u\n", funcCount);
    printf("\033[0m");

    DWORD nameArrayOffset = rva_to_offset(nameRVA, pe->sectionHeaders, pe->numberOfSections);
    DWORD ordinalArrayOffset = rva_to_offset(ordinalRVA, pe->sectionHeaders, pe->numberOfSections);
    DWORD funcArrayOffset = rva_to_offset(funcRVA, pe->sectionHeaders, pe->numberOfSections);

    if (!nameArrayOffset || !ordinalArrayOffset || !funcArrayOffset) {
        printf("\033[1;31m[Error] Failed to locate export address arrays.\033[0m\n");
        return;
    }

    printf("\n\033[1;35m  %-6s %-8s %-10s %s\033[0m\n", "Index", "Ordinal", "FuncRVA", "Name");
    printf("  --------------------------------------------------------\n");

    for (DWORD i = 0; i < nameCount; i++) {
        DWORD ordinal = *(WORD*)(pe->data + ordinalArrayOffset + i * sizeof(WORD)) + ordBase;
        DWORD funcRVA_i = *(DWORD*)(pe->data + funcArrayOffset + (ordinal - ordBase) * sizeof(DWORD));
        DWORD nameStrRVA = *(DWORD*)(pe->data + nameArrayOffset + i * sizeof(DWORD));
        DWORD nameStrOffset = rva_to_offset(nameStrRVA, pe->sectionHeaders, pe->numberOfSections);

        const char* funcName = (nameStrOffset && nameStrOffset < pe->size) ? (const char*)(pe->data + nameStrOffset) : "(Invalid)";

        printf("\033[1;33m  %-6u %-8u 0x%08X %s\033[0m\n", i, ordinal, funcRVA_i, funcName);
    }
}
// Import Table ���
void print_import_table(const PE_FILE* pe);
// --------------------- ��ƿ��Ƽ ---------------------
// RVA �� ������ ��ȯ
DWORD rva_to_offset(DWORD rva, IMAGE_SECTION_HEADER* sections, int nSections) {
    if (!sections || nSections <= 0) return 0;

    for (int i = 0; i < nSections; i++) {
        DWORD va = sections[i].VirtualAddress;
        DWORD vlen = sections[i].Misc.VirtualSize;
        DWORD raw = sections[i].PointerToRawData;
        DWORD rlen = sections[i].SizeOfRawData;

        DWORD size = (vlen > rlen) ? vlen : rlen;

        if (rva >= va && rva < va + size) {
            return raw + (rva - va);
        }
    }
    return 0;
}
double calculate_entropy(const BYTE* data, DWORD size);                            // ��Ʈ���� ���

// --------------------- PE Ÿ�� �Ǻ� ---------------------
int detect_pe_type(const char* filepath, char* out_ext, size_t ext_bufsize) {
    FILE* fp = NULL;
    if (fopen_s(&fp, filepath, "rb") != 0 || fp == NULL) {
        printf("\033[1;31m[Error] Cannot open file for PE type detection: %s\033[0m\n", filepath);
        return 0;
    }

    // Step 1: MZ Signature Ȯ��
    BYTE mz[2] = { 0 };
    if (fread(mz, 1, 2, fp) != 2 || mz[0] != 'M' || mz[1] != 'Z') {
        printf("\033[1;31m[Error] Not a valid PE file (missing MZ header).\033[0m\n");
        fclose(fp);
        return 0;
    }

    // Step 2: e_lfanew ������ �б�
    DWORD pe_offset = 0;
    fseek(fp, 0x3C, SEEK_SET);
    if (fread(&pe_offset, sizeof(DWORD), 1, fp) != 1) {
        printf("\033[1;31m[Error] Failed to read PE header offset.\033[0m\n");
        fclose(fp);
        return 0;
    }

    // Step 3: PE Signature Ȯ��
    fseek(fp, pe_offset, SEEK_SET);
    BYTE pe_sig[4] = { 0 };
    if (fread(pe_sig, 1, 4, fp) != 4 || pe_sig[0] != 'P' || pe_sig[1] != 'E' || pe_sig[2] != 0 || pe_sig[3] != 0) {
        printf("\033[1;31m[Error] Not a valid PE file (missing PE signature).\033[0m\n");
        fclose(fp);
        return 0;
    }

    // Step 4: IMAGE_FILE_HEADER �б� (20����Ʈ)
    IMAGE_FILE_HEADER fileHeader;
    if (fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, fp) != 1) {
        printf("\033[1;31m[Error] Failed to read IMAGE_FILE_HEADER.\033[0m\n");
        fclose(fp);
        return 0;
    }

    // Step 5: Characteristics �ʵ� ��� Ÿ�� �Ǻ�
    const char* type = "unknown";
    if (fileHeader.Characteristics & IMAGE_FILE_DLL) {
        type = "dll";
    }
    else if (fileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        type = "exe";
    }
    else if (fileHeader.Characteristics & 0x1000) { // ����̹�(SYS)�� ����� ��Ŀ
        type = "sys";
    }

    if (out_ext && ext_bufsize > 0) {
        strcpy_s(out_ext, ext_bufsize, type);
    }

    fclose(fp);
    return 1;
}
// --------------------- ���ڵ� ---------------------
void set_console_encoding() {
    SetConsoleOutputCP(CP_UTF8);  // ��� ���ڵ��� UTF-8�� ����
    SetConsoleCP(CP_UTF8);        // �Է� ���ڵ��� UTF-8�� ����
}

#endif // PE_PARSER_H