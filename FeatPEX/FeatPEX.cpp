#include <stdio.h>    // 파일 입출력 함수: fopen, fread, fgets, fprintf 등
#include <iostream>   // 표준 입출력 (cin, cout)
#include <string>     // 문자열 처리
#include <sstream>    // 문자열 스트림
#include <iomanip>    // 입출력 포맷 조정
#include <stdlib.h>   // 동적 메모리 할당, exit 등
#include <string.h>   // 문자열 처리 함수: strcpy, strcmp, strtok 등
#include <Windows.h>  // Windows API 함수: fopen_s, fseek 등
#include <winnt.h>    // PE 파일 구조체 정의
#include <conio.h>    // sleep 함수 사용을 위한 헤더 (POSIX 표준)

int check_retry_or_end();                                                    // 재시도 또는 종료 확인 함수
int detect_pe_type(const char* filepath, char* out_ext, size_t ext_bufsize); // PE 파일 타입 판별 함수
static DWORD rva_to_offset(DWORD rva, IMAGE_SECTION_HEADER* sections, int nSections); // RVA를 파일 오프셋으로 변환하는 함수
void print_pe_structure(const char* filepath); 				                 // PE 파일 구조 출력 함수

#define MAX_PATH 260         // Windows에서 경로의 최대 길이
#define PE_SIGNATURE_PATH 32 //확장자 최대 길이
int main() {
    
    const char* art[] = {
        "  ______         _   _____  ________   __",
        " |  ____|       | | |  __ \\|  ____\\ \\ / /",
        " | |__ ___  __ _| |_| |__) | |__   \\ V / ",
        " |  __/ _ \\/ _` | __|  ___/|  __|   > <  ",
        " | | |  __/ (_| | |_| |    | |____ / . \\ ",
        " |_|  \\___|\\__,_|\\__|_|    |______/_/ \\_\\"
    };

    // ANSI 색상 코드 (무지개 순서)
    int colors[] = { 31, 33, 93, 32, 36, 34, 35 };
    int color_count = sizeof(colors) / sizeof(colors[0]);

    // 줄 수
    int line_count = sizeof(art) / sizeof(art[0]);

    // 출력
    for (int i = 0; i < line_count; i++) {
        int color_index = 0;
        for (int j = 0; art[i][j] != '\0'; j++) {
            char c = art[i][j];
            if (c != ' ') {
                int color = colors[color_index % color_count];
                printf("\033[1;%dm%c\033[0m", color, c); // 색상 입히고 출력
                color_index++;
            }
            else {
                printf(" "); // 공백은 그대로 출력
            }
        }
        printf("\n");
    }

    printf("\033[1;32m\tWelcome to FeatPEX malware analyzer tool!\n\tThis tool is designed to analyze and extract Feature information from PE files.\033[0m\n");
	printf("\033[1;33m\tPlease use the command 'FeatPEX -h' for help.\033[0m\n\n");
    printf("\033[1;34m"); // 파란색으로 입력 프롬프트

    char input[260]; // 경로 최대 길이(Windows MAX_PATH 기준)로 버퍼 선언

    while (1) {
        printf("Please enter the path of the PE file you want to analyze:\n");
        printf("Example: C:\\path\\to\\your\\file.exe\n");

        printf("\033[1;34m");
        if (fgets(input, sizeof(input), stdin) != NULL) {
            size_t len = strlen(input);
            if (len > 0 && input[len - 1] == '\n') {
                input[len - 1] = '\0';
            }
        }
        printf("\033[0m");

        FILE* fp = NULL;
        if (fopen_s(&fp, input, "rb") != 0 || fp == NULL) {
            printf("\033[1;31m[Error] The file does not exist or cannot be opened: %s\033[0m\n", input);

            // 오류 발생 시 사용자 선택 함수 호출
            if (check_retry_or_end()) {
                continue; // 다시 입력
            }
            else {
                break; // 종료
            }
        }
        else {
            fclose(fp);
            printf("\033[1;32m[OK] File found: %s\033[0m\n", input);
            break; // 성공 시 루프 탈출
        }
    }

    // 정상적으로 열렸을 때 분석 로직 진행
    printf("You entered: %s\n", input);
	printf("\033[1;36mStarting analysis...\033[0m\n");

    // PE 파일 타입 판별 및 확장자 변수에 저장
    char detected_ext[PE_SIGNATURE_PATH] = { 0 }; // 확장자 저장 변수

    FILE* fp = NULL;
    detect_pe_type(input, detected_ext, sizeof(detected_ext));

    print_pe_structure(input);


    return 0;
}

// 파일 열기 실패 시 재시도 여부 확인 함수
int check_retry_or_end() {
    char choice[10];
    while (1) {
        printf("\033[1;33mWould you like to try again? (Y/N): \033[0m");
        if (fgets(choice, sizeof(choice), stdin) != NULL) {
            size_t len = strlen(choice);
            if (len > 0 && choice[len - 1] == '\n') {
                choice[len - 1] = '\0';
            }

            if (choice[0] == 'Y' || choice[0] == 'y') {
                return 1; // 재시도
            }
            else if (choice[0] == 'N' || choice[0] == 'n') {
                printf("\033[1;31mProgram terminated by user.\033[0m\n");
                return 0; // 종료
            }
        }

        printf("\033[1;31mInvalid input. Please enter Y or N.\033[0m\n");
    }
}
// PE 파일 타입 판별 함수
int detect_pe_type(const char* filepath, char* out_ext, size_t ext_bufsize) {
    FILE* fp = NULL;
    if (fopen_s(&fp, filepath, "rb") != 0 || fp == NULL) {
        printf("[Error] Cannot open file for PE type detection.\n");
        return 0;
    }

    unsigned char mz[2];
    fread(mz, 1, 2, fp);
    if (mz[0] != 'M' || mz[1] != 'Z') {
        printf("Not a valid PE file (missing MZ header).\n");
        fclose(fp);
        return 0;
    }

    // e_lfanew 위치로 이동
    fseek(fp, 0x3C, SEEK_SET);
    unsigned int pe_offset = 0;
    fread(&pe_offset, 4, 1, fp);

    // PE Signature 확인
    fseek(fp, pe_offset, SEEK_SET);
    unsigned char pe_sig[4];
    fread(pe_sig, 1, 4, fp);
    if (pe_sig[0] != 'P' || pe_sig[1] != 'E' || pe_sig[2] != 0 || pe_sig[3] != 0) {
        printf("Not a valid PE file (missing PE signature).\n");
        fclose(fp);
        return 0;
    }

    // IMAGE_FILE_HEADER 읽기
    unsigned short machine;
    unsigned short num_sections;
    unsigned int time_date_stamp;
    unsigned int pointer_to_symbol_table;
    unsigned int number_of_symbols;
    unsigned short size_of_optional_header;
    unsigned short characteristics;

    fread(&machine, 2, 1, fp);
    fread(&num_sections, 2, 1, fp);
    fread(&time_date_stamp, 4, 1, fp);
    fread(&pointer_to_symbol_table, 4, 1, fp);
    fread(&number_of_symbols, 4, 1, fp);
    fread(&size_of_optional_header, 2, 1, fp);
    fread(&characteristics, 2, 1, fp);

    // characteristics로 타입 판별
    if (characteristics & 0x2000) { // DLL
        strcpy_s(out_ext, ext_bufsize, "dll");
    }
    else if (characteristics & 0x0002) { // EXE
        strcpy_s(out_ext, ext_bufsize, "exe");
    }
    else if (characteristics & 0x1000) { // SYS
        strcpy_s(out_ext, ext_bufsize, "sys");
    }
    else {
        strcpy_s(out_ext, ext_bufsize, "unknown");
    }

    fclose(fp);
    return 1;
}
// RVA를 파일 오프셋으로 변환하는 함수
static DWORD rva_to_offset(DWORD rva, IMAGE_SECTION_HEADER* sections, int nSections) {
    if (rva == 0) return 0;

    for (int i = 0; i < nSections; i++) {
        DWORD secVA = sections[i].VirtualAddress;
        DWORD secSize = sections[i].Misc.VirtualSize;
        DWORD secRawSize = sections[i].SizeOfRawData;
        DWORD secOffset = sections[i].PointerToRawData;

        // 실제 파일에 존재하는 섹션 범위 내에서만 매핑
        DWORD maxSize = (secSize > secRawSize) ? secRawSize : secSize;

        if (rva >= secVA && rva < secVA + maxSize) {
            return secOffset + (rva - secVA);
        }
    }

    return 0;  // 매핑 실패
}
// DLL 이름을 안전하게 읽는 함수 (경계 체크 포함)
static BOOL safe_read_ascii(FILE* fp, DWORD offset, char* outBuf, size_t maxLen, DWORD fileSize) {
    if (offset == 0 || offset >= fileSize) return FALSE;
    if (fseek(fp, offset, SEEK_SET) != 0) return FALSE;

    size_t i = 0;
    int ch;
    while (i < maxLen - 1 && (ch = fgetc(fp)) != EOF && ch != '\0') {
        if (offset + i >= fileSize) break;  // 오버런 방지
        outBuf[i++] = (char)ch;
    }
    outBuf[i] = '\0';
    return TRUE;
}
// DLL 이름을 읽는 래퍼 함수 (rva -> offset -> 문자열)
void read_dll_name(FILE* fp, DWORD rva, IMAGE_SECTION_HEADER* sections, int nSections, char* outBuf, size_t maxLen, DWORD fileSize) {
    DWORD nameOffset = rva_to_offset(rva, sections, nSections);
    if (!safe_read_ascii(fp, nameOffset, outBuf, maxLen, fileSize)) {
        strncpy_s(outBuf, maxLen, "(invalid)", _TRUNCATE);
    }
}
// PE 구조체 출력 함수
void print_pe_structure(const char* filepath) {
    FILE* fp = NULL;
    if (fopen_s(&fp, filepath, "rb") != 0 || fp == NULL) {
        printf("[Error] Cannot open file for PE parsing.\n");
        return;
    }

    // 1. DOS_HEADER
    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, fp);
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {  // "MZ"
        printf("Not a valid PE file (missing MZ header).\n");
        fclose(fp);
        return;
    }
    printf("\n\033[1;36m[DOS_HEADER]\033[0m\n");
    Sleep(1);
    printf("e_magic: 0x%04X\n", dosHeader.e_magic); Sleep(1);
    printf("e_cblp: 0x%04X\n", dosHeader.e_cblp); Sleep(1);
    printf("e_cp: 0x%04X\n", dosHeader.e_cp); Sleep(1);
    printf("e_crlc: 0x%04X\n", dosHeader.e_crlc); Sleep(1);
    printf("e_cparhdr: 0x%04X\n", dosHeader.e_cparhdr); Sleep(1);
    printf("e_minalloc: 0x%04X\n", dosHeader.e_minalloc); Sleep(1);
    printf("e_maxalloc: 0x%04X\n", dosHeader.e_maxalloc); Sleep(1);
    printf("e_ss: 0x%04X\n", dosHeader.e_ss); Sleep(1);
    printf("e_sp: 0x%04X\n", dosHeader.e_sp); Sleep(1);
    printf("e_csum: 0x%04X\n", dosHeader.e_csum); Sleep(1);
    printf("e_ip: 0x%04X\n", dosHeader.e_ip); Sleep(1);
    printf("e_cs: 0x%04X\n", dosHeader.e_cs); Sleep(1);
    printf("e_lfarlc: 0x%04X\n", dosHeader.e_lfarlc); Sleep(1);
    printf("e_ovno: 0x%04X\n", dosHeader.e_ovno); Sleep(1);
    for (int i = 0; i < 4; i++) {
        printf("e_res[%d]: 0x%04X\n", i, dosHeader.e_res[i]); Sleep(1);
    }
    printf("e_oemid: 0x%04X\n", dosHeader.e_oemid); Sleep(1);
    printf("e_oeminfo: 0x%04X\n", dosHeader.e_oeminfo); Sleep(1);
    for (int i = 0; i < 10; i++) {
        printf("e_res2[%d]: 0x%04X\n", i, dosHeader.e_res2[i]); Sleep(1);
    }
    printf("e_lfanew: 0x%08X\n", dosHeader.e_lfanew); Sleep(1);

    // 2. DOS_STUB
    long stub_size = dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
    unsigned char* dos_stub = NULL;
    if (stub_size > 0) {
        dos_stub = (unsigned char*)malloc(stub_size);
        fread(dos_stub, 1, stub_size, fp);
        printf("\n\033[1;36m[DOS_STUB]\033[0m\n");
        Sleep(1);
        printf("Size: %ld bytes\n", stub_size); Sleep(1);
        printf("Bytes:"); Sleep(1);
        // 16바이트씩 줄바꿈하며 모든 바이트 출력
        for (long i = 0; i < stub_size; i++) {
            if (i % 16 == 0) {
                printf("\n"); Sleep(1);
            }
            printf("%02X ", dos_stub[i]);
            Sleep(1);
        }
        printf("\n");
    }

    // 3. RICH_HEADER
    int rich_offset = -1;
    DWORD rich_key = 0;
    if (stub_size > 0 && dos_stub != NULL) {
        for (long i = 0; i < stub_size - 3; i++) {
            if (dos_stub[i] == 'R' && dos_stub[i + 1] == 'i' && dos_stub[i + 2] == 'c' && dos_stub[i + 3] == 'h') {
                // 'Rich' 시그니처 찾음
                rich_offset = (int)(i + sizeof(IMAGE_DOS_HEADER));  // 파일 기준 오프셋 (DOS_HEADER 크기 더함)
                if (i + 7 < stub_size) {
                    // 'Rich' 바로 뒤 4바이트는 XOR 키
                    rich_key = *(DWORD*)(dos_stub + i + 4);
                }
                break;
            }
        }
    }
    printf("\n\033[1;36m[RICH_HEADER]\033[0m\n");
    Sleep(1);
    if (rich_offset != -1) {
        printf("Found at offset: 0x%X\n", rich_offset); Sleep(1);
        printf("XOR Key: 0x%08X\n", rich_key); Sleep(1);
        // Rich 헤더 디코딩
        if (rich_key != 0 && dos_stub != NULL) {
            // 'Rich' 이전에 'DanS' 블록 찾기 (XOR되어 있음)
            long startIndex = -1;
            for (long i = 0; i < stub_size - 11; i++) {
                if (*(DWORD*)(dos_stub + i) == rich_key &&           // 3개의 0 패딩이 XOR된 값은 키 값과 동일
                    *(DWORD*)(dos_stub + i + 4) == rich_key &&
                    *(DWORD*)(dos_stub + i + 8) == rich_key) {
                    startIndex = i - 4;  // 그 앞 4바이트가 'DanS' XOR 결과
                    break;
                }
            }
            if (startIndex < 0) startIndex = 0;
            if (startIndex >= 0 && startIndex < stub_size) {
                long rich_data_size = (rich_offset - sizeof(IMAGE_DOS_HEADER)) - startIndex;
                if (rich_data_size > 0 && startIndex + rich_data_size <= stub_size) {
                    unsigned char* rich_data = (unsigned char*)malloc(rich_data_size);
                    memcpy(rich_data, dos_stub + startIndex, rich_data_size);
                    // XOR 복호화
                    for (long j = 0; j < rich_data_size; j += 4) {
                        if (j + 4 <= rich_data_size) {
                            *(DWORD*)(rich_data + j) ^= rich_key;
                        }
                    }
                    // 복호화된 Rich 헤더 구조 해석
                    if (rich_data_size >= 16 && memcmp(rich_data, "DanS", 4) == 0) {
                        printf("DanS signature: 0x%08X\n", *(DWORD*)rich_data); Sleep(1);
                        int entryOffset = 16;  // 'DanS'+패딩 16바이트 이후부터 엔트리 시작
                        if (rich_data_size > entryOffset) {
                            printf("Rich Entries:\n"); Sleep(1);
                        }
                        while (entryOffset + 7 < rich_data_size) {
                            DWORD compID = *(DWORD*)(rich_data + entryOffset);
                            DWORD count = *(DWORD*)(rich_data + entryOffset + 4);
                            if (compID == 0 && count == 0) break;  // 종료
                            WORD prodId = HIWORD(compID);  // 상위 WORD = Product ID
                            WORD build = LOWORD(compID);   // 하위 WORD = Build ID
                            printf("    • Tool/Product ID: 0x%04X, Build: 0x%04X, Count: %u\n",
                                prodId, build, count);
                            Sleep(1);
                            entryOffset += 8;
                        }
                        if (entryOffset == 16) {
                            printf("    • (No Rich entries)\n"); Sleep(1);
                        }
                    }
                    else {
                        printf("(Rich header decode failed or not present.)\n"); Sleep(1);
                    }
                    free(rich_data);
                }
            }
        }
    }
    else {
        printf("Not found.\n"); Sleep(1);
    }

    // 4. NT_HEADER
    fseek(fp, dosHeader.e_lfanew, SEEK_SET);
    DWORD pe_sig = 0;
    fread(&pe_sig, sizeof(DWORD), 1, fp);
    if (pe_sig != IMAGE_NT_SIGNATURE) {  // "PE\0\0"
        printf("Not a valid PE file (missing PE signature).\n");
        Sleep(1);
        fclose(fp);
        return;
    }
    printf("\n\033[1;36m[NT_HEADER]\033[0m\n");
    Sleep(1);
    printf("PE Signature: 0x%08X ('PE\\0\\0')\n", pe_sig); Sleep(1);

    // 5. IMAGE_FILE_HEADER
    IMAGE_FILE_HEADER fileHeader;
    fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, fp);
    printf("\n\033[1;36m[IMAGE_FILE_HEADER]\033[0m\n");
    Sleep(1);
    printf("Machine: 0x%04X\n", fileHeader.Machine); Sleep(1);
    printf("NumberOfSections: %d\n", fileHeader.NumberOfSections); Sleep(1);
    printf("TimeDateStamp: 0x%08X\n", fileHeader.TimeDateStamp); Sleep(1);
    printf("PointerToSymbolTable: 0x%08X\n", fileHeader.PointerToSymbolTable); Sleep(1);
    printf("NumberOfSymbols: %u\n", fileHeader.NumberOfSymbols); Sleep(1);
    printf("SizeOfOptionalHeader: 0x%04X\n", fileHeader.SizeOfOptionalHeader); Sleep(1);
    printf("Characteristics: 0x%04X\n", fileHeader.Characteristics); Sleep(1);

    // 6. IMAGE_OPTIONAL_HEADER (32-bit or 64-bit)
    size_t optHeaderSize = fileHeader.SizeOfOptionalHeader;
    unsigned char* optBuffer = (unsigned char*)malloc(optHeaderSize);
    fread(optBuffer, 1, optHeaderSize, fp);
    WORD optMagic = *(WORD*)optBuffer;
    BOOL isPE64 = (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ? TRUE : FALSE;
    printf("\n\033[1;36m[IMAGE_OPTIONAL_HEADER%s]\033[0m\n", isPE64 ? "64" : "32");
    Sleep(1);
    DWORD numberOfRva = 0;
    if (!isPE64) {
        // 32비트 Optional Header 파싱
        IMAGE_OPTIONAL_HEADER32 optHeader32;
        memset(&optHeader32, 0, sizeof(optHeader32));
        size_t copySize = (optHeaderSize < sizeof(optHeader32)) ? optHeaderSize : sizeof(optHeader32);
        memcpy(&optHeader32, optBuffer, copySize);
        numberOfRva = optHeader32.NumberOfRvaAndSizes;
        printf("Magic: 0x%04X\n", optHeader32.Magic); Sleep(1);
        printf("MajorLinkerVersion: %u\n", optHeader32.MajorLinkerVersion); Sleep(1);
        printf("MinorLinkerVersion: %u\n", optHeader32.MinorLinkerVersion); Sleep(1);
        printf("SizeOfCode: 0x%08X\n", optHeader32.SizeOfCode); Sleep(1);
        printf("SizeOfInitializedData: 0x%08X\n", optHeader32.SizeOfInitializedData); Sleep(1);
        printf("SizeOfUninitializedData: 0x%08X\n", optHeader32.SizeOfUninitializedData); Sleep(1);
        printf("AddressOfEntryPoint: 0x%08X\n", optHeader32.AddressOfEntryPoint); Sleep(1);
        printf("BaseOfCode: 0x%08X\n", optHeader32.BaseOfCode); Sleep(1);
        printf("BaseOfData: 0x%08X\n", optHeader32.BaseOfData); Sleep(1);
        printf("ImageBase: 0x%08X\n", optHeader32.ImageBase); Sleep(1);
        printf("SectionAlignment: 0x%08X\n", optHeader32.SectionAlignment); Sleep(1);
        printf("FileAlignment: 0x%08X\n", optHeader32.FileAlignment); Sleep(1);
        printf("MajorOperatingSystemVersion: %u\n", optHeader32.MajorOperatingSystemVersion); Sleep(1);
        printf("MinorOperatingSystemVersion: %u\n", optHeader32.MinorOperatingSystemVersion); Sleep(1);
        printf("MajorImageVersion: %u\n", optHeader32.MajorImageVersion); Sleep(1);
        printf("MinorImageVersion: %u\n", optHeader32.MinorImageVersion); Sleep(1);
        printf("MajorSubsystemVersion: %u\n", optHeader32.MajorSubsystemVersion); Sleep(1);
        printf("MinorSubsystemVersion: %u\n", optHeader32.MinorSubsystemVersion); Sleep(1);
        printf("Win32VersionValue: 0x%08X\n", optHeader32.Win32VersionValue); Sleep(1);
        printf("SizeOfImage: 0x%08X\n", optHeader32.SizeOfImage); Sleep(1);
        printf("SizeOfHeaders: 0x%08X\n", optHeader32.SizeOfHeaders); Sleep(1);
        printf("CheckSum: 0x%08X\n", optHeader32.CheckSum); Sleep(1);
        printf("Subsystem: 0x%04X\n", optHeader32.Subsystem); Sleep(1);
        printf("DllCharacteristics: 0x%04X\n", optHeader32.DllCharacteristics); Sleep(1);
        printf("SizeOfStackReserve: 0x%08X\n", optHeader32.SizeOfStackReserve); Sleep(1);
        printf("SizeOfStackCommit: 0x%08X\n", optHeader32.SizeOfStackCommit); Sleep(1);
        printf("SizeOfHeapReserve: 0x%08X\n", optHeader32.SizeOfHeapReserve); Sleep(1);
        printf("SizeOfHeapCommit: 0x%08X\n", optHeader32.SizeOfHeapCommit); Sleep(1);
        printf("LoaderFlags: 0x%08X\n", optHeader32.LoaderFlags); Sleep(1);
        printf("NumberOfRvaAndSizes: %u\n", optHeader32.NumberOfRvaAndSizes); Sleep(1);
        // DataDirectory 엔트리 출력 (사용된 개수만큼)
        for (unsigned int i = 0; i < optHeader32.NumberOfRvaAndSizes; i++) {
            if (i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
                printf("DataDirectory[%d]: RVA=0x%08X, Size=0x%08X\n",
                    i,
                    optHeader32.DataDirectory[i].VirtualAddress,
                    optHeader32.DataDirectory[i].Size);
            }
            else {
                // 만약 데이터 디렉터리 개수가 16보다 많다면, 버퍼에서 직접 읽음
                size_t off = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) + i * sizeof(IMAGE_DATA_DIRECTORY);
                if (off + sizeof(IMAGE_DATA_DIRECTORY) <= optHeaderSize) {
                    IMAGE_DATA_DIRECTORY* pDir = (IMAGE_DATA_DIRECTORY*)(optBuffer + off);
                    printf("DataDirectory[%d]: RVA=0x%08X, Size=0x%08X\n",
                        i, pDir->VirtualAddress, pDir->Size);
                }
                else {
                    printf("DataDirectory[%d]: (not available)\n", i);
                }
            }
            Sleep(1);
        }
    }
    else {
        // 64비트 Optional Header 파싱
        IMAGE_OPTIONAL_HEADER64 optHeader64;
        memset(&optHeader64, 0, sizeof(optHeader64));
        size_t copySize = (optHeaderSize < sizeof(optHeader64)) ? optHeaderSize : sizeof(optHeader64);
        memcpy(&optHeader64, optBuffer, copySize);
        numberOfRva = optHeader64.NumberOfRvaAndSizes;
        printf("Magic: 0x%04X\n", optHeader64.Magic); Sleep(1);
        printf("MajorLinkerVersion: %u\n", optHeader64.MajorLinkerVersion); Sleep(1);
        printf("MinorLinkerVersion: %u\n", optHeader64.MinorLinkerVersion); Sleep(1);
        printf("SizeOfCode: 0x%08X\n", optHeader64.SizeOfCode); Sleep(1);
        printf("SizeOfInitializedData: 0x%08X\n", optHeader64.SizeOfInitializedData); Sleep(1);
        printf("SizeOfUninitializedData: 0x%08X\n", optHeader64.SizeOfUninitializedData); Sleep(1);
        printf("AddressOfEntryPoint: 0x%08X\n", optHeader64.AddressOfEntryPoint); Sleep(1);
        printf("BaseOfCode: 0x%08X\n", optHeader64.BaseOfCode); Sleep(1);
        // BaseOfData는 PE32+에 없음
        printf("ImageBase: 0x%016llX\n", optHeader64.ImageBase); Sleep(1);
        printf("SectionAlignment: 0x%08X\n", optHeader64.SectionAlignment); Sleep(1);
        printf("FileAlignment: 0x%08X\n", optHeader64.FileAlignment); Sleep(1);
        printf("MajorOperatingSystemVersion: %u\n", optHeader64.MajorOperatingSystemVersion); Sleep(1);
        printf("MinorOperatingSystemVersion: %u\n", optHeader64.MinorOperatingSystemVersion); Sleep(1);
        printf("MajorImageVersion: %u\n", optHeader64.MajorImageVersion); Sleep(1);
        printf("MinorImageVersion: %u\n", optHeader64.MinorImageVersion); Sleep(1);
        printf("MajorSubsystemVersion: %u\n", optHeader64.MajorSubsystemVersion); Sleep(1);
        printf("MinorSubsystemVersion: %u\n", optHeader64.MinorSubsystemVersion); Sleep(1);
        printf("Win32VersionValue: 0x%08X\n", optHeader64.Win32VersionValue); Sleep(1);
        printf("SizeOfImage: 0x%08X\n", optHeader64.SizeOfImage); Sleep(1);
        printf("SizeOfHeaders: 0x%08X\n", optHeader64.SizeOfHeaders); Sleep(1);
        printf("CheckSum: 0x%08X\n", optHeader64.CheckSum); Sleep(1);
        printf("Subsystem: 0x%04X\n", optHeader64.Subsystem); Sleep(1);
        printf("DllCharacteristics: 0x%04X\n", optHeader64.DllCharacteristics); Sleep(1);
        printf("SizeOfStackReserve: 0x%016llX\n", optHeader64.SizeOfStackReserve); Sleep(1);
        printf("SizeOfStackCommit: 0x%016llX\n", optHeader64.SizeOfStackCommit); Sleep(1);
        printf("SizeOfHeapReserve: 0x%016llX\n", optHeader64.SizeOfHeapReserve); Sleep(1);
        printf("SizeOfHeapCommit: 0x%016llX\n", optHeader64.SizeOfHeapCommit); Sleep(1);
        printf("LoaderFlags: 0x%08X\n", optHeader64.LoaderFlags); Sleep(1);
        printf("NumberOfRvaAndSizes: %u\n", optHeader64.NumberOfRvaAndSizes); Sleep(1);
        for (unsigned int i = 0; i < optHeader64.NumberOfRvaAndSizes; i++) {
            if (i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
                printf("DataDirectory[%d]: RVA=0x%08X, Size=0x%08X\n",
                    i,
                    optHeader64.DataDirectory[i].VirtualAddress,
                    optHeader64.DataDirectory[i].Size);
            }
            else {
                size_t off = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + i * sizeof(IMAGE_DATA_DIRECTORY);
                if (off + sizeof(IMAGE_DATA_DIRECTORY) <= optHeaderSize) {
                    IMAGE_DATA_DIRECTORY* pDir = (IMAGE_DATA_DIRECTORY*)(optBuffer + off);
                    printf("DataDirectory[%d]: RVA=0x%08X, Size=0x%08X\n",
                        i, pDir->VirtualAddress, pDir->Size);
                }
                else {
                    printf("DataDirectory[%d]: (not available)\n", i);
                }
            }
            Sleep(1);
        }
    }

    // 필요한 데이터 디렉터리 주소 확보 (Export, Import 등)
    DWORD exportDirVA = 0, exportDirSize = 0;
    DWORD importDirVA = 0, importDirSize = 0;
    if (numberOfRva > 0) {
        IMAGE_DATA_DIRECTORY* entry0 = (IMAGE_DATA_DIRECTORY*)(optBuffer +
            (isPE64 ? offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)
                : offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory)));
        // Export Directory (index 0)
        exportDirVA = (numberOfRva > 0) ? entry0[0].VirtualAddress : 0;
        exportDirSize = (numberOfRva > 0) ? entry0[0].Size : 0;
        // Import Directory (index 1)
        importDirVA = (numberOfRva > 1) ? entry0[1].VirtualAddress : 0;
        importDirSize = (numberOfRva > 1) ? entry0[1].Size : 0;
        // (Certificate Table 등 추가 정보 필요 시 index 4 등의 entry 사용 가능)
    }
    free(optBuffer);

    // 7. SECTION_HEADER
    long sectionHeaderOffset = dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
    fseek(fp, sectionHeaderOffset, SEEK_SET);
    printf("\n\033[1;36m[SECTION_HEADER]\033[0m\n");
    Sleep(1);
    // 섹션 헤더들을 읽어 저장
    IMAGE_SECTION_HEADER* sections = NULL;
    if (fileHeader.NumberOfSections > 0) {
        sections = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections);
    }
    for (int i = 0; i < fileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader = { 0 };
        if (fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, fp) != 1) {
            printf("\033[1;31m[Error] Failed to read section header %d\033[0m\n", i + 1);
            break;
        }
        if (sections) sections[i] = sectionHeader;
        // 섹션 이름 정리 및 출력
        char secName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
        memcpy(secName, sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME);
        secName[IMAGE_SIZEOF_SHORT_NAME] = '\0';

        // 시각적 확인용: 16진수 섹션 이름 출력
        printf("Raw Section Name Bytes: ");
        for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
            printf("%02X ", sectionHeader.Name[j]);
        }
        printf("\n");

        // 가독성 확보: 비표준 문자 '.' 대체
        for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
            if (secName[j] == '\0') break;
            if (secName[j] < 0x20 || secName[j] > 0x7E) secName[j] = '.';
        }

        // 이름이 비어 있는 경우 대체 문자열 출력
        if (secName[0] == '\0') {
            _snprintf_s(secName, sizeof(secName), _TRUNCATE, "unnamed");
        }

        printf("\033[1;34m[%d] Name: %s\033[0m\n", i + 1, secName);
        printf("    • VirtualSize (code/data size in memory)      : 0x%08X\n", sectionHeader.Misc.VirtualSize);
        printf("    • VirtualAddress (RVA)                         : 0x%08X\n", sectionHeader.VirtualAddress);
        printf("    • SizeOfRawData (actual file size on disk)    : 0x%08X\n", sectionHeader.SizeOfRawData);
        printf("    • PointerToRawData (offset in file)           : 0x%08X\n", sectionHeader.PointerToRawData);
        printf("    • PointerToRelocations                        : 0x%08X\n", sectionHeader.PointerToRelocations);
        printf("    • PointerToLinenumbers                        : 0x%08X\n", sectionHeader.PointerToLinenumbers);
        printf("    • NumberOfRelocations                         : %u\n", sectionHeader.NumberOfRelocations);
        printf("    • NumberOfLinenumbers                         : %u\n", sectionHeader.NumberOfLinenumbers);
        printf("    • Characteristics (flags)                     : 0x%08X\n", sectionHeader.Characteristics);
        printf("--------------------------------------------------------------\n");
        Sleep(10);
    }

    // EXPORT_TABLE (내보낸 함수) 파싱
    if (exportDirVA != 0 && exportDirSize != 0) {
        printf("\n\033[1;36m[EXPORT_TABLE]\033[0m\n");
        Sleep(1);
        DWORD expOffset = rva_to_offset(exportDirVA, sections, fileHeader.NumberOfSections);
        IMAGE_EXPORT_DIRECTORY expDir;
        fseek(fp, expOffset, SEEK_SET);
        fread(&expDir, sizeof(IMAGE_EXPORT_DIRECTORY), 1, fp);

        // 모듈 이름 출력
        char dllNameBuf[256] = { 0 };
        if (expDir.Name != 0) {
            DWORD nameOffset = rva_to_offset(expDir.Name, sections, fileHeader.NumberOfSections);
            if (nameOffset) {
                fseek(fp, nameOffset, SEEK_SET);
                int idx = 0, ch;
                while (idx < 255 && (ch = fgetc(fp)) != EOF && ch != '\0') {
                    dllNameBuf[idx++] = (char)ch;
                }
                dllNameBuf[idx] = '\0';
            }
        }
        printf("\033[1;34mName: %s\033[0m\n", dllNameBuf[0] ? dllNameBuf : "(unknown)");
        Sleep(1);

        // 함수 이름 출력 생략
        printf("    • Exported Functions: (omitted)\n");
        Sleep(1);
    }

    // IMPORT_TABLE (가져오는 함수) 파싱
    if (importDirVA != 0 && importDirSize != 0) {
        printf("\n\033[1;36m[IMPORT_TABLE]\033[0m\n");
        Sleep(1);
        DWORD impOffset = rva_to_offset(importDirVA, sections, fileHeader.NumberOfSections);
        fseek(fp, impOffset, SEEK_SET);
        IMAGE_IMPORT_DESCRIPTOR importDesc;
        int importIndex = 0;

        // 파일 크기 계산
        fseek(fp, 0, SEEK_END);
        DWORD fileSize = ftell(fp);
        rewind(fp);

        // Import Descriptor 배열 순회
        while (1) {
            fseek(fp, impOffset + importIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR), SEEK_SET);
            if (fread(&importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, fp) != 1) break;
            if (importDesc.Name == 0 && importDesc.FirstThunk == 0) break;  // 끝

            importIndex++;

            // DLL 이름 읽기
            char importDllName[256] = { 0 };
            read_dll_name(fp, importDesc.Name, sections, fileHeader.NumberOfSections, importDllName, sizeof(importDllName), fileSize);

            // DLL 이름만 출력
            printf("\033[1;34m[%d] Name: %s\033[0m\n", importIndex, importDllName[0] ? importDllName : "(null)");
            Sleep(1);
        }
    }


    // 메모리 해제 및 파일 닫기
    if (sections) free(sections);
    if (dos_stub) free(dos_stub);
    fclose(fp);
}