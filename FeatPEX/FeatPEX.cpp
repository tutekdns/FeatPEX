#include <stdio.h>    // 파일 입출력 함수: fopen, fread, fgets, fprintf 등
#include <iostream>   // 표준 입출력 (cin, cout)
#include <string>     // 문자열 처리
#include <sstream>    // 문자열 스트림
#include <iomanip>    // 입출력 포맷 조정
#include <stdlib.h>   // 동적 메모리 할당, exit 등
#include <string.h>   // 문자열 처리 함수: strcpy, strcmp, strtok 등
#include <Windows.h>  // Windows API 함수: fopen_s, fseek 등
#include <winnt.h>    // PE 파일 구조체 정의
#include <conio.h>  // sleep 함수 사용을 위한 헤더 (POSIX 표준)
#include <stdlib.h>

int check_retry_or_end();                                                    // 재시도 또는 종료 확인 함수
int detect_pe_type(const char* filepath, char* out_ext, size_t ext_bufsize); // PE 파일 타입 판별 함수
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
// PE 파일 구조 출력 함수
void print_pe_structure(const char* filepath) {
    FILE* fp = NULL;
    if (fopen_s(&fp, filepath, "rb") != 0 || fp == NULL) {
        printf("[Error] Cannot open file for PE parsing.\n");
        return;
    }

    // 1. DOS_HEADER
    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, fp);
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid PE file (missing MZ header).\n");
        fclose(fp);
        return;
    }
    printf("\n\033[1;36m[DOS_HEADER]\033[0m\n");
    Sleep(1);
    printf("e_magic: 0x%04X\n", dosHeader.e_magic);
    Sleep(1);
    printf("e_cblp: 0x%04X\n", dosHeader.e_cblp);
    Sleep(1);
    printf("e_cp: 0x%04X\n", dosHeader.e_cp);
    Sleep(1);
    printf("e_crlc: 0x%04X\n", dosHeader.e_crlc);
    Sleep(1);
    printf("e_cparhdr: 0x%04X\n", dosHeader.e_cparhdr);
    Sleep(1);
    printf("e_minalloc: 0x%04X\n", dosHeader.e_minalloc);
    Sleep(1);
    printf("e_maxalloc: 0x%04X\n", dosHeader.e_maxalloc);
    Sleep(1);
    printf("e_ss: 0x%04X\n", dosHeader.e_ss);
    Sleep(1);
    printf("e_sp: 0x%04X\n", dosHeader.e_sp);
    Sleep(1);
    printf("e_csum: 0x%04X\n", dosHeader.e_csum);
    Sleep(1);
    printf("e_ip: 0x%04X\n", dosHeader.e_ip);
    Sleep(1);
    printf("e_cs: 0x%04X\n", dosHeader.e_cs);
    Sleep(1);
    printf("e_lfarlc: 0x%04X\n", dosHeader.e_lfarlc);
    Sleep(1);
    printf("e_ovno: 0x%04X\n", dosHeader.e_ovno);
    Sleep(1);
    for (int i = 0; i < 4; i++) {
        printf("e_res[%d]: 0x%04X\n", i, dosHeader.e_res[i]);
        Sleep(1);
    }
    printf("e_oemid: 0x%04X\n", dosHeader.e_oemid);
    Sleep(1);
    printf("e_oeminfo: 0x%04X\n", dosHeader.e_oeminfo);
    Sleep(1);
    for (int i = 0; i < 10; i++) {
        printf("e_res2[%d]: 0x%04X\n", i, dosHeader.e_res2[i]);
        Sleep(1);
    }
    printf("e_lfanew: 0x%08X\n", dosHeader.e_lfanew);
    Sleep(1);

    // 2. DOS_STUB
    long stub_size = dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
    if (stub_size > 0) {
        unsigned char* dos_stub = (unsigned char*)malloc(stub_size);
        fread(dos_stub, 1, stub_size, fp);
        printf("\n\033[1;36m[DOS_STUB]\033[0m\n");
        Sleep(1);
        printf("Size: %ld bytes\n", stub_size);
        Sleep(1);
        printf("First 16 bytes: ");
        Sleep(1);
        for (int i = 0; i < 16 && i < stub_size; i++) {
            printf("%02X ", dos_stub[i]);
            Sleep(1);
        }
        printf("\n");
        free(dos_stub);
    }

    // 3. RICH_HEADER (존재 여부 및 오프셋만)
    fseek(fp, sizeof(IMAGE_DOS_HEADER), SEEK_SET);
    int rich_offset = -1;
    unsigned char buf[4];
    for (long i = sizeof(IMAGE_DOS_HEADER); i < dosHeader.e_lfanew - 4; i++) {
        fread(buf, 1, 4, fp);
        if (memcmp(buf, "Rich", 4) == 0) {
            rich_offset = (int)i;
            break;
        }
        fseek(fp, i + 1, SEEK_SET);
    }
    if (rich_offset != -1) {
        printf("\n\033[1;36m[RICH_HEADER]\033[0m\n");
        Sleep(1);
        printf("Found at offset: 0x%X\n", rich_offset);
        Sleep(1);
    }
    else {
        printf("\n\033[1;36m[RICH_HEADER]\033[0m\n");
        Sleep(1);
        printf("Not found.\n");
        Sleep(1);
    }

    // 4. NT_HEADER
    fseek(fp, dosHeader.e_lfanew, SEEK_SET);
    DWORD pe_sig = 0;
    fread(&pe_sig, sizeof(DWORD), 1, fp);
    if (pe_sig != IMAGE_NT_SIGNATURE) {
        printf("Not a valid PE file (missing PE signature).\n");
        Sleep(1);
        fclose(fp);
        return;
    }
    printf("\n\033[1;36m[NT_HEADER]\033[0m\n");
    Sleep(1);
    printf("PE Signature: 0x%08X ('PE\\0\\0')\n", pe_sig);
    Sleep(1);

    // 5. IMAGE_FILE_HEADER
    IMAGE_FILE_HEADER fileHeader;
    fread(&fileHeader, sizeof(IMAGE_FILE_HEADER), 1, fp);
    printf("\n\033[1;36m[IMAGE_FILE_HEADER]\033[0m\n");
    Sleep(1);
    printf("Machine: 0x%04X\n", fileHeader.Machine);
    Sleep(1);
    printf("NumberOfSections: %d\n", fileHeader.NumberOfSections);
    Sleep(1);
    printf("TimeDateStamp: 0x%08X\n", fileHeader.TimeDateStamp);
    Sleep(1);
    printf("PointerToSymbolTable: 0x%08X\n", fileHeader.PointerToSymbolTable);
    Sleep(1);
    printf("NumberOfSymbols: %u\n", fileHeader.NumberOfSymbols);
    Sleep(1);
    printf("SizeOfOptionalHeader: 0x%04X\n", fileHeader.SizeOfOptionalHeader);
    Sleep(1);
    printf("Characteristics: 0x%04X\n", fileHeader.Characteristics);
    Sleep(1);

    // 6. IMAGE_OPTIONAL_HEADER
    IMAGE_OPTIONAL_HEADER32 optionalHeader;
    fread(&optionalHeader, sizeof(IMAGE_OPTIONAL_HEADER32), 1, fp);
    printf("\n\033[1;36m[IMAGE_OPTIONAL_HEADER32]\033[0m\n");
    Sleep(1);
    printf("Magic: 0x%04X\n", optionalHeader.Magic);
    Sleep(1);
    printf("MajorLinkerVersion: %u\n", optionalHeader.MajorLinkerVersion);
    Sleep(1);
    printf("MinorLinkerVersion: %u\n", optionalHeader.MinorLinkerVersion);
    Sleep(1);
    printf("SizeOfCode: 0x%08X\n", optionalHeader.SizeOfCode);
    Sleep(1);
    printf("SizeOfInitializedData: 0x%08X\n", optionalHeader.SizeOfInitializedData);
    Sleep(1);
    printf("SizeOfUninitializedData: 0x%08X\n", optionalHeader.SizeOfUninitializedData);
    Sleep(1);
    printf("AddressOfEntryPoint: 0x%08X\n", optionalHeader.AddressOfEntryPoint);
    Sleep(1);
    printf("BaseOfCode: 0x%08X\n", optionalHeader.BaseOfCode);
    Sleep(1);
    printf("BaseOfData: 0x%08X\n", optionalHeader.BaseOfData);
    Sleep(1);
    printf("ImageBase: 0x%08X\n", optionalHeader.ImageBase);
    Sleep(1);
    printf("SectionAlignment: 0x%08X\n", optionalHeader.SectionAlignment);
    Sleep(1);
    printf("FileAlignment: 0x%08X\n", optionalHeader.FileAlignment);
    Sleep(1);
    printf("MajorOperatingSystemVersion: %u\n", optionalHeader.MajorOperatingSystemVersion);
    Sleep(1);
    printf("MinorOperatingSystemVersion: %u\n", optionalHeader.MinorOperatingSystemVersion);
    Sleep(1);
    printf("MajorImageVersion: %u\n", optionalHeader.MajorImageVersion);
    Sleep(1);
    printf("MinorImageVersion: %u\n", optionalHeader.MinorImageVersion);
    Sleep(1);
    printf("MajorSubsystemVersion: %u\n", optionalHeader.MajorSubsystemVersion);
    Sleep(1);
    printf("MinorSubsystemVersion: %u\n", optionalHeader.MinorSubsystemVersion);
    Sleep(1);
    printf("Win32VersionValue: 0x%08X\n", optionalHeader.Win32VersionValue);
    Sleep(1);
    printf("SizeOfImage: 0x%08X\n", optionalHeader.SizeOfImage);
    Sleep(1);
    printf("SizeOfHeaders: 0x%08X\n", optionalHeader.SizeOfHeaders);
    Sleep(1);
    printf("CheckSum: 0x%08X\n", optionalHeader.CheckSum);
    Sleep(1);
    printf("Subsystem: 0x%04X\n", optionalHeader.Subsystem);
    Sleep(1);
    printf("DllCharacteristics: 0x%04X\n", optionalHeader.DllCharacteristics);
    Sleep(1);
    printf("SizeOfStackReserve: 0x%08X\n", optionalHeader.SizeOfStackReserve);
    Sleep(1);
    printf("SizeOfStackCommit: 0x%08X\n", optionalHeader.SizeOfStackCommit);
    Sleep(1);
    printf("SizeOfHeapReserve: 0x%08X\n", optionalHeader.SizeOfHeapReserve);
    Sleep(1);
    printf("SizeOfHeapCommit: 0x%08X\n", optionalHeader.SizeOfHeapCommit);
    Sleep(1);
    printf("LoaderFlags: 0x%08X\n", optionalHeader.LoaderFlags);
    Sleep(1);
    printf("NumberOfRvaAndSizes: %u\n", optionalHeader.NumberOfRvaAndSizes);
    Sleep(1);

    // DataDirectory 출력 (일부만)
    for (int i = 0; i < optionalHeader.NumberOfRvaAndSizes && i < 16; i++) {
        printf("DataDirectory[%d]: RVA=0x%08X, Size=0x%08X\n",i, optionalHeader.DataDirectory[i].VirtualAddress, optionalHeader.DataDirectory[i].Size);
        Sleep(1);
    }

    // 7. SECTION_HEADER
    printf("\n\033[1;36m[SECTION_HEADER]\033[0m\n");
    for (int i = 0; i < fileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader;
        fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, fp);
        printf("[%d] Name: %.8s\n", i + 1, sectionHeader.Name);
        Sleep(1);
        printf("    VirtualSize: 0x%08X\n", sectionHeader.Misc.VirtualSize);
        Sleep(1);
        printf("    VirtualAddress: 0x%08X\n", sectionHeader.VirtualAddress);
        Sleep(1);
        printf("    SizeOfRawData: 0x%08X\n", sectionHeader.SizeOfRawData);
        Sleep(1);
        printf("    PointerToRawData: 0x%08X\n", sectionHeader.PointerToRawData);
        Sleep(1);
        printf("    PointerToRelocations: 0x%08X\n", sectionHeader.PointerToRelocations);
        Sleep(1);
        printf("    PointerToLinenumbers: 0x%08X\n", sectionHeader.PointerToLinenumbers);
        Sleep(1);
        printf("    NumberOfRelocations: %u\n", sectionHeader.NumberOfRelocations);
        Sleep(1);
        printf("    NumberOfLinenumbers: %u\n", sectionHeader.NumberOfLinenumbers);
        Sleep(1);
        printf("    Characteristics: 0x%08X\n", sectionHeader.Characteristics);
        Sleep(1);
    }

    fclose(fp);
}