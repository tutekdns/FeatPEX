#include <stdio.h>    // 파일 입출력 함수: fopen, fread, fgets, fprintf 등
#include <iostream>   // 표준 입출력 (cin, cout)
#include <string>     // 문자열 처리
#include <sstream>    // 문자열 스트림
#include <iomanip>    // 입출력 포맷 조정
#include <stdlib.h>   // 동적 메모리 할당, exit 등
#include <string.h>   // 문자열 처리 함수: strcpy, strcmp, strtok 등

int check_retry_or_end();                                                    //재시도 또는 종료 확인 함수
int detect_pe_type(const char* filepath, char* out_ext, size_t ext_bufsize); // PE 파일 타입 판별 함수

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