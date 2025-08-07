#include <stdio.h>                                                                  // 파일 입출력 함수: fopen, fread, fgets, fprintf 등
#include <iostream>                                                                 // 표준 입출력 (cin, cout)
#include <string>                                                                   // 문자열 처리
#include <sstream>                                                                  // 문자열 스트림
#include <iomanip>                                                                  // 입출력 포맷 조정
#include <stdlib.h>                                                                 // 동적 메모리 할당, exit 등
#include <string.h>                                                                 // 문자열 처리 함수: strcpy, strcmp, strtok 등
#include <Windows.h>                                                                // Windows API 함수: fopen_s, fseek 등
#include <winnt.h>                                                                  // PE 파일 구조체 정의
#include <tchar.h>
#include "pe_parser.h"                                                              // PE 파일 파싱을 위한 헤더

#define MAX_PATH 260                                                                // Windows에서 경로의 최대 길이

int check_retry_or_end();                                                           // 파일 열기 실패 시 재시도 여부 확인 함수

int main() {
	set_console_encoding();                                                         // 콘솔 인코딩 설정

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
                printf("\033[1;%dm%c\033[0m", color, c);                            // 색상 입히고 출력
                color_index++;
            }
            else {
                printf(" ");                                                        // 공백은 그대로 출력
            }
        }
        printf("\n");
    }

    printf("\033[1;32m\tWelcome to FeatPEX malware analyzer tool!\n\tThis tool is designed to analyze and extract Feature information from PE files.\033[0m\n");
    printf("\033[1;33m\tPlease use the command 'FeatPEX -h' for help.\033[0m\n\n");
    printf("\033[1;34m");                                                           // 파란색으로 입력 프롬프트

    PE_FILE* pe = (PE_FILE*)malloc(sizeof(PE_FILE));
    if (!pe) {
        printf("[Error] Memory allocation failed.\n");
        return 1;
    }

    char input[MAX_PATH] = { 0 };                                                           // 경로 최대 길이(Windows MAX_PATH 기준)로 버퍼 선언
	char peType[16] = { 0 };                                                        // PE 파일 타입을 저장할 버퍼

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
                continue;                                                           // 다시 입력
            }
            else {
                break;                                                              // 종료
            }
        }
        else {
            fclose(fp);
            printf("\033[1;32m[OK] File found: %s\033[0m\n", input);
            break;                                                                  // 성공 시 루프 탈출
        }
    }

    // 정상적으로 열렸을 때 분석 로직 진행
    printf("You entered: %s\n", input);
    printf("\033[1;36mStarting analysis...\033[0m\n");

    detect_pe_type(input, peType, sizeof(peType));                                   // PE 타입 판별 함수 호출 (출력 버퍼는 NULL로 설정)
    printf("\033[1;33m[*] PE Type: %s\033[0m\n", peType);

    if (!load_pe_file(input, pe)) {
        printf("[Error] PE file load failed.\n");
        free(pe);
        return 1;
    }                                                        // PE 파일 로드 함수 호출
    else {
		print_dos_header(pe);                                            // DOS 헤더 출력 함수 호출
		print_rich_header(pe);                                          // Rich 헤더 출력 함수 호출
        if (pe->ntHeader32) {
            WORD magic = pe->ntHeader32->OptionalHeader.Magic;

            if (magic == 0x10B) {       // PE32 (32-bit)
                print_nt_header32(pe);
                print_file_header(pe);
                print_optional_header32(pe);
            }
            else if (magic == 0x20B) {  // PE32+ (64-bit)
                print_nt_header64(pe);
                print_file_header(pe);
                print_optional_header64(pe);
            }
            else {
                printf("\033[1;31m[Error] Unknown OptionalHeader.Magic: 0x%X\033[0m\n", magic);
            }
        }
        else {
            printf("\033[1;31m[Error] NT Header is NULL.\033[0m\n");
        }
		print_section_headers(pe);                                 // 섹션 헤더 출력 함수 호출
		print_data_directories(pe);// 데이터 디렉토리 출력 함수 호출
        print_export_table(pe); // export 테이블 출력 함수 호출
    }
    
    free(pe);
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