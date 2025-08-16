#include <stdio.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <tchar.h>
#include "pe_parser.h"

// Windows가 이미 MAX_PATH를 정의함. 다시 정의하지 않도록!
// #define MAX_PATH 260

int check_retry_or_end();

int main() {
    set_console_encoding();

    const char* art[] = {
        "  ______         _   _____  ________   __",
        " |  ____|       | | |  __ \\|  ____\\ \\ / /",
        " | |__ ___  __ _| |_| |__) | |__   \\ V / ",
        " |  __/ _ \\/ _` | __|  ___/|  __|   > <  ",
        " | | |  __/ (_| | |_| |    | |____ / . \\ ",
        " |_|  \\___|\\__,_|\\__|_|    |______/_/ \\_\\"
    };

    int colors[] = { 31, 33, 93, 32, 36, 34, 35 };
    int color_count = sizeof(colors) / sizeof(colors[0]);
    int line_count = sizeof(art) / sizeof(art[0]);

    for (int i = 0; i < line_count; i++) {
        int color_index = 0;
        for (int j = 0; art[i][j] != '\0'; j++) {
            char c = art[i][j];
            if (c != ' ') {
                int color = colors[color_index % color_count];
                printf("\033[1;%dm%c\033[0m", color, c);
                color_index++;
            }
            else {
                printf(" ");
            }
        }
        printf("\n");
    }

    printf("\033[1;32m\tWelcome to FeatPEX malware analyzer tool!\n\tThis tool is designed to analyze and extract Feature information from PE files.\033[0m\n");
    printf("\033[1;33m\tPlease use the command 'FeatPEX -h' for help.\033[0m\n\n");
    printf("\033[1;34m");

    // 구조체 자체를 동적 할당하되, 내부 버퍼는 load_pe_file()에서 malloc됨
    PE_FILE* pe = (PE_FILE*)malloc(sizeof(PE_FILE));
    if (!pe) {
        printf("[Error] Memory allocation failed.\n");
        return 1;
    }

    char input[MAX_PATH] = { 0 };
    char peType[16] = { 0 };

    while (1) {
        printf("Please enter the path of the PE file you want to analyze:\n");
        printf("Example: C:\\path\\to\\your\\file.exe\n");

        printf("\033[1;34m");
        if (fgets(input, sizeof(input), stdin) != NULL) {
            size_t len = strlen(input);
            if (len > 0 && input[len - 1] == '\n') input[len - 1] = '\0';
        }
        printf("\033[0m");

        FILE* fp = NULL;
        if (fopen_s(&fp, input, "rb") != 0 || fp == NULL) {
            printf("\033[1;31m[Error] The file does not exist or cannot be opened: %s\033[0m\n", input);
            if (check_retry_or_end()) continue;
            else { free(pe); return 1; }
        }
        else {
            fclose(fp);
            printf("\033[1;32m[OK] File found: %s\033[0m\n", input);
            break;
        }
    }

    printf("You entered: %s\n", input);
    printf("\033[1;36mStarting analysis...\033[0m\n");

    detect_pe_type(input, peType, sizeof(peType));
    printf("\033[1;33m[*] PE Type: %s\033[0m\n", peType);

    if (!load_pe_file(input, pe)) {
        printf("[Error] PE file load failed.\n");
        free(pe);
        return 1;
    }

    // ===== 출력 파이프라인 (전체 필드/테이블 상세 출력) =====
    // preview16 = TRUE 면 각 Data Directory에서 16바이트 HEX 프리뷰를 같이 보여줍니다.
    print_everything(pe, TRUE);

    // 리소스 정리: 내부 버퍼 해제 + 구조체 해제
    free_pe_file(pe);
    free(pe);
    return 0;
}

int check_retry_or_end() {
    char choice[10];
    while (1) {
        printf("\033[1;33mWould you like to try again? (Y/N): \033[0m");
        if (fgets(choice, sizeof(choice), stdin) != NULL) {
            size_t len = strlen(choice);
            if (len > 0 && choice[len - 1] == '\n') choice[len - 1] = '\0';

            if (choice[0] == 'Y' || choice[0] == 'y') return 1;
            else if (choice[0] == 'N' || choice[0] == 'n') {
                printf("\033[1;31mProgram terminated by user.\033[0m\n");
                return 0;
            }
        }
        printf("\033[1;31mInvalid input. Please enter Y or N.\033[0m\n");
    }
}
