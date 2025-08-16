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

static void print_usage() {
    printf(
        "Usage:\n"
        "  FeatPEX [-h] [-p] [-a] [-o out.csv] <pe_path>\n"
        "\n"
        "Options:\n"
        "  -h            Show this help and exit\n"
        "  -p            Pretty feature report only (concise)\n"
        "  -a            Print EVERYTHING (headers/dirs/tables) as well\n"
        "  -o <out.csv>  Append features to the specified CSV file\n"
        "\n"
        "Notes:\n"
        "  If <pe_path> is omitted, interactive mode will ask for a file path.\n"
    );
}

int main(int argc, char* argv[]) {
    set_console_encoding();

RESTART_ALL:
    // ===== 배너 =====
    {
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
                } else {
                    printf(" ");
                }
            }
            printf("\n");
        }
        printf("\033[1;32m\tWelcome to FeatPEX malware analyzer tool!\n\tThis tool is designed to analyze and extract Feature information from PE files.\033[0m\n");
        printf("\033[1;33m\tUse 'FeatPEX -h' for help.\033[0m\n\n");
        printf("\033[1;34m");
    }

    // ===== 옵션 파싱 =====
    bool opt_help = false;
    bool opt_all  = false; // -a: print_everything
    bool opt_pretty = false; // -p: pretty report only
    char opt_outcsv[MAX_PATH] = {0};
    const char* arg_path = nullptr;

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (a[0] == '-' || a[0] == '/') {
            if (!_stricmp(a, "-h") || !_stricmp(a, "/h") || !_stricmp(a, "--help")) {
                opt_help = true;
            } else if (!_stricmp(a, "-a") || !_stricmp(a, "/a") ) {
                opt_all = true;
            } else if (!_stricmp(a, "-p") || !_stricmp(a, "/p") ) {
                opt_pretty = true;
            } else if (!_stricmp(a, "-o") || !_stricmp(a, "/o")) {
                if (i + 1 < argc) {
                    strcpy_s(opt_outcsv, argv[++i]);
                } else {
                    printf("\033[1;31m[Error] -o requires an output path.\033[0m\n");
                    return 1;
                }
            } else {
                printf("\033[1;31m[Error] Unknown option: %s\033[0m\n", a);
                return 1;
            }
        } else {
            arg_path = a; // 첫 번째 비옵션 인자 = 파일 경로
            // 나머지 비옵션은 무시
            break;
        }
    }

    if (opt_help) { print_usage(); return 0; }

    // ===== 구조체 동적할당 =====
    PE_FILE* pe = (PE_FILE*)malloc(sizeof(PE_FILE));
    if (!pe) { printf("[Error] Memory allocation failed.\n"); return 1; }

    char input[MAX_PATH] = { 0 };
    char peType[16] = { 0 };

    bool interactive = (arg_path == nullptr);

    // ===== 파일 경로 획득 =====
    if (!interactive) {
        strcpy_s(input, arg_path);
    } else {
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
                if (check_retry_or_end()) continue;   // 다시 파일 경로 물음
                else { free(pe); return 1; }
            } else {
                fclose(fp);
                printf("\033[1;32m[OK] File found: %s\033[0m\n", input);
                break;
            }
        }
    }

    printf("You entered: %s\n", input);
    printf("\033[1;36mStarting analysis...\033[0m\n");

    detect_pe_type(input, peType, sizeof(peType));
    printf("\033[1;33m[*] PE Type: %s\033[0m\n", peType[0] ? peType : "unknown");

    if (!load_pe_file(input, pe)) {
        printf("[Error] PE file load failed.\n");
        free(pe);
        return 1;
    }

    print_everything(pe, TRUE);
   
    // ===== Feature 추출 =====
    feature_extraction_banner(1200); // 진행감 표시
    PE_FEATURES feat;
    if (extract_pe_features(pe, &feat)) {
        if (opt_pretty || !opt_all) {
            // 사람이 읽기 쉬운 리포트
            print_features_pretty(input, &feat);
        }

        // CSV 콘솔 프리뷰
        printf("\n\033[1;36m[+] Feature Vector (CSV preview)\033[0m\n");
        print_features_csv_header_once();      // 헤더는 최초 1회만
        print_features_csv_row(input, &feat);  // 한 줄 프리뷰
        printf("\n");

        // CSV 저장
        if (opt_outcsv[0]) {
            if (write_features_csv(opt_outcsv, input, &feat)) {
                printf("\033[1;32m[OK] Features appended to %s\033[0m\n", opt_outcsv);
            } else {
                printf("\033[1;31m[Error] Failed to write CSV: %s\033[0m\n", opt_outcsv);
            }
        } else if (interactive) {
            char ans[16] = { 0 };
            printf("\n\033[1;33mDo you want to export these features to CSV? (Y/N): \033[0m");
            if (fgets(ans, sizeof(ans), stdin)) {
                if (ans[0] == 'Y' || ans[0] == 'y') {
                    char outpath[MAX_PATH] = { 0 };
                    printf("\033[1;33mEnter output CSV path (default: features.csv): \033[0m");
                    if (fgets(outpath, sizeof(outpath), stdin)) {
                        size_t L = strlen(outpath);
                        if (L > 0 && outpath[L - 1] == '\n') outpath[L - 1] = 0;
                    }
                    if (outpath[0] == 0) strcpy_s(outpath, sizeof(outpath), "features.csv");

                    if (write_features_csv(outpath, input, &feat)) {
                        printf("\033[1;32m[OK] Features appended to %s\033[0m\n", outpath);
                    } else {
                        printf("\033[1;31m[Error] Failed to write CSV: %s\033[0m\n", outpath);
                    }
                }
            }
        }
    } else {
        printf("\033[1;31m[Error] Feature extraction failed.\033[0m\n");
    }

    // ===== 리소스 정리 =====
    free_pe_file(pe);
    free(pe);

    // 비대화형이면 종료, 대화형이면 재시도 여부
    if (!interactive) return 0;

    if (check_retry_or_end()) {
        printf("\n");
        goto RESTART_ALL;   // 처음으로 돌아가서 새 파일 분석
    }
    return 0;
}


int check_retry_or_end(void) {
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