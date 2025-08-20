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

// ========================= Release 빌드: 디버그 정보 제거 & 최적화 =========================
// NDEBUG는 보통 Release에서 정의됨.
#ifdef NDEBUG
// PDB/디버그 정보 생성 금지
#pragma comment(linker, "/DEBUG:NONE")
// 미사용 코드/데이터 제거 및 동일 함수 병합 → exe 사이즈 축소
#pragma comment(linker, "/OPT:REF")
#pragma comment(linker, "/OPT:ICF")
// 증분 링크 비활성화(릴리즈 권장)
#pragma comment(linker, "/INCREMENTAL:NO")
#endif
// ============================================================================================


// ========================= 2GB 제한 설정 (x86/x64 공통) =========================
// x86(32-bit) 빌드에서는 LARGEADDRESSAWARE 비활성화 → 유저 VA 2GB 고정
#ifndef _WIN64
#pragma comment(linker, "/LARGEADDRESSAWARE:NO")
#endif

// Job Object로 프로세스 커밋(실사용) 상한 2GB 설정 (x86/x64 공통)
static HANDLE g_featpexJob = NULL;

static BOOL set_process_memory_limit_bytes(SIZE_T bytes) {
    if (g_featpexJob) return TRUE;

    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) return FALSE;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
    ZeroMemory(&jeli, sizeof(jeli));
    jeli.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
    jeli.ProcessMemoryLimit = bytes;
    jeli.JobMemoryLimit = bytes;

    if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
        CloseHandle(hJob);
        return FALSE;
    }
    if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
        CloseHandle(hJob);
        return FALSE;
    }
    g_featpexJob = hJob; // 핸들을 유지해야 제한이 유지됨
    return TRUE;
}

static BOOL set_process_memory_limit_gb(double gb) {
    SIZE_T bytes = (SIZE_T)(gb * 1024.0 * 1024.0 * 1024.0);
    return set_process_memory_limit_bytes(bytes);
}

// (선택) 기대치 안내/자기진단
static void assert_2gb_user_mode_expectation(void) {

}
// ============================================================================


// ---------- 유틸: 트림/인터랙티브 명령 파싱 ----------
static void trim(char* s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
    char* p = s;
    while (*p == ' ' || *p == '\t') ++p;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

/*
 인터랙티브 입력 줄에서 'FeatPEX -옵션 [경로] [-o out.csv]' 형태를 인식
 반환:
   2  = help 요청(-h)
   1  = 옵션/경로 정상 파싱
   0  = 그냥 파일 경로(명령줄 아님)
  -1  = 알 수 없는 옵션/형식 오류
  -2  = -p와 -a 충돌
*/
static int parse_interactive_command(
    char* line,
    bool* opt_all, bool* opt_pretty,
    char* opt_outcsv,
    char* outPath, size_t cap
) {
    trim(line);
    if (!line[0]) return 0;

    bool looks_like_cmd =
        !_strnicmp(line, "FeatPEX", 7) || line[0] == '-' || line[0] == '/';

    if (!looks_like_cmd) return 0; // 파일 경로

    // MSVC 안전 버전 사용 (C4996 회피)
    char tmp[1024]; strncpy_s(tmp, sizeof(tmp), line, _TRUNCATE);
    char* ctx = NULL, * tok = strtok_s(tmp, " \t", &ctx);

    // 선두가 실행파일명이면 스킵
    if (tok && (!_stricmp(tok, "FeatPEX") || !_stricmp(tok, "FeatPEX.exe"))) {
        tok = strtok_s(NULL, " \t", &ctx);
    }

    bool seen_p = *opt_pretty, seen_a = *opt_all;
    outPath[0] = 0;

    while (tok) {
        if (tok[0] == '-' || tok[0] == '/') {
            if (!_stricmp(tok, "-h") || !_stricmp(tok, "/h") || !_stricmp(tok, "--help")) return 2;
            else if (!_stricmp(tok, "-p") || !_stricmp(tok, "/p")) { seen_p = true; seen_a = false; }
            else if (!_stricmp(tok, "-a") || !_stricmp(tok, "/a")) { seen_a = true; seen_p = false; }
            else if (!_stricmp(tok, "-o") || !_stricmp(tok, "/o")) {
                char* nxt = strtok_s(NULL, " \t", &ctx);
                if (!nxt) return -1;
                strcpy_s(opt_outcsv, MAX_PATH, nxt);
            }
            else {
                return -1; // 알 수 없는 옵션
            }
        }
        else {
            if (!outPath[0]) { strncpy_s(outPath, cap, tok, _TRUNCATE); }
            else return -1; // 비옵션이 2개 이상
        }
        tok = strtok_s(NULL, " \t", &ctx);
    }

    if (seen_p && seen_a) return -2;
    *opt_pretty = seen_p;
    *opt_all = seen_a;
    return 1;
}

// ---------- 도움말 ----------
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

    // ★ 2GB 커밋 상한 (x86/x64 공통) — 가능한 한 빨리!
    if (!set_process_memory_limit_gb(2.0)) {
        fprintf(stderr, "\033[1;33m[Warn]\033[0m Failed to set 2GB memory limit (err=%lu)\n",
            (unsigned long)GetLastError());
    }
    // (선택) 기대치 안내
    assert_2gb_user_mode_expectation();

    SetConsoleTitleW(L"FeatPEX.exe");

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
                }
                else {
                    printf(" ");
                }
            }
            printf("\n");
        }
        printf("\033[1;32m\tWelcome to FeatPEX malware analyzer tool!\n\tThis tool is designed to analyze and extract Feature information from PE files.\033[0m\n");
        printf("\033[1;33m\tUse 'FeatPEX -h' for help.\033[0m\n\n");
        // 파란 안내를 쓰므로 여기서 색을 굳이 바꾸지 않음
    }

    // ===== 옵션 파싱 (커맨드라인) =====
    bool opt_help = false;
    bool opt_all = false;    // -a: 전체 구조만
    bool opt_pretty = false; // -p: Feature 요약만
    char opt_outcsv[MAX_PATH] = { 0 };
    const char* arg_path = nullptr;

    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (a[0] == '-' || a[0] == '/') {
            if (!_stricmp(a, "-h") || !_stricmp(a, "/h") || !_stricmp(a, "--help")) {
                opt_help = true;
            }
            else if (!_stricmp(a, "-a") || !_stricmp(a, "/a")) {
                opt_all = true;  opt_pretty = false;
            }
            else if (!_stricmp(a, "-p") || !_stricmp(a, "/p")) {
                opt_pretty = true; opt_all = false;
            }
            else if (!_stricmp(a, "-o") || !_stricmp(a, "/o")) {
                if (i + 1 < argc) {
                    strcpy_s(opt_outcsv, argv[++i]);
                }
                else {
                    printf("\033[1;31m[Error] -o requires an output path.\033[0m\n");
                    return 1;
                }
            }
            else {
                printf("\033[1;31m[Error] Unknown option: %s\033[0m\n", a);
                return 1;
            }
        }
        else {
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
    }
    else {
        while (1) {
            // 파란색 안내
            printf("\033[1;34mPlease enter the path of the PE file you want to analyze:\n");
            printf("Example: C:\\path\\to\\your\\file.exe\033[0m\n");

            if (fgets(input, sizeof(input), stdin) != NULL) {
                size_t len = strlen(input);
                if (len > 0 && input[len - 1] == '\n') input[len - 1] = '\0';
            }
            trim(input);
            if (!input[0]) {
                free(pe);
                printf("\033[1;31m[Error] Empty path. Aborted by user.\033[0m\n");
                return 2;
            }

            // 프롬프트에서 "FeatPEX -h|-p|-a [-o out.csv] [path]" 인식
            char parsedPath[MAX_PATH] = { 0 };
            int pr = parse_interactive_command(input, &opt_all, &opt_pretty, opt_outcsv, parsedPath, MAX_PATH);
            if (pr == 2) {                   // -h
                print_usage();
                continue; // 도움말 보여주고 다시 경로 입력
            }
            else if (pr == -1) {
                printf("\033[1;31m[Error] Unknown/invalid option in input.\033[0m\n");
                print_usage();
                continue;
            }
            else if (pr == -2) {
                printf("\033[1;31m[Error] -p and -a cannot be used together.\033[0m\n");
                continue;
            }
            else if (pr == 1) {
                if (parsedPath[0]) strcpy_s(input, parsedPath);
                else {
                    // 옵션만 입력했으면 계속 경로를 물음
                    continue;
                }
            }
            // pr == 0 이면 input은 경로 그대로

            FILE* fp = NULL;
            if (fopen_s(&fp, input, "rb") != 0 || fp == NULL) {
                printf("\033[1;31m[Error] The file does not exist or cannot be opened: %s\033[0m\n", input);
                if (check_retry_or_end()) continue;   // 다시 파일 경로 물음/옵션 가능
                else { free(pe); return 1; }
            }
            else {
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

    // ===== 출력 제어 =====
    // 기본: 전체 + 요약
    // opt_all=true -> 전체만 / opt_pretty=true -> 요약만
    const bool print_all = opt_all || (!opt_all && !opt_pretty);
    const bool print_feat = opt_pretty || (!opt_all && !opt_pretty);

    if (print_all) {
        print_everything(pe, TRUE);
    }

    if (print_feat) {
        feature_extraction_banner(1200); // 진행감 표시
        PE_FEATURES feat;
        if (extract_pe_features(pe, &feat)) {
            print_features_pretty(input, &feat);

            // CSV 콘솔 프리뷰
            printf("\n\033[1;36m[+] Feature Vector (CSV preview)\033[0m\n");
            print_features_csv_header_once();      // 헤더는 최초 1회만
            print_features_csv_row(input, &feat);  // 한 줄 프리뷰
            printf("\n");

            // CSV 저장
            if (opt_outcsv[0]) {
                if (write_features_csv(opt_outcsv, input, &feat)) {
                    printf("\033[1;32m[OK] Features appended to %s\033[0m\n", opt_outcsv);
                }
                else {
                    printf("\033[1;31m[Error] Failed to write CSV: %s\033[0m\n", opt_outcsv);
                }
            }
        }
        else {
            printf("\033[1;31m[Error] Feature extraction failed.\033[0m\n");
        }
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