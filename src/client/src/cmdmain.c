//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Main command parser entry point
//-----------------------------------------------------------------------------

// ensure gmtime_r is available even with -std=c99; must be included before
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200112L
#endif
#include "cmdmain.h"

#include <string.h>
#include <ctype.h>
#include <time.h>    // MingW
#include <stdlib.h>  // calloc

#include "comms.h"
#include "cmdhf.h"
#include "cmddata.h"
#include "cmdhw.h"
#include "cmdlf.h"
#include "cmdnfc.h"
#include "cmdtrace.h"
#include "cmdscript.h"
#include "cmdcrc.h"
#include "cmdanalyse.h"
#include "emv/cmdemv.h"   // EMV
#include "cmdflashmem.h"  // rdv40 flashmem commands
#include "cmdpiv.h"
#include "cmdsmartcard.h" // rdv40 smart card ISO7816 commands
#include "cmdusart.h"     // rdv40 FPC USART commands
#include "cmdwiegand.h"   // wiegand commands
#include "ui.h"
#include "util_posix.h"
#include "commonutil.h"   // ARRAYLEN
#include "preferences.h"
#include "cliparser.h"
#include "cmdmqtt.h"

static int CmdHelp(const char *Cmd);

static void AppendDate(char *s, size_t slen, const char *fmt) {
    struct tm *ct, tm_buf;
    time_t now = time(NULL);
#if defined(_WIN32)
    ct = gmtime_s(&tm_buf, &now) == 0 ? &tm_buf : NULL;
#else
    ct = gmtime_r(&now, &tm_buf);
#endif
    if (ct == NULL) {
        PrintAndLogEx(WARNING, "gmtime 失败");
        return;
    }

    // If no format is specified, use ISO8601
    if (fmt == NULL)
        strftime(s, slen, "%Y-%m-%dT%H:%M:%SZ", ct);  // ISO8601
    else
        strftime(s, slen, fmt, ct);
}

static int lf_search_plus(const char *Cmd) {

    sample_config oldconfig;
    memset(&oldconfig, 0, sizeof(sample_config));

    int retval = lf_getconfig(&oldconfig);

    if (retval != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "获取当前设备配置失败");
        return retval;
    }

    // Divisor : frequency(khz)
    // 95      88      47      31      23
    // 125.00  134.83  250.00  375.00  500.00

    int16_t default_divisor[] = {95, 88, 47, 31, 23};

    /*
      default LF config is set to:
      decimation = 1
      bits_per_sample = 8
      averaging = YES
      divisor = 95 (125kHz)
      trigger_threshold = 0
      samples_to_skip = 0
      verbose = YES
    */
    sample_config config = {
        .decimation = 1,
        .bits_per_sample = 8,
        .averaging = 1,
        .trigger_threshold = 0,
        .samples_to_skip = 0,
        .verbose = false
    };

    // Iteration defaults
    for (int i = 0; i < ARRAYLEN(default_divisor); ++i) {

        if (kbd_enter_pressed()) {
            PrintAndLogEx(INFO, "键盘已按下。完成。");
            break;
        }
        // Try to change config!
        uint32_t d;
        d = config.divisor = default_divisor[i];
        PrintAndLogEx(INFO, "-->  trying  ( " _GREEN_("%d.%02d kHz")" )", 12000 / (d + 1), ((1200000 + (d + 1) / 2) / (d + 1)) - ((12000 / (d + 1)) * 100));

        retval = lf_setconfig(&config);
        if (retval != PM3_SUCCESS)
            break;

        // The config for pm3 is changed, we can trying search!
        retval = CmdLFfind(Cmd);
        if (retval == PM3_SUCCESS)
            break;

    }

    lf_setconfig(&oldconfig);
    return retval;
}

static int CmdAuto(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "auto",
                  "运行低频搜索/高频搜索/数据绘图/数据保存",
                  "auto"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("c", NULL, "Continue searching even after a first hit"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool exit_first = (arg_get_lit(ctx, 1) == false);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "低频搜索");
    int ret = CmdLFfind("");
    if (ret == PM3_SUCCESS && exit_first)
        return ret;

    PrintAndLogEx(INFO, "高频搜索");
    ret = CmdHFSearch("");
    if (ret == PM3_SUCCESS && exit_first)
        return ret;

    PrintAndLogEx(INFO, "lf search - 未知");
    ret = lf_search_plus("");
    if (ret == PM3_SUCCESS && exit_first)
        return ret;

    if (ret != PM3_SUCCESS)
        PrintAndLogEx(INFO, "LF / HF 搜索均失败，");

    PrintAndLogEx(INFO, "Trying " _YELLOW_("`lf read`") " and save a trace for you");

    CmdPlot("");

    lf_read(false, 40000);

    char *fname = calloc(100, sizeof(uint8_t));
    if (fname == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    AppendDate(fname, 100, "-f lf_unknown_%Y-%m-%d_%H:%M");
    CmdSave(fname);
    free(fname);
    return PM3_SUCCESS;
}

int CmdRem(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "rem",
                  "在日志文件中添加文本行",
                  "rem my message    -> adds a timestamp with `my message`"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx1(NULL, NULL, NULL, "message line you want inserted"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    struct arg_str *foo = arg_get_str(ctx, 1);
    size_t count = 0;
    size_t len = 0;
    do {
        count += strlen(foo->sval[len]);
    } while (len++ < (foo->count - 1));

    char s[count + foo->count];
    memset(s, 0, sizeof(s));

    len = 0;
    do {
        snprintf(s + strlen(s), sizeof(s) - strlen(s), "%s ", foo->sval[len]);
    } while (len++ < (foo->count - 1));

    CLIParserFree(ctx);
    char buf[22] = {0};
    AppendDate(buf, sizeof(buf), NULL);
    PrintAndLogEx(SUCCESS, "%s 备注: %s", buf, s);
    return PM3_SUCCESS;
}

static int CmdHints(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hint",
                  "开启/关闭提示",
                  "hints --on\n"
                  "hints -1\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("1", "on", "开启提示"),
        arg_lit0("0", "off", "关闭提示"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool turn_on = arg_get_lit(ctx, 1);
    bool turn_off = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (turn_on && turn_off) {
        PrintAndLogEx(ERR, "不能同时关闭和开启");
        return PM3_EINVARG;
    }

    if (turn_off) {
        g_session.show_hints = false;
    } else if (turn_on) {
        g_session.show_hints = true;
    }

    PrintAndLogEx(INFO, "提示为 %s", (g_session.show_hints) ? "ON" : "OFF");
    return PM3_SUCCESS;
}

static int CmdMsleep(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "msleep",
                  "休眠指定的毫秒数",
                  "msleep -t 100"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("t", "ms", "<ms>", "时间（毫秒）"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t ms = arg_get_u32_def(ctx, 1, 0);
    CLIParserFree(ctx);

    if (ms == 0) {
        PrintAndLogEx(ERR, "指定的输入无效。不能为零");
        return PM3_EINVARG;
    }

    msleep(ms);
    return PM3_SUCCESS;
}

static int CmdQuit(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "quit",
                  "退出 Proxmark3 客户端终端",
                  "退出"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return PM3_SQUIT;
}

static int CmdRev(const char *Cmd) {
    CmdCrc(Cmd);
    return PM3_SUCCESS;
}

static int CmdPref(const char *Cmd) {
    CmdPreferences(Cmd);
    return PM3_SUCCESS;
}

static int CmdClear(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "clear",
                  "清除Proxmark3客户端终端屏幕",
                  "clear      -> clear the terminal screen\n"
                  "clear -b   -> clear the terminal screen and the scrollback buffer"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("b", "back", "同时清除回滚缓冲区"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool scrollback = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (!scrollback)
        PrintAndLogEx(NORMAL, _CLEAR_ _TOP_ "");
    else
        PrintAndLogEx(NORMAL, _CLEAR_ _TOP_ _CLEAR_SCROLLBACK_ "");

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {

    {"help",         CmdHelp,      AlwaysAvailable,         "使用`" _YELLOW_("<command> help") "` for details of a command"},
    {"prefs",        CmdPref,      AlwaysAvailable,         "{ 编辑客户端/设备偏好... }"},
    {"--------",     CmdHelp,      AlwaysAvailable,         "----------------------- " _CYAN_("技术") " -----------------------"},
    {"analyse",      CmdAnalyse,   AlwaysAvailable,         "{ 分析工具... }"},
    {"data",         CmdData,      AlwaysAvailable,         "{ 绘图窗口 / 数据缓冲区操作... }"},
    {"emv",          CmdEMV,       AlwaysAvailable,         "{ EMV ISO-14443 / ISO-7816... }"},
    {"hf",           CmdHF,        AlwaysAvailable,         "{ 高频命令... }"},
    {"hw",           CmdHW,        AlwaysAvailable,         "{ 硬件命令... }"},
    {"lf",           CmdLF,        AlwaysAvailable,         "{ 低频命令... }"},
    {"mem",          CmdFlashMem,  IfPm3Flash,              "{ Flash 内存操作... }"},
    {"mqtt",         CmdMqtt,      AlwaysAvailable,         "{ MQTT 命令... }"},
    {"nfc",          CmdNFC,       AlwaysAvailable,         "{ NFC 命令... }"},
    {"piv",          CmdPIV,       AlwaysAvailable,         "{ PIV 命令... }"},
    {"reveng",       CmdRev,       AlwaysAvailable,         "{ 来自 RevEng 软件的 CRC 计算... }"},
    {"smart",        CmdSmartcard, AlwaysAvailable,         "{ 智能卡 ISO-7816 命令... }"},
    {"script",       CmdScript,    AlwaysAvailable,         "{ 脚本命令... }"},
    {"trace",        CmdTrace,     AlwaysAvailable,         "{ 迹线操作... }"},
    {"usart",        CmdUsart,     IfPm3FpcUsartFromUsb,    "{ USART 命令... }"},
    {"wiegand",      CmdWiegand,   AlwaysAvailable,         "{ Wiegand 格式操作... }"},
    {"--------",     CmdHelp,      AlwaysAvailable,         "----------------------- " _CYAN_("常规") " -----------------------"},
    {"auto",         CmdAuto,      IfPm3Present,            "未知标签自动检测过程"},
    {"clear",        CmdClear,     AlwaysAvailable,         "清屏"},
    {"hint",        CmdHints,     AlwaysAvailable,         "开启/关闭提示"},
    {"msleep",       CmdMsleep,    AlwaysAvailable,         "添加毫秒级暂停"},
    {"rem",          CmdRem,       AlwaysAvailable,         "在日志文件中添加文本行"},
    {"quit",         CmdQuit,      AlwaysAvailable,         ""},
    {"exit",         CmdQuit,      AlwaysAvailable,         "退出程序"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Entry point into our code: called whenever the user types a command and
// then presses Enter, which the full command line that they typed.
//-----------------------------------------------------------------------------
int CommandReceived(const char *Cmd) {
    return CmdsParse(CommandTable, Cmd);
}

command_t *getTopLevelCommandTable(void) {
    return CommandTable;
}

