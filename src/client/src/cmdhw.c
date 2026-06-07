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
// Hardware commands
// low-level hardware control
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_PYTHON
#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif
#include <Python.h>
#endif

#include "cmdparser.h" // command_t
#include "cliparser.h"
#include "comms.h"
#include "usart_defs.h"
#include "ui.h"
#include "fpga.h"
#include "cmdhw.h"
#include "cmddata.h"
#include "commonutil.h"
#include "preferences.h"
#include "pm3_cmd.h"
#include "pmflash.h"     // rdv40validation_t
#include "cmdflashmem.h" // get_signature..
#include "uart/uart.h"   // configure timeout
#include "util_posix.h"
#include "flash.h" // reboot to bootloader mode
#include "proxgui.h"
#include "graph.h" // for graph data

#include "lua.h"

static int CmdHelp(const char *Cmd);

static void lookup_chipid_short(uint32_t iChipID, uint32_t mem_used) {
    const char *asBuff;
    switch (iChipID) {
        case 0x270B0A40:
            asBuff = "AT91SAM7S512 Rev A";
            break;
        case 0x270B0A4E:
        case 0x270B0A4F:
            asBuff = "AT91SAM7S512 Rev B";
            break;
        case 0x270D0940:
            asBuff = "AT91SAM7S256 Rev A";
            break;
        case 0x270B0941:
            asBuff = "AT91SAM7S256 Rev B";
            break;
        case 0x270B0942:
            asBuff = "AT91SAM7S256 Rev C";
            break;
        case 0x270B0943:
            asBuff = "AT91SAM7S256 Rev D";
            break;
        case 0x270C0740:
            asBuff = "AT91SAM7S128 Rev A";
            break;
        case 0x270A0741:
            asBuff = "AT91SAM7S128 Rev B";
            break;
        case 0x270A0742:
            asBuff = "AT91SAM7S128 Rev C";
            break;
        case 0x270A0743:
            asBuff = "AT91SAM7S128 Rev D";
            break;
        case 0x27090540:
            asBuff = "AT91SAM7S64 Rev A";
            break;
        case 0x27090543:
            asBuff = "AT91SAM7S64 Rev B";
            break;
        case 0x27090544:
            asBuff = "AT91SAM7S64 Rev C";
            break;
        case 0x27080342:
            asBuff = "AT91SAM7S321 Rev A";
            break;
        case 0x27080340:
            asBuff = "AT91SAM7S32 Rev A";
            break;
        case 0x27080341:
            asBuff = "AT91SAM7S32 Rev B";
            break;
        case 0x27050241:
            asBuff = "AT9SAM7S161 Rev A";
            break;
        case 0x27050240:
            asBuff = "AT91SAM7S16 Rev A";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    PrintAndLogEx(NORMAL, "    MCU....... " _YELLOW_("%s"), asBuff);

    uint32_t mem_avail = 0;
    switch ((iChipID & 0xF00) >> 8) {
        case 0:
            mem_avail = 0;
            break;
        case 1:
            mem_avail = 8;
            break;
        case 2:
            mem_avail = 16;
            break;
        case 3:
            mem_avail = 32;
            break;
        case 5:
            mem_avail = 64;
            break;
        case 7:
            mem_avail = 128;
            break;
        case 9:
            mem_avail = 256;
            break;
        case 10:
            mem_avail = 512;
            break;
        case 12:
            mem_avail = 1024;
            break;
        case 14:
            mem_avail = 2048;
            break;
    }

    PrintAndLogEx(NORMAL, "    Memory.... " _YELLOW_("%u") " KB ( " _YELLOW_("%2.0f%%") " used )"
                  , mem_avail
                  , mem_avail == 0 ? 0.0f : (float)mem_used / (mem_avail * 1024) * 100
                 );
}

static void lookupChipID(uint32_t iChipID, uint32_t mem_used) {
    const char *asBuff;
    uint32_t mem_avail = 0;
    PrintAndLogEx(NORMAL, "\n [ " _YELLOW_("Hardware") " ]");

    switch (iChipID) {
        case 0x270B0A40:
            asBuff = "AT91SAM7S512 Rev A";
            break;
        case 0x270B0A4E:
        case 0x270B0A4F:
            asBuff = "AT91SAM7S512 Rev B";
            break;
        case 0x270D0940:
            asBuff = "AT91SAM7S256 Rev A";
            break;
        case 0x270B0941:
            asBuff = "AT91SAM7S256 Rev B";
            break;
        case 0x270B0942:
            asBuff = "AT91SAM7S256 Rev C";
            break;
        case 0x270B0943:
            asBuff = "AT91SAM7S256 Rev D";
            break;
        case 0x270C0740:
            asBuff = "AT91SAM7S128 Rev A";
            break;
        case 0x270A0741:
            asBuff = "AT91SAM7S128 Rev B";
            break;
        case 0x270A0742:
            asBuff = "AT91SAM7S128 Rev C";
            break;
        case 0x270A0743:
            asBuff = "AT91SAM7S128 Rev D";
            break;
        case 0x27090540:
            asBuff = "AT91SAM7S64 Rev A";
            break;
        case 0x27090543:
            asBuff = "AT91SAM7S64 Rev B";
            break;
        case 0x27090544:
            asBuff = "AT91SAM7S64 Rev C";
            break;
        case 0x27080342:
            asBuff = "AT91SAM7S321 Rev A";
            break;
        case 0x27080340:
            asBuff = "AT91SAM7S32 Rev A";
            break;
        case 0x27080341:
            asBuff = "AT91SAM7S32 Rev B";
            break;
        case 0x27050241:
            asBuff = "AT9SAM7S161 Rev A";
            break;
        case 0x27050240:
            asBuff = "AT91SAM7S16 Rev A";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    PrintAndLogEx(NORMAL, "  --= uC: " _YELLOW_("%s"), asBuff);

    switch ((iChipID & 0xE0) >> 5) {
        case 1:
            asBuff = "ARM946ES";
            break;
        case 2:
            asBuff = "ARM7TDMI";
            break;
        case 4:
            asBuff = "ARM920T";
            break;
        case 5:
            asBuff = "ARM926EJS";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Embedded Processor: %s", asBuff);

    switch ((iChipID & 0xF0000) >> 16) {
        case 1:
            asBuff = "1K bytes";
            break;
        case 2:
            asBuff = "2K bytes";
            break;
        case 3:
            asBuff = "6K bytes";
            break;
        case 4:
            asBuff = "112K bytes";
            break;
        case 5:
            asBuff = "4K bytes";
            break;
        case 6:
            asBuff = "80K bytes";
            break;
        case 7:
            asBuff = "160K bytes";
            break;
        case 8:
            asBuff = "8K bytes";
            break;
        case 9:
            asBuff = "16K bytes";
            break;
        case 10:
            asBuff = "32K bytes";
            break;
        case 11:
            asBuff = "64K bytes";
            break;
        case 12:
            asBuff = "128K bytes";
            break;
        case 13:
            asBuff = "256K bytes";
            break;
        case 14:
            asBuff = "96K bytes";
            break;
        case 15:
            asBuff = "512K bytes";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Internal SRAM size: %s", asBuff);

    switch ((iChipID & 0xFF00000) >> 20) {
        case 0x19:
            asBuff = "AT91SAM9xx Series";
            break;
        case 0x29:
            asBuff = "AT91SAM9XExx Series";
            break;
        case 0x34:
            asBuff = "AT91x34 Series";
            break;
        case 0x37:
            asBuff = "CAP7 Series";
            break;
        case 0x39:
            asBuff = "CAP9 Series";
            break;
        case 0x3B:
            asBuff = "CAP11 Series";
            break;
        case 0x40:
            asBuff = "AT91x40 Series";
            break;
        case 0x42:
            asBuff = "AT91x42 Series";
            break;
        case 0x55:
            asBuff = "AT91x55 Series";
            break;
        case 0x60:
            asBuff = "AT91SAM7Axx Series";
            break;
        case 0x61:
            asBuff = "AT91SAM7AQxx Series";
            break;
        case 0x63:
            asBuff = "AT91x63 Series";
            break;
        case 0x70:
            asBuff = "AT91SAM7Sxx Series";
            break;
        case 0x71:
            asBuff = "AT91SAM7XCxx Series";
            break;
        case 0x72:
            asBuff = "AT91SAM7SExx Series";
            break;
        case 0x73:
            asBuff = "AT91SAM7Lxx Series";
            break;
        case 0x75:
            asBuff = "AT91SAM7Xxx Series";
            break;
        case 0x92:
            asBuff = "AT91x92 Series";
            break;
        case 0xF0:
            asBuff = "AT75Cxx Series";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Architecture identifier: %s", asBuff);

    switch ((iChipID & 0x70000000) >> 28) {
        case 0:
            asBuff = "ROM";
            break;
        case 1:
            asBuff = "ROMless or on-chip Flash";
            break;
        case 2:
            asBuff = "Embedded flash memory";
            break;
        case 3:
            asBuff = "ROM and Embedded flash memory\nNVPSIZ is ROM size\nNVPSIZ2 is Flash size";
            break;
        case 4:
            asBuff = "SRAM emulating ROM";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    switch ((iChipID & 0xF00) >> 8) {
        case 0:
            mem_avail = 0;
            break;
        case 1:
            mem_avail = 8;
            break;
        case 2:
            mem_avail = 16;
            break;
        case 3:
            mem_avail = 32;
            break;
        case 5:
            mem_avail = 64;
            break;
        case 7:
            mem_avail = 128;
            break;
        case 9:
            mem_avail = 256;
            break;
        case 10:
            mem_avail = 512;
            break;
        case 12:
            mem_avail = 1024;
            break;
        case 14:
            mem_avail = 2048;
            break;
    }

    PrintAndLogEx(NORMAL, "  --= %s " _YELLOW_("%uK") " bytes ( " _YELLOW_("%2.0f%%") " used )"
                  , asBuff
                  , mem_avail
                  , mem_avail == 0 ? 0.0f : (float)mem_used / (mem_avail * 1024) * 100
                 );

    /*
    switch ((iChipID & 0xF000) >> 12) {
        case 0:
            asBuff = "None");
            break;
        case 1:
            asBuff = "8K bytes");
            break;
        case 2:
            asBuff = "16K bytes");
            break;
        case 3:
            asBuff = "32K bytes");
            break;
        case 5:
            asBuff = "64K bytes");
            break;
        case 7:
            asBuff = "128K bytes");
            break;
        case 9:
            asBuff = "256K bytes");
            break;
        case 10:
            asBuff = "512K bytes");
            break;
        case 12:
            asBuff = "1024K bytes");
            break;
        case 14:
            asBuff = "2048K bytes");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Second nonvolatile program memory size: %s", asBuff);
    */
}

static int CmdDbg(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 调试",
                  "设置设备端调试级别输出。\\n"
                  "Note: option `-4`, this option may cause malfunction itself by\n"
                  "introducing delays in time critical functions like simulation or sniffing",
                  "hw dbg    --> get current log level\n"
                  "hw dbg -1 --> set log level to _error_\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("0", NULL, "no debug messages"),
        arg_lit0("1", NULL, "error messages"),
        arg_lit0("2", NULL, "plus information messages"),
        arg_lit0("3", NULL, "plus debug messages"),
        arg_lit0("4", NULL, "print even debug messages in timing critical functions"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool lv0 = arg_get_lit(ctx, 1);
    bool lv1 = arg_get_lit(ctx, 2);
    bool lv2 = arg_get_lit(ctx, 3);
    bool lv3 = arg_get_lit(ctx, 4);
    bool lv4 = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if ((lv0 + lv1 + lv2 + lv3 + lv4) > 1) {
        PrintAndLogEx(INFO, "只能设置一个调试级别");
        return PM3_EINVARG;
    }

    uint8_t curr = DBG_NONE;
    if (getDeviceDebugLevel(&curr) != PM3_SUCCESS)
        return PM3_EFAILED;

    const char *dbglvlstr;
    switch (curr) {
        case DBG_NONE:
            dbglvlstr = "无";
            break;
        case DBG_ERROR:
            dbglvlstr = "error";
            break;
        case DBG_INFO:
            dbglvlstr = "info";
            break;
        case DBG_DEBUG:
            dbglvlstr = "debug";
            break;
        case DBG_EXTENDED:
            dbglvlstr = "extended";
            break;
        default:
            dbglvlstr = "unknown";
            break;
    }
    PrintAndLogEx(INFO, "  Current debug log level..... %d ( " _YELLOW_("%s") " )", curr, dbglvlstr);

    if ((lv0 + lv1 + lv2 + lv3 + lv4) == 1) {
        uint8_t dbg = 0;
        if (lv0)
            dbg = 0;
        else if (lv1)
            dbg = 1;
        else if (lv2)
            dbg = 2;
        else if (lv3)
            dbg = 3;
        else if (lv4)
            dbg = 4;

        if (setDeviceDebugLevel(dbg, true) != PM3_SUCCESS)
            return PM3_EFAILED;
    }
    return PM3_SUCCESS;
}

static int CmdDetectReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 检测读取器",
                  "开始检测读卡器场的存在",
                  "hw detectreader\n"
                  "hw detectreader -L\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("L", "LF", "仅检测低频125/134 kHz"),
        arg_lit0("H", "HF", "仅检测高频13.56 MHz"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool lf = arg_get_lit(ctx, 1);
    bool hf = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // 0: Detect both frequency in mode 1
    // 1: LF_ONLY
    // 2: HF_ONLY
    uint8_t arg = 0;
    if (lf == true && hf == false) {
        arg = 1;
    } else if (hf == true && lf == false) {
        arg = 2;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LISTEN_READER_FIELD, (uint8_t *)&arg, sizeof(arg));
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to change modes and exit");

    for (;;) {
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, _GREEN_("<Enter>") " pressed");
        }

        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_LISTEN_READER_FIELD, &resp, 1000)) {
            if (resp.status != PM3_EOPABORTED) {
                PrintAndLogEx(ERR, "意外响应: %d", resp.status);
            }
            break;
        }
    }
    PrintAndLogEx(INFO, "完成！");
    return PM3_SUCCESS;
}

// ## FPGA Control
static int CmdFPGAOff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 FPGA关闭",
                  "关闭FPGA和天线场",
                  "hw fpgaoff\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_FPGA_MAJOR_MODE_OFF, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdLCD(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 LCD",
                  "向LCD发送命令/数据",
                  "hw lcd -r AA -c 03    -> sends 0xAA three times"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1("r", "raw", "<hex>", "data "),
        arg_int1("c", "cnt", "<dec>", "发送次数"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int r_len = 0;
    uint8_t raw[1] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &r_len);
    int j = arg_get_int_def(ctx, 2, 1);
    CLIParserFree(ctx);
    if (j < 1) {
        PrintAndLogEx(WARNING, "计数必须大于零");
        return PM3_EINVARG;
    }

    while (j--) {
        clearCommandBuffer();
        SendCommandMIX(CMD_LCD, raw[0], 0, 0, NULL, 0);
    }
    return PM3_SUCCESS;
}

static int CmdLCDReset(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 LCD重置",
                  "硬件复位LCD",
                  "hw lcdreset\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_LCD_RESET, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdReadmem(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 读内存",
                  "将处理器闪存读取到文件或控制台查看",
                  "hw readmem -f myfile                    -> save 512KB processor flash memory to file\n"
                  "hw readmem -a 8192 -l 512               -> display 512 bytes from offset 8192\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("a", "adr", "<dec>", "开始读取的闪存地址"),
        arg_u64_0("l", "len", "<dec>", "长度（默认32或512KB）"),
        arg_str0("f", "file", "<fn>", "保存到文件"),
        arg_u64_0("c", "cols", "<dec>", "列分隔"),
        arg_lit0("r", "raw", "使用原始地址模式：从任意位置读取，不仅限于闪存"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // check for -file option first to determine the output mode
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool save_to_file = fnlen > 0;

    // default len to 512KB when saving to file, to 32 bytes when viewing on the console.
    uint32_t default_len = save_to_file ? 512 * 1024 : 32;

    uint32_t address = arg_get_u32_def(ctx, 1, 0);
    uint32_t len = arg_get_u32_def(ctx, 2, default_len);
    int breaks = arg_get_int_def(ctx, 4, 32);
    bool raw = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    uint8_t *buffer = calloc(len, sizeof(uint8_t));
    if (buffer == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    const char *flash_str = raw ? "" : " flash";
    PrintAndLogEx(INFO, "reading " _YELLOW_("%u") " bytes from processor%s memory",
                  len, flash_str);

    DeviceMemType_t type = raw ? MCU_MEM : MCU_FLASH;
    if (!GetFromDevice(type, buffer, len, address, NULL, 0, NULL, -1, true)) {
        PrintAndLogEx(FAILED, "错误：从MCU闪存读取");
        free(buffer);
        return PM3_EFLASH;
    }

    if (save_to_file) {
        saveFile(filename, ".bin", buffer, len);
    } else {
        PrintAndLogEx(INFO, "---- " _CYAN_("processor%s memory") " ----", flash_str);
        print_hex_break(buffer, len, breaks);
    }

    free(buffer);
    return PM3_SUCCESS;
}

static int CmdReset(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 重置",
                  "重置Proxmark3设备。",
                  "硬件 重置"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_HARDWARE_RESET, NULL, 0);
    PrintAndLogEx(INFO, "Proxmark3已重置。");
    return PM3_SUCCESS;
}

/*
 * Sets the divisor for LF frequency clock: lets the user choose any LF frequency below
 * 600kHz.
 */
static int CmdSetDivisor(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 设置低频分频器",
                  "以12 MHz / (除数 + 1)驱动低频天线。",
                  "hw setlfdivisor -d 88"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1("d", "div", "<dec>", "19 - 255 除数（默认95）"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t arg = arg_get_u32_def(ctx, 1, 95);
    CLIParserFree(ctx);

    if (arg < 19) {
        PrintAndLogEx(ERR, "Divisor must be between " _YELLOW_("19") " and " _YELLOW_("255"));
        return PM3_EINVARG;
    }
    // 12 000 000 (12MHz)
    clearCommandBuffer();
    SendCommandNG(CMD_LF_SET_DIVISOR, (uint8_t *)&arg, sizeof(arg));
    PrintAndLogEx(SUCCESS, "Divisor set, expected " _YELLOW_("%.1f") " kHz", ((double)12000 / (arg + 1)));
    return PM3_SUCCESS;
}

static int CmdSetHFThreshold(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 设置高频阈值",
                  "设置HF/14a和Legic模式中的阈值。",
                  "hw sethfthresh -t 7 -i 20 -l 8"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("t", "thresh", "<dec>", "阈值，用于14a读卡器模式（默认7）"),
        arg_int0("i", "high", "<dec>", "高阈值，用于 14a 嗅探模式（默认 20）"),
        arg_int0("l", "legic", "<dec>", "Legic模式中使用的阈值（默认8）"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct {
        uint8_t threshold;
        uint8_t threshold_high;
        uint8_t legic_threshold;
    } PACKED params;

    params.threshold = arg_get_int_def(ctx, 1, 7);
    params.threshold_high = arg_get_int_def(ctx, 2, 20);
    params.legic_threshold = arg_get_int_def(ctx, 3, 8);
    CLIParserFree(ctx);

    if ((params.threshold < 1) || (params.threshold > 63) || (params.threshold_high < 1) || (params.threshold_high > 63)) {
        PrintAndLogEx(ERR, "Thresholds must be between " _YELLOW_("1") " and " _YELLOW_("63"));
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443A_SET_THRESHOLDS, (uint8_t *)&params, sizeof(params));
    PrintAndLogEx(SUCCESS, "阈值已设置。");
    return PM3_SUCCESS;
}

static int CmdSetMux(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 设置多路复用器",
                  "将ADC多路复用器设置为特定值",
                  "hw setmux --hipkd    -> set HIGH PEAK\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "lopkd", "low peak"),
        arg_lit0(NULL, "loraw", "low raw"),
        arg_lit0(NULL, "hipkd", "high peak"),
        arg_lit0(NULL, "hiraw", "high raw"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool lopkd = arg_get_lit(ctx, 1);
    bool loraw = arg_get_lit(ctx, 2);
    bool hipkd = arg_get_lit(ctx, 3);
    bool hiraw = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if ((lopkd + loraw + hipkd + hiraw) > 1) {
        PrintAndLogEx(INFO, "只能设置一个 mux");
        return PM3_EINVARG;
    }

#ifdef WITH_FPC_USART
    if (loraw || hiraw) {
        PrintAndLogEx(INFO, "此ADC多路复用选项在编译了FPC USART的RDV4上不可用");
        return PM3_EINVARG;
    }
#endif

    uint8_t arg = 0;
    if (lopkd)
        arg = 0;
    else if (loraw)
        arg = 1;
    else if (hipkd)
        arg = 2;
    else if (hiraw)
        arg = 3;

    clearCommandBuffer();
    SendCommandNG(CMD_SET_ADC_MUX, (uint8_t *)&arg, sizeof(arg));
    return PM3_SUCCESS;
}

static int CmdStandalone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 独立模式",
                  "启动独立模式",
                  "hw standalone       -> start \n"
                  "hw standalone -a 1  -> start and send arg 1"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("a", "arg", "<dec>", "参数字节"),
        arg_str0("b", NULL, "<str>", "UniSniff arg: 14a, 14b, 15, iclass"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct p {
        uint8_t arg;
        uint8_t mlen;
        uint8_t mode[10];
    } PACKED packet;

    packet.arg = arg_get_u32_def(ctx, 1, 1);
    int mlen = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 2), packet.mode, sizeof(packet.mode), &mlen);
    if (mlen) {
        packet.mlen = mlen;
    }
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_STANDALONE, (uint8_t *)&packet, sizeof(struct p));
    return PM3_SUCCESS;
}

static int CmdDecay(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 衰减",
                  "测量场关闭后 HF 天线的衰减。\\n"
                  "Captures how quickly the peak-detect capacitor voltage drops\n"
                  "after the 13.56 MHz field is turned off. Different antenna loading\n"
                  "(unloaded, booster board, damaged) produces different decay profiles.",
                  "hw decay\n"
                  "hw decay --ms 100  --> stabilize for 100ms before measurement\n"
                  "hw decay --us 5000 --> measure 5ms decay window\n");

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "ms", "<dec>", "Field stabilization time in ms (default: 50)"),
        arg_int0(NULL, "us", "<dec>", "Measurement window in us (default: 2000)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint16_t stabilize_ms = arg_get_int_def(ctx, 1, 50);
    uint16_t measure_us = arg_get_int_def(ctx, 2, 2000);
    CLIParserFree(ctx);

    // Build parameter packet
    hf_decay_params_t decay_params = {
        .stabilize_ms = stabilize_ms,
        .measure_us = measure_us,
    };

    PrintAndLogEx(INFO, "测量高频天线衰减...");
    PrintAndLogEx(INFO, "  Field stabilization: " _YELLOW_("%d") " ms", stabilize_ms);
    PrintAndLogEx(INFO, "  Measurement window:  " _YELLOW_("%d") " us", measure_us);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_DECAY, (uint8_t *)&decay_params, sizeof(decay_params));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_DECAY, &resp, 5000) == false) {
        PrintAndLogEx(WARNING, "等待衰减测量超时");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "衰减测量失败");
        return PM3_ESOFT;
    }

    // Parse response header
    hf_decay_response_t *decay_resp = (hf_decay_response_t *)resp.data.asBytes;
    uint16_t baseline_mv = decay_resp->baseline_mv;
    uint16_t num_samples = decay_resp->num_samples;
    uint16_t sample_interval_us = decay_resp->sample_interval_us;
    uint16_t measure_window_us = decay_resp->measure_window_us;
    uint16_t samples[num_samples];
    memcpy(samples, decay_resp->samples_mv, num_samples * sizeof(uint16_t));

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------- " _CYAN_("HF Decay Measurement") " ----------");
    PrintAndLogEx(SUCCESS, "Baseline (field on).... " _YELLOW_("%d") " mV  (%.2f V)",
                  baseline_mv, baseline_mv / 1000.0);
    PrintAndLogEx(SUCCESS, "捕获的采样....... %d", num_samples);
    PrintAndLogEx(SUCCESS, "采样间隔........ ~%d us", sample_interval_us);
    PrintAndLogEx(SUCCESS, "总窗口........... %d 微秒", measure_window_us);

    if (num_samples == 0) {
        PrintAndLogEx(WARNING, "未捕获到样本");
        return PM3_ESOFT;
    }

    // Decay samples use fast ADC (reduced S&H) for ~5us/sample resolution.
    // Absolute mV values are ~11% of truth due to RC charging limitation,
    // but relative decay shape is accurate. Use first sample as 100% reference.
    uint16_t ref_mv = samples[0];

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, " idx | time (us) |  raw  |  %% of peak");
    PrintAndLogEx(INFO, "-----+-----------+-------+-------------");

    for (uint16_t i = 0; i < num_samples; i++) {
        uint32_t time_us = (num_samples > 1)
                           ? (uint32_t)i * measure_window_us / (num_samples - 1)
                           : 0;
        double pct = (ref_mv > 0)
                     ? 100.0 * samples[i] / ref_mv
                     : 0;
        PrintAndLogEx(INFO, " %3d | %7d   | %5d | %.1f%%",
                      i, time_us, samples[i], pct);
    }

    // Find time to 50% decay (relative to first sample)
    uint16_t half_ref = ref_mv / 2;
    int t_half_idx = -1;
    for (uint16_t i = 0; i < num_samples; i++) {
        if (samples[i] <= half_ref) {
            t_half_idx = i;
            break;
        }
    }

    PrintAndLogEx(NORMAL, "");
    if (t_half_idx >= 0) {
        uint32_t t_half_us = (num_samples > 1)
                             ? (uint32_t)t_half_idx * measure_window_us / (num_samples - 1)
                             : 0;
        PrintAndLogEx(SUCCESS, "衰减至 50%% 的时间..... ~" _YELLOW_("%d") " us (sample %d)", t_half_us, t_half_idx);
    } else {
        PrintAndLogEx(INFO, "电压在测量窗口内未达到50%%衰减");
    }

    uint16_t final_mv = samples[num_samples - 1];
    double final_pct = (ref_mv > 0) ? 100.0 * final_mv / ref_mv : 0;
    PrintAndLogEx(SUCCESS, "最终电压.......... %d 原始值（峰值的 %.1f%%）", final_mv, final_pct);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "注意：衰减样本使用快速ADC（约5微秒/样本，相对值）");

    // Load into graph window
    for (uint16_t i = 0; i < num_samples; i++) {
        g_GraphBuffer[i] = (int)samples[i];
    }
    g_GraphTraceLen = num_samples;
    ShowGraphWindow();
    RepaintGraphWindow();

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "衰减曲线已加载到图形窗口（mV vs 采样索引）");
    PrintAndLogEx(NORMAL, "");

    return PM3_SUCCESS;
}

static int CmdTune(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件调谐",
                  "测量设备天线的调谐。结果显示在图形窗口中。\\n"
                  "此命令 不会主动调校天线, \n"
                  "it's only informative by measuring voltage that the antennas will generate",
                  "硬件调谐"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

#define NON_VOLTAGE 1000
#define LF_UNUSABLE_V 2000
#define LF_MARGINAL_V 10000
#define HF_UNUSABLE_V 3000
#define HF_MARGINAL_V 5000
#define ANTENNA_ERROR 1.00 // current algo has 3% error margin.

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------- " _CYAN_("提醒") " ----------------------------");
    PrintAndLogEx(INFO, "`" _YELLOW_("硬件调谐") "` 不会主动调校天线.");
    PrintAndLogEx(INFO, "仅用于检测天线产生的电压以供参考.");
    PrintAndLogEx(INFO, "测量天线特性...");

    // hide demod plot line
    g_DemodBufferLen = 0;
    setClockGrid(0, 0);
    RepaintGraphWindow();
    int timeout = 0;
    int timeout_max = 20;

    clearCommandBuffer();
    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING, NULL, 0);
    PacketResponseNG resp;
    PrintAndLogEx(INPLACE, "% 3i", timeout_max - timeout);

    while (WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING, &resp, 500) == false) {

        fflush(stdout);
        if (timeout >= timeout_max) {
            PrintAndLogEx(WARNING, "\\n未收到Proxmark3响应。正在中止...");
            return PM3_ETIMEOUT;
        }

        timeout++;
        PrintAndLogEx(INPLACE, "% 3i", timeout_max - timeout);
    }

    PrintAndLogEx(NORMAL, "");

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "天线调谐失败");
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------- " _CYAN_("低频天线") " ----------");
    // in mVolt
    struct p {
        uint32_t v_lf134;
        uint32_t v_lf125;
        uint32_t v_lfconf;
        uint32_t v_hf;
        uint32_t peak_v;
        uint32_t peak_f;
        int divisor;
        uint8_t results[256];
    } PACKED;

    struct p *package = (struct p *)resp.data.asBytes;

    if (package->v_lf125 > NON_VOLTAGE)
        PrintAndLogEx(SUCCESS, "%.2f kHz ........... " _YELLOW_("%5.2f") " V", LF_DIV2FREQ(LF_DIVISOR_125), (package->v_lf125 * ANTENNA_ERROR) / 1000.0);

    if (package->v_lf134 > NON_VOLTAGE)
        PrintAndLogEx(SUCCESS, "%.2f kHz ........... " _YELLOW_("%5.2f") " V", LF_DIV2FREQ(LF_DIVISOR_134), (package->v_lf134 * ANTENNA_ERROR) / 1000.0);

    if (package->v_lfconf > NON_VOLTAGE && package->divisor > 0 && package->divisor != LF_DIVISOR_125 && package->divisor != LF_DIVISOR_134)
        PrintAndLogEx(SUCCESS, "%.2f kHz ........... " _YELLOW_("%5.2f") " V", LF_DIV2FREQ(package->divisor), (package->v_lfconf * ANTENNA_ERROR) / 1000.0);

    if (package->peak_v > NON_VOLTAGE && package->peak_f > 0)
        PrintAndLogEx(SUCCESS, "%.2f kHz （最佳谐振）.... " _BACK_GREEN_("%5.2f") " V", LF_DIV2FREQ(package->peak_f), (package->peak_v * ANTENNA_ERROR) / 1000.0);

    // Empirical measures in mV
    const double vdd_rdv4 = 9000;
    const double vdd_other = 5400;
    double vdd = IfPm3Rdv4Fw() ? vdd_rdv4 : vdd_other;

    if (package->peak_v > NON_VOLTAGE && package->peak_f > 0) {

        // Q measure with Q=f/delta_f
        double v_3db_scaled = (double)(package->peak_v * 0.707) / 512; // /512 == >>9
        uint32_t s2 = 0, s4 = 0;
        for (int i = 1; i < 256; i++) {
            if ((s2 == 0) && (package->results[i] > v_3db_scaled)) {
                s2 = i;
            }
            if ((s2 != 0) && (package->results[i] < v_3db_scaled)) {
                s4 = i;
                break;
            }
        }

        PrintAndLogEx(SUCCESS, "");
        PrintAndLogEx(SUCCESS, "近似Q因子测量");
        double lfq1 = 0;
        if (s4 != 0) {
            // we got all our points of interest
            double a = package->results[s2 - 1];
            double b = package->results[s2];
            double f1 = LF_DIV2FREQ(s2 - 1 + (v_3db_scaled - a) / (b - a));
            double c = package->results[s4 - 1];
            double d = package->results[s4];
            double f2 = LF_DIV2FREQ(s4 - 1 + (c - v_3db_scaled) / (c - d));
            lfq1 = LF_DIV2FREQ(package->peak_f) / (f1 - f2);
            PrintAndLogEx(SUCCESS, "频率带宽... " _YELLOW_("%.1lf"), lfq1);
        }

        // Q measure with Vlr=Q*(2*Vdd/pi)
        double lfq2 = (double)package->peak_v * 3.14 / 2 / vdd;
        PrintAndLogEx(SUCCESS, "峰值电压.......... " _YELLOW_("%.1lf"), lfq2);
        // cross-check results
        if (lfq1 > 3) {
            double approx_vdd = (double)package->peak_v * 3.14 / 2 / lfq1;
            // Got 8858 on a RDV4 with large antenna 134/14
            // Got 8761 on a non-RDV4
            const double approx_vdd_other_max = 8840;

            // 1% over threshold and supposedly non-RDV4
            if ((approx_vdd > approx_vdd_other_max * 1.01) && (!IfPm3Rdv4Fw())) {
                PrintAndLogEx(WARNING, "Contradicting measures seem to indicate you're running a " _YELLOW_("PM3GENERIC firmware on a RDV4"));
                PrintAndLogEx(WARNING, "可能存在误报，请检查您的设置");
            }
            // 1% below threshold and supposedly RDV4
            if ((approx_vdd < approx_vdd_other_max * 0.99) && (IfPm3Rdv4Fw())) {
                PrintAndLogEx(WARNING, "Contradicting measures seem to indicate you're running a " _YELLOW_("PM3_RDV4 firmware on a generic device"));
                PrintAndLogEx(WARNING, "可能存在误报，请检查您的设置");
            }
        }
    }

    char judgement[20];
    memset(judgement, 0, sizeof(judgement));
    // LF evaluation
    if (package->peak_v < LF_UNUSABLE_V)
        snprintf(judgement, sizeof(judgement), _RED_("unusable"));
    else if (package->peak_v < LF_MARGINAL_V)
        snprintf(judgement, sizeof(judgement), _YELLOW_("marginal"));
    else
        snprintf(judgement, sizeof(judgement), _GREEN_("ok"));

    // PrintAndLogEx((package->peak_v < LF_UNUSABLE_V) ? WARNING : SUCCESS, "LF antenna ( %s )", judgement);
    PrintAndLogEx((package->peak_v < LF_UNUSABLE_V) ? WARNING : SUCCESS, "LF antenna............ %s", judgement);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------- " _CYAN_("高频天线") " ----------");
    // HF evaluation
    if (package->v_hf > NON_VOLTAGE) {
        PrintAndLogEx(SUCCESS, "13.56 MHz............. " _BACK_GREEN_("%5.2f") " V", (package->v_hf * ANTENNA_ERROR) / 1000.0);
    }

    memset(judgement, 0, sizeof(judgement));

    // If HF is unusable or marginal, run a quick decay measurement to check
    // for booster board. With a booster, the first fast-ADC decay sample reads
    // 50-500 (rapid discharge). Without a booster, it reads >1000.
    bool hf_booster_detected = false;
    if (!IfPm3Rdv4Fw() && package->v_hf < HF_MARGINAL_V) {
        hf_decay_params_t decay_params = {
            .stabilize_ms = 50,
            .measure_us = 50,
        };

        clearCommandBuffer();
        SendCommandNG(CMD_HF_DECAY, (uint8_t *)&decay_params, sizeof(decay_params));

        if (WaitForResponseTimeout(CMD_HF_DECAY, &resp, 3000) && resp.status == PM3_SUCCESS) {
            hf_decay_response_t *decay_resp = (hf_decay_response_t *)resp.data.asBytes;
            if (decay_resp->num_samples > 0) {
                uint16_t samples[1];
                memcpy(samples, decay_resp->samples_mv, sizeof(uint16_t));
                if (samples[0] >= 50 && samples[0] <= 500) {
                    hf_booster_detected = true;
                }
            }
        }
    }

    if (hf_booster_detected) {
        PrintAndLogEx(SUCCESS, "");
        PrintAndLogEx(SUCCESS, "您的高频天线测量显示");
        PrintAndLogEx(SUCCESS, "一致的低电压");
        PrintAndLogEx(SUCCESS, "通过安装增强器");
        PrintAndLogEx(SUCCESS, "板。如果您没有");
        PrintAndLogEx(SUCCESS, "安装升压板，要么");
        PrintAndLogEx(SUCCESS, "你的天线故障或");
        PrintAndLogEx(SUCCESS, "HF 天线上有标签。");
    }

    PrintAndLogEx(SUCCESS, "");
    PrintAndLogEx(SUCCESS, "近似Q因子测量");

    if (package->v_hf >= HF_UNUSABLE_V) {
        // Q measure with Vlr=Q*(2*Vdd/pi)
        double hfq = (double)package->v_hf * 3.14 / 2 / vdd;
        PrintAndLogEx(SUCCESS, "峰值电压.......... " _YELLOW_("%.1lf"), hfq);
    }

    if (package->v_hf < HF_UNUSABLE_V)
        snprintf(judgement, sizeof(judgement), _RED_("unusable"));
    else if (package->v_hf < HF_MARGINAL_V)
        snprintf(judgement, sizeof(judgement), _YELLOW_("marginal"));
    else
        snprintf(judgement, sizeof(judgement), _GREEN_("ok"));

    PrintAndLogEx((package->v_hf < HF_UNUSABLE_V) ? WARNING : SUCCESS, "HF antenna ( %s )", judgement);

    // If HF voltage is ok/marginal but below 13V, check for
    // surface interference via decay measurement.
    // Only on PM3 Easy — RDV4 has different voltage divider.
    if (!IfPm3Rdv4Fw() && package->v_hf >= HF_MARGINAL_V && package->v_hf < 13000) {
        hf_decay_params_t surface_params = {
            .stabilize_ms = 50,
            .measure_us = 50,
        };

        clearCommandBuffer();
        SendCommandNG(CMD_HF_DECAY, (uint8_t *)&surface_params, sizeof(surface_params));

        if (WaitForResponseTimeout(CMD_HF_DECAY, &resp, 3000) && resp.status == PM3_SUCCESS) {
            hf_decay_response_t *surface_resp = (hf_decay_response_t *)resp.data.asBytes;
            if (surface_resp->num_samples > 0) {
                uint16_t samples[1];
                memcpy(samples, surface_resp->samples_mv, sizeof(uint16_t));
                if (samples[0] >= 600 && samples[0] <= 900) {
                    PrintAndLogEx(SUCCESS, "");
                    PrintAndLogEx(SUCCESS, "您的 proxmark 所在的表面可能");
                    PrintAndLogEx(SUCCESS, "包含干扰材料。请重试");
                    PrintAndLogEx(SUCCESS, "同时将proxmark握持在自由空间中。");
                }
            }
        }
    }

    // graph LF measurements
    // even here, these values has 3% error.
    uint16_t test1 = 0;
    for (int i = 0; i < 256; i++) {
        g_GraphBuffer[i] = package->results[i] - 128;
        test1 += package->results[i];
    }

    if (test1 > 0) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "-------- " _CYAN_("低频调谐图谱") " ------------");
        PrintAndLogEx(SUCCESS, "橙色线 - 分频 %d / %.2f kHz"
                      , LF_DIVISOR_125
                      , LF_DIV2FREQ(LF_DIVISOR_125)
                     );
        PrintAndLogEx(SUCCESS, "蓝线 - 分频   %d / %.2f kHz\n\n"
                      , LF_DIVISOR_134
                      , LF_DIV2FREQ(LF_DIVISOR_134)
                     );
        g_GraphTraceLen = 256;
        g_MarkerC.pos = LF_DIVISOR_125;
        g_MarkerD.pos = LF_DIVISOR_134;
        ShowGraphWindow();
        RepaintGraphWindow();
    } else {
        PrintAndLogEx(FAILED, "\\n所有值均为零。不显示低频调谐图\\n\\n");
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Q 因子必须在天线上无标签时测量");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdVersion(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件版本",
                  "显示客户端和连接的Proxmark3的版本信息",
                  "硬件版本"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    pm3_version(true, false);
    return PM3_SUCCESS;
}

static int CmdStatus(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 状态",
                  "显示已连接Proxmark3的运行时状态信息",
                  "hw status\n"
                  "hw status --ms 1000 -> Test connection speed with 1000ms timeout\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("m", "ms", "<ms>", "速度测试超时时间（微秒）"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int32_t speedTestTimeout = arg_get_int_def(ctx, 1, -1);
    CLIParserFree(ctx);

    clearCommandBuffer();
    PacketResponseNG resp;
    if (speedTestTimeout < 0) {
        speedTestTimeout = 0;
        SendCommandNG(CMD_STATUS, NULL, 0);
    } else {
        SendCommandNG(CMD_STATUS, (uint8_t *)&speedTestTimeout, sizeof(speedTestTimeout));
    }

    if (WaitForResponseTimeout(CMD_STATUS, &resp, 2000 + speedTestTimeout) == false) {
        PrintAndLogEx(WARNING, "状态命令超时。通信速度测试超时");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

int handle_tearoff(tearoff_params_t *params, bool verbose) {

    if (params == NULL)
        return PM3_EINVARG;

    clearCommandBuffer();
    SendCommandNG(CMD_SET_TEAROFF, (uint8_t *)params, sizeof(tearoff_params_t));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SET_TEAROFF, &resp, 500) == false) {
        PrintAndLogEx(WARNING, "撕扯命令超时。");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        if (params->delay_us > 0 && verbose)
            PrintAndLogEx(INFO, "Tear-off hook configured with delay of " _GREEN_("%i us"), params->delay_us);

        if (params->skip > 0 && verbose)
            PrintAndLogEx(INFO, "Tear-off hook will be skipped " _YELLOW_("%i times") " before being activated", params->skip);
        if (params->skip == 0 && verbose)
            PrintAndLogEx(INFO, "Tear-off hook skipping " _GREEN_("已禁用"));

        if (params->on && verbose)
            PrintAndLogEx(INFO, "Tear-off hook " _GREEN_("enabled"));

        if (params->off && verbose)
            PrintAndLogEx(INFO, "Tear-off hook " _RED_("已禁用"));
    } else if (verbose)
        PrintAndLogEx(WARNING, "撕扯命令失败。");
    return resp.status;
}

static int CmdTearoff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件撕脱",
                  "为下一个支持撕离的写命令配置撕离钩子。\\n"
                  "After having been triggered by a write command, the tear-off hook is deactivated\n"
                  "Delay (in us) must be between 1 and 43000 (43ms). Precision is about 1/3us.",
                  "hw tearoff --delay 1200 --> define delay of 1200us\n"
                  "hw tearoff --on --> (re)activate a previously defined delay\n"
                  "hw tearoff --off --> deactivate a previously activated but not yet triggered hook\n"
                  "hw tearoff --list --> list commands implementing tear-off hooks\n");

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "delay", "<dec>", "Delay in us before triggering tear-off, must be between 1 and 43000"),
        arg_lit0(NULL, "on", "Activate tear-off hook"),
        arg_lit0(NULL, "off", "Deactivate tear-off hook"),
        arg_int0(NULL, "skip", "<dec>", "Skip N triggers before activating the hook"),
        arg_lit0("s", "silent", "减少详细输出"),
        arg_lit0(NULL, "list", "List commands implementing tear-off hooks"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);
    tearoff_params_t params;
    int delay = arg_get_int_def(ctx, 1, -1);
    params.on = arg_get_lit(ctx, 2);
    params.off = arg_get_lit(ctx, 3);
    int skip = arg_get_int_def(ctx, 4, -1);
    bool silent = arg_get_lit(ctx, 5);
    bool list = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (list) {
        PrintAndLogEx(INFO, "实现撕下钩子的命令:");
        PrintAndLogEx(INFO, "  hf 14a raw");
        PrintAndLogEx(INFO, "  hf 14b apdu");
        PrintAndLogEx(INFO, "  hf 14b raw");
        PrintAndLogEx(INFO, "  hf 15 raw");
        PrintAndLogEx(INFO, "  hf iclass creditepurse");
        PrintAndLogEx(INFO, "  hf iclass wrbl");
        PrintAndLogEx(INFO, "  hf mf wrbl");
        PrintAndLogEx(INFO, "  hf mfu wrbl (with --skip 3)");
        PrintAndLogEx(INFO, "  hf topaz wrbl");
        PrintAndLogEx(INFO, "  lf em 4x05 write");
        PrintAndLogEx(INFO, "  lf em 4x50 wrbl");
        PrintAndLogEx(INFO, "  lf em 4x50 wrpwd");
        PrintAndLogEx(INFO, "  lf hitag wrbl");
        PrintAndLogEx(INFO, "  lf hitag hts wrbl");
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "另请参阅自行实现撕裂的命令:");
        PrintAndLogEx(INFO, "  lf em 4x05_unlock");
        PrintAndLogEx(INFO, "  lf t55xx dangerraw");
        PrintAndLogEx(INFO, "  hf iclass tear");
        PrintAndLogEx(INFO, "  hf iclass blacktears");
        PrintAndLogEx(INFO, "  hf mfu otptear");
        PrintAndLogEx(INFO, "  Standalone mode HF_ST25_TEAROFF");
        return PM3_SUCCESS;
    }

    if (delay != -1) {
        if ((delay < 1) || (delay > 43000)) {
            PrintAndLogEx(WARNING, "您不能将延迟设置在 1..43000 范围之外！");
            return PM3_EINVARG;
        }
    } else {
        delay = 0; // will be ignored by ARM
    }

    params.delay_us = delay;

    if (skip != -1) {
        if ((skip < 0) || (skip > 127)) {
            PrintAndLogEx(WARNING, "您不能将跳过设置在 0..127 范围之外！");
            return PM3_EINVARG;
        }
    }

    params.skip = skip;

    if (params.on && params.off) {
        PrintAndLogEx(WARNING, "您不能同时设置 --on 和 --off！");
        return PM3_EINVARG;
    }

    return handle_tearoff(&params, !silent);
}

static int CmdTia(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件TIA",
                  "触发定时间隔采集以重新调整实时计数器分频器",
                  "硬件TIA"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "触发新的时序间隔采集（TIA）...");
    clearCommandBuffer();
    SendCommandNG(CMD_TIA, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_TIA, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "TIA命令超时。您可能需要拔掉Proxmark3。");
        return PM3_ETIMEOUT;
    }
    PrintAndLogEx(INFO, "TIA完成。");
    return PM3_SUCCESS;
}

static int CmdTimeout(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件超时",
                  "设置客户端的通信超时",
                  "hw timeout            --> Show current timeout\n"
                  "hw timeout -m 20      --> Set the timeout to 20ms\n"
                  "hw timeout --ms 500   --> Set the timeout to 500ms\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("m", "ms", "<ms>", "超时时间（微秒）"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int32_t arg = arg_get_int_def(ctx, 1, -1);
    CLIParserFree(ctx);

    uint32_t oldTimeout = uart_get_timeouts();

    // timeout is not given/invalid, just show the current timeout then return
    if (arg < 0) {
        PrintAndLogEx(INFO, "Current communication timeout... " _GREEN_("%u") " ms", oldTimeout);
        return PM3_SUCCESS;
    }

    uint32_t newTimeout = arg;
    // UART_USB_CLIENT_RX_TIMEOUT_MS is considered as the minimum required timeout.
    if (newTimeout < UART_USB_CLIENT_RX_TIMEOUT_MS) {
        PrintAndLogEx(WARNING, "超时小于%u毫秒可能会导致错误。", UART_USB_CLIENT_RX_TIMEOUT_MS);
    } else if (newTimeout > 5000) {
        PrintAndLogEx(WARNING, "超时大于5000毫秒会导致客户端无响应。");
    }
    uart_reconfigure_timeouts(newTimeout);
    PrintAndLogEx(INFO, "旧通信超时... %u 毫秒", oldTimeout);
    PrintAndLogEx(INFO, "New communication timeout... " _GREEN_("%u") " ms", newTimeout);
    return PM3_SUCCESS;
}

static int CmdPing(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 Ping",
                  "测试 Proxmark3 是否响应",
                  "hw ping\n"
                  "hw ping --len 32"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("l", "len", "<dec>", "要发送的有效载荷长度"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t len = arg_get_u32_def(ctx, 1, 32);
    CLIParserFree(ctx);

    if (len > PM3_CMD_DATA_SIZE)
        len = PM3_CMD_DATA_SIZE;

    if (len) {
        PrintAndLogEx(INFO, "Ping sent with payload len... " _YELLOW_("%d"), len);
    } else {
        PrintAndLogEx(INFO, "Ping已发送");
    }

    clearCommandBuffer();
    PacketResponseNG resp;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0};

    for (uint16_t i = 0; i < len; i++) {
        data[i] = i & 0xFF;
    }

    uint64_t tms = msclock();
    SendCommandNG(CMD_PING, data, len);
    if (WaitForResponseTimeout(CMD_PING, &resp, 1000)) {
        tms = msclock() - tms;
        if (len) {
            bool error = (memcmp(data, resp.data.asBytes, len) != 0);
            PrintAndLogEx((error) ? ERR : SUCCESS, "Ping response " _GREEN_("已接收")
                          " in " _YELLOW_("%" PRIu64) " ms and content ( %s )",
                          tms, error ? _RED_("fail") : _GREEN_("ok"));
        } else {
            PrintAndLogEx(SUCCESS, "Ping response " _GREEN_("已接收")
                          " in " _YELLOW_("%" PRIu64) " ms", tms);
        }
    } else
        PrintAndLogEx(WARNING, "Ping response " _RED_("timeout"));
    return PM3_SUCCESS;
}

static int CmdConnect(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 连接",
                  "通过指定串口连接到Proxmark3设备。\\n"
                  "Baudrate here is only for physical UART or UART-BT, NOT for USB-CDC or blue shark add-on",
                  "hw connect -p " SERIAL_PORT_EXAMPLE_H "\n"
                  "hw connect -p "SERIAL_PORT_EXAMPLE_H" -b 115200"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "port", "<str>", "要连接的串口，否则重试上次使用的串口"),
        arg_u64_0("b", "baud", "<dec>", "波特率"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    char port[FILE_PATH_SIZE] = {0};
    int p_len = sizeof(port) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated;
    CLIGetStrWithReturn(ctx, 1, (uint8_t *)port, &p_len);
    uint32_t baudrate = arg_get_u32_def(ctx, 2, USART_BAUD_RATE);
    CLIParserFree(ctx);

    if (baudrate == 0) {
        PrintAndLogEx(WARNING, "波特率不能为零");
        return PM3_EINVARG;
    }

    // default back to previous used serial port
    if (strlen(port) == 0) {
        if (strlen(g_conn.serial_port_name) == 0) {
            PrintAndLogEx(WARNING, "必须指定串口");
            return PM3_EINVARG;
        }
        memcpy(port, g_conn.serial_port_name, sizeof(port));
    }

    if (g_session.pm3_present) {
        CloseProxmark(g_session.current_device);
    }

    // 10 second timeout
    OpenProxmark(&g_session.current_device, port, false, 10, false, baudrate);

    if (g_session.pm3_present && (TestProxmark(g_session.current_device) != PM3_SUCCESS)) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " cannot communicate with the Proxmark3\n");
        CloseProxmark(g_session.current_device);
        return PM3_ENOTTY;
    }
    return PM3_SUCCESS;
}

static int CmdBreak(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 中断",
                  "发送中断循环包",
                  "hw break\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdBootloader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "硬件 引导加载程序",
                  "重启Proxmark3进入引导加载程序模式",
                  "hw bootloader\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    flash_reboot_bootloader(g_conn.serial_port_name, false);
    return PM3_SUCCESS;
}

int set_fpga_mode(uint8_t mode) {
    if (mode < FPGA_BITSTREAM_MIN || mode > FPGA_BITSTREAM_MAX) {
        return PM3_EINVARG;
    }
    uint8_t d[] = {mode};
    clearCommandBuffer();
    SendCommandNG(CMD_SET_FPGAMODE, d, sizeof(d));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SET_FPGAMODE, &resp, 1000) == false) {
        PrintAndLogEx(WARNING, "命令执行超时");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "设置FPGA模式失败");
    }
    return resp.status;
}

static command_t CommandTable[] = {
    {"help", CmdHelp, AlwaysAvailable, "此帮助"},
    {"-------------", CmdHelp, AlwaysAvailable, "----------------------- " _CYAN_("操作") " -----------------------"},
    {"detectreader", CmdDetectReader, IfPm3Present, "检测外部读卡器场"},
    {"status", CmdStatus, IfPm3Present, "显示已连接Proxmark3的运行时状态信息"},
    {"tearoff", CmdTearoff, IfPm3Present, "为下一个支持撕拉的命令编程撕拉钩子"},
    {"timeout", CmdTimeout, AlwaysAvailable, "设置客户端的通信超时"},
    {"version", CmdVersion, AlwaysAvailable, "显示客户端和Proxmark3的版本信息"},
    {"-------------", CmdHelp, AlwaysAvailable, "----------------------- " _CYAN_("硬件") " -----------------------"},
    {"break", CmdBreak, IfPm3Present, "发送中断循环USB命令"},
    {"bootloader", CmdBootloader, IfPm3Present, "重启进入引导加载程序模式"},
    {"connect", CmdConnect, AlwaysAvailable, "通过串口连接到设备"},
    {"dbg", CmdDbg, IfPm3Present, "设置设备端调试级别"},
    {"fpgaoff", CmdFPGAOff, IfPm3Present, "关闭设备上的FPGA"},
    {"lcd", CmdLCD, IfPm3Lcd, "向LCD发送命令/数据"},
    {"lcdreset", CmdLCDReset, IfPm3Lcd, "硬件复位LCD"},
    {"ping", CmdPing, IfPm3Present, "测试 Proxmark3 是否响应"},
    {"readmem", CmdReadmem, IfPm3Present, "从MCU闪存读取"},
    {"reset", CmdReset, IfPm3Present, "重置设备"},
    {"setlfdivisor", CmdSetDivisor, IfPm3Lf, "以12MHz/(除数+1)驱动低频天线"},
    {"sethfthresh", CmdSetHFThreshold, IfPm3Iso14443a, "设置HF/14a模式下的阈值"},
    {"setmux", CmdSetMux, IfPm3Present, "将ADC多路复用器设置为特定值"},
    {"standalone", CmdStandalone, IfPm3Present, "启动设备上已安装的独立模式"},
    {"tia", CmdTia, IfPm3Present, "触发定时间隔采集以重新调整实时计数器分频器"},
    {"tune", CmdTune, IfPm3Lf, "测量设备天线调谐"},
    {"decay", CmdDecay, IfPm3Present, "测量场关闭后 HF 天线衰减"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHW(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

#if defined(__MINGW64__)
#define PM3CLIENTCOMPILER "MinGW-w64 "
#elif defined(__MINGW32__)
#define PM3CLIENTCOMPILER "MinGW "
#elif defined(__clang__)
#define PM3CLIENTCOMPILER "Clang/LLVM "
#elif defined(__GNUC__) || defined(__GNUG__)
#define PM3CLIENTCOMPILER "GCC "
#else
#define PM3CLIENTCOMPILER "unknown compiler "
#endif

#if defined(__APPLE__) || defined(__MACH__)
#define PM3HOSTOS "OSX"
#elif defined(__ANDROID__) || defined(ANDROID)
// must be tested before __linux__
#define PM3HOSTOS "Android"
#elif defined(__linux__)
#define PM3HOSTOS "Linux"
#elif defined(__FreeBSD__)
#define PM3HOSTOS "FreeBSD"
#elif defined(__NetBSD__)
#define PM3HOSTOS "NetBSD"
#elif defined(__OpenBSD__)
#define PM3HOSTOS "OpenBSD"
#elif defined(__CYGWIN__)
#define PM3HOSTOS "Cygwin"
#elif defined(_WIN64) || defined(__WIN64__)
// must be tested before _WIN32
#define PM3HOSTOS "Windows (64b)"
#elif defined(_WIN32) || defined(__WIN32__)
#define PM3HOSTOS "Windows (32b)"
#else
#define PM3HOSTOS "unknown"
#endif

#if defined(__x86_64__)
#define PM3HOSTARCH "x86_64"
#elif defined(__i386__)
#define PM3HOSTARCH "x86"
#elif defined(__aarch64__)
#define PM3HOSTARCH "aarch64"
#elif defined(__arm__)
#define PM3HOSTARCH "arm"
#elif defined(__powerpc64__)
#define PM3HOSTARCH "powerpc64"
#elif defined(__mips__)
#define PM3HOSTARCH "mips"
#else
#define PM3HOSTARCH "unknown"
#endif

void pm3_version_short(void) {
    //    PrintAndLogEx(NORMAL, "  [ " _CYAN_("Proxmark3 RFID instrument") " ]");
    PrintAndLogEx(NORMAL, "  [ " _CYAN_(_URL_("https://github.com/RfidResearchGroup/proxmark3", "Proxmark3")) " ]");
    PrintAndLogEx(NORMAL, "");

    if (g_session.pm3_present) {

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_VERSION, NULL, 0);

        if (WaitForResponseTimeout(CMD_VERSION, &resp, 1000)) {

            struct p {
                uint32_t id;
                uint32_t section_size;
                uint32_t versionstr_len;
                char versionstr[PM3_CMD_DATA_SIZE - 12];
            } PACKED;

            struct p *payload = (struct p *)&resp.data.asBytes;

            lookup_chipid_short(payload->id, payload->section_size);

            if (IfPm3Rdv4Fw()) {

                // validate signature data
                rdv40_validation_t mem;
                signature_e type;

                if (pm3_get_signature(&mem) == PM3_SUCCESS) {
                    if (pm3_validate(&mem, &type) == PM3_SUCCESS) {

                        if (type == SIGN_RDV4) {
                            PrintAndLogEx(NORMAL, "    Target.... %s", _YELLOW_("RDV4"));
                        } else if (type == SIGN_GENERIC) {
                            PrintAndLogEx(NORMAL, "    Target.... %s", _YELLOW_("GENERIC"));
                        } else {
                            PrintAndLogEx(NORMAL, "    Target.... %s", _RED_("device / fw mismatch"));
                        }
                    }
                }
            } else {
                PrintAndLogEx(NORMAL, "    Target.... %s", _YELLOW_("PM3 GENERIC"));
            }
            PrintAndLogEx(NORMAL, "");

            // client
            char temp[PM3_CMD_DATA_SIZE - 12]; // same limit as for ARM image
            format_version_information_short(temp, sizeof(temp), &g_version_information);
            PrintAndLogEx(NORMAL, "    Client.... %s", temp);

            bool armsrc_mismatch = false;
            char *ptr = strstr(payload->versionstr, "OS......... ");
            if (ptr != NULL) {
                ptr = strstr(ptr, "\n");
                if ((ptr != NULL) && (strlen(g_version_information.armsrc) == 9)) {
                    if (strncmp(ptr - 9, g_version_information.armsrc, 9) != 0) {
                        armsrc_mismatch = true;
                    }
                }
            }

            // bootrom
            ptr = strstr(payload->versionstr, "Bootrom.... ");
            if (ptr != NULL) {
                char *ptr_end = strstr(ptr, "\n");
                if (ptr_end != NULL) {
                    uint8_t len = ptr_end - 12 - ptr;
                    PrintAndLogEx(NORMAL, "    Bootrom... %.*s", len, ptr + 12);
                }
            }

            // os:
            ptr = strstr(payload->versionstr, "OS......... ");
            if (ptr != NULL) {
                char *ptr_end = strstr(ptr, "\n");
                if (ptr_end != NULL) {
                    uint8_t len = ptr_end - 12 - ptr;
                    PrintAndLogEx(NORMAL, "    OS........ %.*s", len, ptr + 12);
                }
            }
            PrintAndLogEx(NORMAL, "");

            if (armsrc_mismatch) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(WARNING, " --> " _RED_("ARM firmware does not match the source at the time the client was compiled"));
                PrintAndLogEx(WARNING, " --> Make sure to flash a correct and up-to-date version");
            }
        }
    }
    PrintAndLogEx(NORMAL, "");
}

void pm3_version(bool verbose, bool oneliner) {

    char temp[PM3_CMD_DATA_SIZE - 12]; // same limit as for ARM image

    if (oneliner) {
        // For "proxmark3 -v", simple printf, avoid logging
        FormatVersionInformation(temp, sizeof(temp), "Client: ", &g_version_information);
        PrintAndLogEx(NORMAL, "%s compiler: " PM3CLIENTCOMPILER __VERSION__ " OS:" PM3HOSTOS " ARCH:" PM3HOSTARCH "\n", temp);
        return;
    }

    if (!verbose) {
        return;
    }

    PrintAndLogEx(NORMAL, "\n [ " _CYAN_("Proxmark3") " ]");
    PrintAndLogEx(NORMAL, "\n [ " _YELLOW_("Client") " ]");
    FormatVersionInformation(temp, sizeof(temp), "  ", &g_version_information);
    PrintAndLogEx(NORMAL, "%s", temp);
    PrintAndLogEx(NORMAL, "  Compiler.................. " PM3CLIENTCOMPILER __VERSION__);
    PrintAndLogEx(NORMAL, "  Platform.................. " PM3HOSTOS " / " PM3HOSTARCH);
#if defined(HAVE_READLINE)
    PrintAndLogEx(NORMAL, "  Readline support.......... " _GREEN_("present"));
#elif defined(HAVE_LINENOISE)
    PrintAndLogEx(NORMAL, "  Linenoise support......... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  Readline/Linenoise support." _YELLOW_("absent"));
#endif
#ifdef HAVE_GUI
    PrintAndLogEx(NORMAL, "  QT GUI support............ " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  QT GUI support............ " _YELLOW_("absent"));
#endif
#ifdef HAVE_BLUEZ
    PrintAndLogEx(NORMAL, "  Native BT support......... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  Native BT support......... " _YELLOW_("absent"));
#endif

#ifdef HAVE_PYTHON
#ifndef PY_VERSION
#define PY_VERSION "unknown version"
#endif
    PrintAndLogEx(NORMAL, "  Python script support..... " _GREEN_("present") " ( " _YELLOW_(PY_VERSION) " )");
#else
    PrintAndLogEx(NORMAL, "  Python script support..... " _YELLOW_("absent"));
#endif
#ifdef HAVE_PYTHON_SWIG
    PrintAndLogEx(NORMAL, "  Python SWIG support....... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  Python SWIG support....... " _YELLOW_("absent"));
#endif
    PrintAndLogEx(NORMAL, "  Lua script support........ " _GREEN_("present") " ( " _YELLOW_("%s.%s.%s") " )", LUA_VERSION_MAJOR, LUA_VERSION_MINOR, LUA_VERSION_RELEASE);
#ifdef HAVE_LUA_SWIG
    PrintAndLogEx(NORMAL, "  Lua SWIG support.......... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  Lua SWIG support.......... " _YELLOW_("absent"));
#endif

    if (g_session.pm3_present) {
        PrintAndLogEx(NORMAL, "\n [ " _YELLOW_("Model") " ]");

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_VERSION, NULL, 0);

        if (WaitForResponseTimeout(CMD_VERSION, &resp, 1000)) {
            if (IfPm3Rdv4Fw()) {

                // validate signature data
                rdv40_validation_t mem;
                signature_e type;

                if (pm3_get_signature(&mem) == PM3_SUCCESS) {
                    if (pm3_validate(&mem, &type) == PM3_SUCCESS) {

                        if (type == SIGN_RDV4) {
                            PrintAndLogEx(NORMAL, "  Device.................... " _GREEN_("RDV4"));
                            PrintAndLogEx(NORMAL, "  Firmware.................. " _GREEN_("RDV4"));
                        } else if (type == SIGN_GENERIC) {
                            PrintAndLogEx(NORMAL, "  Device.................... ", _GREEN_("GENERIC"));
                            PrintAndLogEx(NORMAL, "  Firmware.................. ", _GREEN_("GENERIC"));
                        } else {
                            PrintAndLogEx(NORMAL, "  Device.................... " _RED_("Bad signature detected!"));
                            PrintAndLogEx(NORMAL, "  Firmware.................. " _YELLOW_("N/A"));
                        }
                    }
                }

                PrintAndLogEx(NORMAL, "  External flash............ %s", IfPm3Flash() ? _GREEN_("present") : _YELLOW_("absent"));
                PrintAndLogEx(NORMAL, "  Smartcard reader.......... %s", IfPm3Smartcard() ? _GREEN_("present") : _YELLOW_("absent"));
                PrintAndLogEx(NORMAL, "  FPC USART for BT add-on... %s", IfPm3FpcUsartHost() ? _GREEN_("present") : _YELLOW_("absent"));
            } else {
                PrintAndLogEx(NORMAL, "  Firmware.................. %s", _YELLOW_("PM3 GENERIC"));
                if (IfPm3Flash()) {
                    PrintAndLogEx(NORMAL, "  External flash............ %s", _GREEN_("present"));
                }

                if (IfPm3FpcUsartHost()) {
                    PrintAndLogEx(NORMAL, "  FPC USART for BT add-on... %s", _GREEN_("present"));
                }
            }

            if (IfPm3FpcUsartDevFromUsb()) {
                PrintAndLogEx(NORMAL, "  FPC USART for developer... %s", _GREEN_("present"));
            }

            PrintAndLogEx(NORMAL, "");

            struct p {
                uint32_t id;
                uint32_t section_size;
                uint32_t versionstr_len;
                char versionstr[PM3_CMD_DATA_SIZE - 12];
            } PACKED;

            struct p *payload = (struct p *)&resp.data.asBytes;

            bool armsrc_mismatch = false;
            char *ptr = strstr(payload->versionstr, "OS......... ");
            if (ptr != NULL) {
                ptr = strstr(ptr, "\n");
                if ((ptr != NULL) && (strlen(g_version_information.armsrc) == 9)) {
                    if (strncmp(ptr - 9, g_version_information.armsrc, 9) != 0) {
                        armsrc_mismatch = true;
                    }
                }
            }
            PrintAndLogEx(NORMAL, payload->versionstr);
            if (strstr(payload->versionstr, FPGA_TYPE) == NULL) {
                PrintAndLogEx(NORMAL, "  FPGA firmware... %s", _RED_("chip mismatch"));
            }

            lookupChipID(payload->id, payload->section_size);
            if (armsrc_mismatch) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(WARNING, _RED_("ARM firmware does not match the source at the time the client was compiled"));
                PrintAndLogEx(WARNING, "请确保刷入正确且最新的版本");
            }
        }
    }
    PrintAndLogEx(NORMAL, "");
}
