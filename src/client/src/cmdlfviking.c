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
// Low frequency Viking tag commands (AKA FDI Matalec Transit)
// ASK/Manchester, RF/32, 64 bits (complete)
//-----------------------------------------------------------------------------
#include "cmdlfviking.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "common.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "commonutil.h"     // num_to_bytes
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

//see ASKDemod for what args are accepted
int demodViking(bool verbose) {
    (void) verbose; // unused so far

    bool st = false;
    if (ASKDemod_ext(0, 0, 100, 0, false, false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: 错误 - Viking ASK 解调失败");
        return PM3_ESOFT;
    }

    size_t size = g_DemodBufferLen;
    int ans = detectViking(g_DemodBuffer, &size);
    if (ans < 0) {
        PrintAndLogEx(DEBUG, "DEBUG: 错误 - Viking 解调 %d %s", ans, (ans == -5) ? _RED_("[chksum error]") : "");
        return PM3_ESOFT;
    }

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer + ans, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + ans + 32, 32);
    uint32_t cardid = bytebits_to_byte(g_DemodBuffer + ans + 24, 32);
    uint8_t  checksum = bytebits_to_byte(g_DemodBuffer + ans + 32 + 24, 8);
    PrintAndLogEx(SUCCESS, "Viking - Card " _GREEN_("%08X") ", Raw: %08X%08X", cardid, raw1, raw2);
    PrintAndLogEx(DEBUG, "校验和: %02X", checksum);
    setDemodBuff(g_DemodBuffer, 64, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));
    return PM3_SUCCESS;
}

static int CmdVikingDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频Viking解调",
                  "尝试查找Viking AM前导码，如果找到则解码/解扰数据",
                  "低频Viking解调"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodViking(true);
}

//see ASKDemod for what args are accepted
static int CmdVikingReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频维京读取器",
                  "读取 Viking AM 标签",
                  "lf viking reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        lf_read(false, 10000);
        demodViking(true);
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

static int CmdVikingClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频Viking克隆",
                  "将 Viking AM 标签克隆到 T55x7、Q5/T5555 或 EM4305/4469 标签。",
                  "lf viking clone --cn 01A337        -> encode for T55x7 tag\n"
                  "lf viking clone --cn 01A337 --q5   -> encode for Q5/T5555 tag\n"
                  "lf viking clone --cn 112233 --em   -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "cn", "<hex>", "8 digit hex viking card number"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[4] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);
    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    uint32_t id = bytes_to_num(raw, raw_len);
    if (id == 0) {
        PrintAndLogEx(ERR, "卡号不能为零");
        return PM3_EINVARG;
    }

    if (q5 && em) {
        PrintAndLogEx(FAILED, "不能同时指定Q5和EM4305");
        return PM3_EINVARG;
    }

    uint64_t rawID = getVikingBits(id);

    struct p {
        bool Q5;
        bool EM;
        uint8_t blocks[8];
    } PACKED payload;
    payload.Q5 = q5;
    payload.EM = em;

    num_to_bytes(rawID, 8, &payload.blocks[0]);

    char cardtype[16] = {"T55x7"};
    if (q5)
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    else if (em)
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");

    PrintAndLogEx(INFO, "Preparing to clone Viking tag on " _YELLOW_("%s") " - ID " _YELLOW_("%08X")" raw " _YELLOW_("%s")
                  , cardtype
                  , id
                  , sprint_hex(payload.blocks, sizeof(payload.blocks))
                 );

    clearCommandBuffer();

    SendCommandNG(CMD_LF_VIKING_CLONE, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_VIKING_CLONE, &resp, T55XX_WRITE_TIMEOUT) == false) {
        PrintAndLogEx(ERR, "发生错误，设备在写操作期间无响应。");
        return PM3_ETIMEOUT;
    }
    PrintAndLogEx(SUCCESS, "完成！");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf viking reader`") " to verify");
    return resp.status;
}

static int CmdVikingSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频维京模拟",
                  "启用模拟指定卡号的维京卡。\\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n"
                  "Per viking format, the card number is 8 digit hex number.  Larger values are truncated.",
                  "lf viking sim --cn 01A337"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "cn", "<hex>", "8 digit hex viking card number"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[4] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    uint32_t id = bytes_to_num(raw, raw_len);
    if (id == 0) {
        PrintAndLogEx(ERR, "卡号不能为零");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);

    uint64_t rawID = getVikingBits(id);

    PrintAndLogEx(SUCCESS, "Simulating Viking - ID " _YELLOW_("%08X") " raw " _YELLOW_("%08X%08X"), id, (uint32_t)(rawID >> 32), (uint32_t)(rawID & 0xFFFFFFFF));

    uint8_t bs[64];
    num_to_bytebits(rawID, sizeof(bs), bs);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }
    payload->encoding = 1;
    payload->invert = 0;
    payload->separator = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_ASK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "完成！");
    if (resp.status != PM3_EOPABORTED) {
        return resp.status;
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "此帮助"},
    {"demod",   CmdVikingDemod, AlwaysAvailable, "从 GraphBuffer 解调 Viking 标签"},
    {"reader",  CmdVikingReader,  IfPm3Lf,       "尝试读取并提取标签数据"},
    {"clone",   CmdVikingClone, IfPm3Lf,         "克隆 Viking 标签到 T55x7、Q5/T5555 或 EM4305/4469"},
    {"sim",     CmdVikingSim,   IfPm3Lf,         "模拟Viking标签"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFViking(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// calc checksum
uint64_t getVikingBits(uint32_t id) {
    uint8_t checksum = ((id >> 24) & 0xFF) ^ ((id >> 16) & 0xFF) ^ ((id >> 8) & 0xFF) ^ (id & 0xFF) ^ 0xF2 ^ 0xA8;
    uint64_t ret = (uint64_t)0xF2 << 56;
    ret |= (uint64_t)id << 8;
    ret |= checksum;
    return ret;
}

static bool isValidVikingChecksum(uint8_t *src) {
    uint32_t checkCalc = bytebits_to_byte(src, 8) ^
                         bytebits_to_byte(src + 8, 8) ^
                         bytebits_to_byte(src + 16, 8) ^
                         bytebits_to_byte(src + 24, 8) ^
                         bytebits_to_byte(src + 32, 8) ^
                         bytebits_to_byte(src + 40, 8) ^
                         bytebits_to_byte(src + 48, 8) ^
                         bytebits_to_byte(src + 56, 8) ^
                         0xA8;
    return checkCalc == 0;
}

// find viking preamble 0xF200 in already demoded data
int detectViking(uint8_t *src, size_t *size) {
    //make sure buffer has data
    if (*size < 64) return -2;
    size_t tsize = *size;
    size_t startIdx = 0;
    bool preamblefound = false;
    uint8_t preamble[] = {1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (preambleSearch(src, preamble, sizeof(preamble), size, &startIdx)) {
        preamblefound = true;
        if (*size != 64) return -6;
        if (isValidVikingChecksum(src + startIdx)) {
            //return start position
            return (int)startIdx;
        }
    }
    // Invert bits and try again
    *size = tsize;
    for (uint32_t i = 0; i < *size; i++) src[i] ^= 1;
    if (preambleSearch(src, preamble, sizeof(preamble), size, &startIdx)) {
        preamblefound = true;
        if (*size != 64) return -6;
        if (isValidVikingChecksum(src + startIdx)) {
            //return start position
            return (int)startIdx;
        }
    }
    // Restore buffer
    *size = tsize;
    for (uint32_t i = 0; i < *size; i++) src[i] ^= 1;
    if (preamblefound)
        return -5;
    else
        return -4;
}
