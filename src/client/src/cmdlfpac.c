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
// Low frequency PAC/Stanley tag commands
// NRZ, RF/32, 128 bits long
//-----------------------------------------------------------------------------
#include "cmdlfpac.h"

#include <ctype.h>      // tolower
#include <string.h>
#include <stdlib.h>
#include "commonutil.h" // ARRAYLEN
#include "common.h"
#include "cmdparser.h"  // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"    // preamble test
#include "protocols.h"  // t55xx defines
#include "cmdlft55xx.h" // clone
#include "parity.h"
#include "cmdlfem4x05.h"   //
#include "cliparser.h"

// 8 bytes + null terminator
#define PAC_ID_LEN  (8 + 1)

static int CmdHelp(const char *Cmd);

// PAC_8byte format: preamble (8 mark/idle bits), ascii STX (02), ascii '2' (32), ascii '0' (30), ascii bytes 0..7 (cardid), then xor checksum of cardid bytes
// all bytes following 8 bit preamble are one start bit (0), 7 data bits (lsb first), odd parity bit, and one stop bit (1)
static int pac_buf_to_cardid(uint8_t *src, const size_t src_size, uint8_t *dst, const size_t dst_size) {
    const size_t byteLength = 10; // start bit, 7 data bits, parity bit, stop bit
    const size_t startIndex = 8 + (3 * byteLength) + 1; // skip 8 bits preamble, STX, '2', '0', and first start bit
    const size_t dataLength = 9;

    if (startIndex + byteLength * (dataLength - 1) > src_size) {
        PrintAndLogEx(DEBUG, "DEBUG: 错误 - PAC: 源缓冲区太小");
        return PM3_EOVFLOW;
    }
    if (dataLength > dst_size) {
        PrintAndLogEx(DEBUG, "DEBUG: 错误 - PAC: 目标缓冲区太小");
        return PM3_EOVFLOW;
    }

    uint8_t checksum = 0;
    for (size_t idx = 0; idx < dataLength; idx++) {
        uint8_t byte = (uint8_t)bytebits_to_byteLSBF(src + startIndex + (byteLength * idx), 8);
        dst[idx] = byte & 0x7F; // discard the parity bit
        if (oddparity8(dst[idx]) != (byte & 0x80) >> 7) {
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - PAC: 奇偶校验失败");
            return PM3_ESOFT;
        }
        if (idx < dataLength - 1) checksum ^= dst[idx];
    }
    if (dst[dataLength - 1] != checksum) {
        PrintAndLogEx(DEBUG, "DEBUG: 错误 - PAC: 校验和错误 - 期望: %02X, 实际: %02X", dst[dataLength - 1], checksum);
        return PM3_ESOFT;
    }

    // overwrite checksum byte with null terminator
    dst[dataLength - 1] = 0;

    return PM3_SUCCESS;
}

// convert a 16 byte array of raw demod data (FF204990XX...) to 8 bytes of PAC_8byte ID
// performs no parity or checksum validation
static void pac_raw_to_cardid(const uint8_t *src, uint8_t *dst) {
    for (int i = 4; i < 12; i++) {
        uint8_t shift = 7 - (i + 3) % 4 * 2;
        size_t index = i + (i - 1) / 4;

        dst[i - 4] = reflect8((((src[index] << 8) | (src[index + 1])) >> shift) & 0xFE);
    }
}

// convert 8 bytes of PAC_8byte ID to 16 byte array of raw data (FF204990XX...)
static void pac_cardid_to_raw(const char *src, uint8_t *dst) {
    uint8_t idbytes[10];

    // prepend PAC_8byte card type "20"
    idbytes[0] = '2';
    idbytes[1] = '0';
    for (size_t i = 0; i < 8; i++)
        idbytes[i + 2] = toupper(src[i]);

    // initialise array with start and stop bits
    for (size_t i = 0; i < 16; i++)
        dst[i] = 0x40 >> (i + 3) % 5 * 2;

    dst[0] = 0xFF; // mark + stop
    dst[1] = 0x20; // start + reflect8(STX)

    uint8_t checksum = 0;
    for (size_t i = 2; i < 13; i++) {
        uint8_t shift = 7 - (i + 3) % 4 * 2;
        uint8_t index = i + (i - 1) / 4;

        uint16_t pattern;
        if (i < 12) {
            pattern = reflect8(idbytes[i - 2]);
            pattern |= oddparity8(pattern);
            if (i > 3) checksum ^= idbytes[i - 2];
        } else {
            pattern = (reflect8(checksum) & 0xFE) | (oddparity8(checksum));
        }
        pattern <<= shift;

        dst[index] |= pattern >> 8 & 0xFF;
        dst[index + 1] |= pattern & 0xFF;
    }
}

//see NRZDemod for what args are accepted
int demodPac(bool verbose) {
    (void) verbose; // unused so far
    //NRZ
    if (NRZrawDemod(0, 0, 100, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: 错误 - PAC: NRZ 解调失败");
        return PM3_ESOFT;
    }
    bool invert = false;
    size_t size = g_DemodBufferLen;
    int ans = detectPac(g_DemodBuffer, &size, &invert);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - PAC: 找到的位数太少");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - PAC: 未找到前导码");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - PAC: 大小不正确: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - PAC: ans: %d", ans);

        return PM3_ESOFT;
    }

    if (invert) {
        for (size_t i = ans; i < ans + 128; i++) {
            g_DemodBuffer[i] ^= 1;
        }
    }
    setDemodBuff(g_DemodBuffer, 128, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(g_DemodBuffer + 64, 32);
    uint32_t raw4 = bytebits_to_byte(g_DemodBuffer + 96, 32);

    // 8 bytes + null terminator
    uint8_t cardid[PAC_ID_LEN];
    int retval = pac_buf_to_cardid(g_DemodBuffer, g_DemodBufferLen, cardid, sizeof(cardid));

    if (retval == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "PAC/Stanley - Card: " _GREEN_("%s") ", Raw: %08X%08X%08X%08X", cardid, raw1, raw2, raw3, raw4);
    }

    return retval;
}

static int CmdPacDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频PAC解调",
                  "尝试查找PAC/Stanley前导码，如果找到则解码/解扰数据",
                  "低频PAC解调"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodPac(true);
}

static int CmdPacReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频PAC读取器",
                  "读取 PAC/Stanley 标签",
                  "lf pac reader -@   -> continuous reader mode"
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
        lf_read(false, 4096 * 2 + 20);
        demodPac(!cm);
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

static int CmdPacClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频PAC克隆",
                  "将 PAC/Stanley 标签克隆到 T55x7、Q5/T5555 或 EM4305/4469 标签。",
                  "lf pac clone --cn CD4F5552           -> encode for T55x7 tag\n"
                  "lf pac clone --cn CD4F5552 --q5      -> encode for Q5/T5555 tag\n"
                  "lf pac clone --cn CD4F5552 --em      -> encode for EM4305/4469\n"
                  "lf pac clone --raw FF2049906D8511C593155B56D5B2649F -> encode for T55x7 tag, raw mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "cn", "<dec>", "8 byte PAC/Stanley card ID"),
        arg_str0("r", "raw", "<hex>", "原始十六进制数据，最多16字节"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t cnstr[10] = {0};
    int cnlen = sizeof(cnstr) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
    memset(cnstr, 0x00, sizeof(cnstr));
    CLIGetStrWithReturn(ctx, 1, cnstr, &cnlen);

    // skip first block,  4*4 = 16 bytes left
    int raw_len = 0;
    uint8_t raw[16] = {0};
    CLIGetHexWithReturn(ctx, 2, raw, &raw_len);

    bool q5 = arg_get_lit(ctx, 3);
    bool em = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "不能同时指定Q5和EM4305");
        return PM3_EINVARG;
    }
    if (cnlen && raw_len) {
        PrintAndLogEx(FAILED, "不能同时指定CardID和原始十六进制");
        return PM3_EINVARG;
    }

    if (cnlen && cnlen < 8) {
        PrintAndLogEx(FAILED, "卡片 ID 必须是 8 或 9 个十六进制数字 (%d)", cnlen);
        return PM3_EINVARG;
    }

    if (cnlen == 8 || cnlen == 9) {
        pac_cardid_to_raw((char *)cnstr, raw);
    } else {
        pac_raw_to_cardid(raw, cnstr);
    }

    uint32_t blocks[5];
    for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
        blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
    }

    // Pac - compat mode, NRZ, data rate 32, 3 data blocks
    blocks[0] = T55x7_MODULATION_DIRECT | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT;
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_DIRECT | T5555_SET_BITRATE(32) | 4 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_PAC_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    PrintAndLogEx(INFO, "Preparing to clone PAC/Stanley tag to " _YELLOW_("%s") " with ID " _GREEN_("%s")  " raw " _GREEN_("%s")
                  , cardtype
                  , cnstr
                  , sprint_hex_inrow(raw, sizeof(raw))
                 );

    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "完成！");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf pac reader`") " to verify");
    return res;
}

static int CmdPacSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频PAC模拟",
                  "启用对指定卡号的 PAC/Stanley 卡的模拟。\\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n"
                  "The card ID is 8 byte number. Larger values are truncated.",
                  "lf pac sim --cn CD4F5552\n"
                  "lf pac sim --raw FF2049906D8511C593155B56D5B2649F"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "cn", "<dec>", "8 byte PAC/Stanley card ID"),
        arg_str0("r", "raw", "<hex>", "原始十六进制数据，最多16字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t cnstr[10];
    int cnlen = sizeof(cnstr) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
    memset(cnstr, 0x00, sizeof(cnstr));
    CLIGetStrWithReturn(ctx, 1, cnstr, &cnlen);

    // skip first block,  4*4 = 16 bytes left
    int raw_len = 0;
    uint8_t raw[16] = {0};
    CLIGetHexWithReturn(ctx, 2, raw, &raw_len);
    CLIParserFree(ctx);

    if (cnlen && raw_len) {
        PrintAndLogEx(FAILED, "不能同时指定CardID和原始十六进制");
        return PM3_EINVARG;
    }

    if (cnlen && cnlen < 8) {
        PrintAndLogEx(FAILED, "卡片 ID 必须是 8 或 9 个十六进制数字 (%d)", cnlen);
        return PM3_EINVARG;
    }

    if (cnlen == 8 || cnlen == 9) {
        pac_cardid_to_raw((char *)cnstr, raw);
    } else {
        pac_raw_to_cardid(raw, cnstr);
    }

    uint8_t bs[128];
    for (size_t i = 0; i < 4; i++) {
        uint32_t tmp = bytes_to_num(raw + (i * sizeof(uint32_t)), sizeof(uint32_t));
        num_to_bytebits(tmp, sizeof(uint32_t) * 8, bs + (i * sizeof(uint32_t) * 8));
    }

    PrintAndLogEx(SUCCESS, "Simulating PAC/Stanley - ID " _YELLOW_("%s")" raw " _YELLOW_("%s")
                  , cnstr
                  , sprint_hex_inrow(raw, sizeof(raw))
                 );

    // NRZ sim.
    lf_nrzsim_t *payload = calloc(1, sizeof(lf_nrzsim_t) + sizeof(bs));
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }
    payload->invert = 0;
    payload->separator = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_NRZ_SIMULATE, (uint8_t *)payload,  sizeof(lf_nrzsim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_NRZ_SIMULATE, &resp);

    PrintAndLogEx(INFO, "完成！");
    if (resp.status != PM3_EOPABORTED) {
        return resp.status;
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,        AlwaysAvailable, "此帮助"},
    {"demod", CmdPacDemod,    AlwaysAvailable, "从 GraphBuffer 解调 PAC 标签"},
    {"reader",  CmdPacReader, IfPm3Lf,         "尝试读取并提取标签数据"},
    {"clone", CmdPacClone,    IfPm3Lf,         "克隆 PAC 标签到 T55x7、Q5/T5555 或 EM4305/4469"},
    {"sim",   CmdPacSim,      IfPm3Lf,         "模拟PAC标签"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFPac(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find PAC preamble in already demoded data
int detectPac(uint8_t *dest, size_t *size, bool *invert) {
    // make sure buffer has data
    if (*size < 128)
        return -1;

    size_t startIdx = 0;
    uint8_t preamble[] = {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx)) {

        // preamble not found
        uint8_t pre_inv[] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1};
        if (!preambleSearch(dest, pre_inv, sizeof(pre_inv), size, &startIdx)) {
            return -2;
        } else {
            *invert = true;
        }
    }

    // wrong demoded size
    if (*size != 128)
        return -3;

    // return start position
    return (int)startIdx;
}


