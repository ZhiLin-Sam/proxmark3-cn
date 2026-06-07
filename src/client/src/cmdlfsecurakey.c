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
// Low frequency Securakey tag commands
// ASK/Manchester, RF/40, 96 bits long (unknown cs)
//-----------------------------------------------------------------------------
#include "cmdlfsecurakey.h"
#include <string.h>       // memcpy
#include <ctype.h>        // tolower
#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"      // preamble test
#include "parity.h"       // for wiegand parity test
#include "protocols.h"    // t55xx defines
#include "cmdlft55xx.h"   // clone..
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM defines

static int CmdHelp(const char *Cmd);

//see ASKDemod for what args are accepted
int demodSecurakey(bool verbose) {
    (void) verbose; // unused so far

    //ASK / Manchester
    bool st = false;
    if (ASKDemod_ext(40, 0, 0, 0, false, false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: 错误 - Securakey: ASK/曼彻斯特解调失败");
        return PM3_ESOFT;
    }
    if (st)
        return PM3_ESOFT;

    size_t size = g_DemodBufferLen;
    int ans = detectSecurakey(g_DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - Securakey: 找到的比特数太少");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - Securakey: 未找到前导码");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - Securakey: 大小不正确: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - Securakey: 应答: %d", ans);
        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(g_DemodBuffer + 64, 32);

    // 26 bit format
    // preamble     ??bitlen   reserved        EPx   xxxxxxxy   yyyyyyyy   yyyyyyyOP  CS?        CS2?
    // 0111111111 0 01011010 0 00000000 0 00000010 0 00110110 0 00111110 0 01100010 0 00001111 0 01100000 0 00000000 0 0000

    // 32 bit format
    // preamble     ??bitlen   reserved  EPxxxxxxx   xxxxxxxy   yyyyyyyy   yyyyyyyOP  CS?        CS2?
    // 0111111111 0 01100000 0 00000000 0 10000100 0 11001010 0 01011011 0 01010110 0 00010110 0 11100000 0 00000000 0 0000

    // x = FC?
    // y = card #
    // standard wiegand parities.
    // unknown checksum 11 bits? at the end
    uint8_t bits_no_spacer[85];
    memcpy(bits_no_spacer, g_DemodBuffer + 11, 85);

    // remove marker bits (0's every 9th digit after preamble) (pType = 3 (always 0s))
    size = removeParity(bits_no_spacer, 0, 9, 3, 85);
    if (size != 85 - 9) {
        PrintAndLogEx(DEBUG, "DEBUG: 错误 移除奇偶校验: %zu", size);
        return 0;
    }

    uint8_t bitLen = (uint8_t)bytebits_to_byte(bits_no_spacer + 2, 6);
    uint32_t fc = 0, lWiegand = 0, rWiegand = 0;
    if (bitLen > 40) { //securakey's max bitlen is 40 bits...
        PrintAndLogEx(DEBUG, "DEBUG: 错误 比特长度过长: %u", bitLen);
        return PM3_ESOFT;
    }
    // get left 1/2 wiegand & right 1/2 wiegand (for parity test and wiegand print)
    lWiegand = bytebits_to_byte(bits_no_spacer + 48 - bitLen, bitLen / 2);
    rWiegand = bytebits_to_byte(bits_no_spacer + 48 - bitLen + bitLen / 2, bitLen / 2);
    // get FC
    fc = bytebits_to_byte(bits_no_spacer + 49 - bitLen, bitLen - 2 - 16);

    // test bitLen
    if (bitLen != 26 && bitLen != 32)
        PrintAndLogEx(NORMAL, "***未知 securakey 位长度 - 请分享到论坛***");

    uint32_t cardid = bytebits_to_byte(bits_no_spacer + 8 + 23, 16);
    // test parities - evenparity32 looks to add an even parity returns 0 if already even...
    bool parity = !evenparity32(lWiegand) && !oddparity32(rWiegand);

    PrintAndLogEx(SUCCESS, "Securakey - len: " _GREEN_("%u") " FC: " _GREEN_("0x%X")" Card: " _GREEN_("%u") ", Raw: %08X%08X%08X", bitLen, fc, cardid, raw1, raw2, raw3);
    if (bitLen <= 32)
        PrintAndLogEx(SUCCESS, "Wiegand: " _GREEN_("%08X") " parity ( %s )", (lWiegand << (bitLen / 2)) | rWiegand, parity ? _GREEN_("ok") : _RED_("fail"));

    if (verbose) {
        PrintAndLogEx(INFO, "\\nFC如何转换为打印的FC未知");
        PrintAndLogEx(INFO, "校验和的计算方式未知");
        PrintAndLogEx(INFO, "通过在 pm3 论坛或 discord 上分享您的标签，帮助社区进一步识别此格式");
    }
    return PM3_SUCCESS;
}

static int CmdSecurakeyDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频Securakey解调",
                  "尝试查找Securakey前导码，如果找到则解码/解扰数据",
                  "低频Securakey解调"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodSecurakey(true);
}

static int CmdSecurakeyReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频Securakey读取器",
                  "读取 Securakey 标签",
                  "lf securakey reader -@   -> continuous reader mode"
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
        lf_read(false, 8000);
        demodSecurakey(!cm);
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

static int CmdSecurakeyClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频Securakey克隆",
                  "将 Securakey 标签克隆到 T55x7、Q5/T5555 或 EM4305/4469 标签。",
                  "lf securakey clone --raw 7FCB400001ADEA5344300000      -> encode for T55x7 tag\n"
                  "lf securakey clone --raw 7FCB400001ADEA5344300000 --q5 -> encode for Q5/T5555 tag\n"
                  "lf securakey clone --raw 7FCB400001ADEA5344300000 --em -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("r", "raw", "<hex>", "原始十六进制数据，12字节"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);
    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "不能同时指定Q5和EM4305");
        return PM3_EINVARG;
    }

    if (raw_len != 12) {
        PrintAndLogEx(ERR, "Data must be 12 bytes (24 HEX characters)  %d", raw_len);
        return PM3_EINVARG;
    }

    uint32_t blocks[4];
    for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
        blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
    }

    //Securakey - compat mode, ASK/Man, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_40 | 3 << T55x7_MAXBLOCK_SHIFT;
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(40) | T5555_ST_TERMINATOR | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_SECURAKEY_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    PrintAndLogEx(INFO, "Preparing to clone Securakey to " _YELLOW_("%s") "  with raw hex", cardtype);
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "完成！");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf securakey reader`") " to verify");
    return res;
}

static int CmdSecurakeySim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频Securakey模拟",
                  "启用对指定卡号的 secura 卡的模拟。\\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf securakey sim --raw 7FCB400001ADEA5344300000"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", " raw hex data. 12 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);
    CLIParserFree(ctx);

    if (raw_len != 12) {
        PrintAndLogEx(ERR, "Data must be 12 bytes (24 HEX characters)  %d", raw_len);
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Simulating SecuraKey - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, sizeof(raw)));

    uint8_t bs[sizeof(raw) * 8];
    bytes_to_bytebits(raw, sizeof(raw), bs);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }
    payload->encoding = 1;
    payload->invert = 0;
    payload->separator = 0;
    payload->clock = 40;
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
    {"help",    CmdHelp,            AlwaysAvailable, "此帮助"},
    {"demod",   CmdSecurakeyDemod,  AlwaysAvailable, "从GraphBuffer解调Securakey标签"},
    {"reader",  CmdSecurakeyReader, IfPm3Lf,         "尝试读取并提取标签数据"},
    {"clone",   CmdSecurakeyClone,  IfPm3Lf,         "克隆 Securakey 标签到 T55x7、Q5/T5555 或 EM4305/4469"},
    {"sim",     CmdSecurakeySim,    IfPm3Lf,         "模拟Securakey标签"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFSecurakey(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// by marshmellow
// find Securakey preamble in already demoded data
int detectSecurakey(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 96) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

