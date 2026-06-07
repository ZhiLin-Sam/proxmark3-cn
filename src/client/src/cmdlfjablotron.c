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
// Low frequency Jablotron tag commands
// Differential Biphase, RF/64, 64 bits long (complete)
//-----------------------------------------------------------------------------

#include "cmdlfjablotron.h"
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <ctype.h>
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h"   // ARRAYLEN
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"    // for T55xx config register definitions
#include "lfdemod.h"      // parityTest
#include "cmdlft55xx.h"   // verifywrite
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM defines

#define JABLOTRON_ARR_LEN 64

static int CmdHelp(const char *Cmd);

static uint8_t jablontron_chksum(uint8_t *bits) {
    uint8_t chksum = 0;
    for (int i = 16; i < 56; i += 8) {
        chksum += bytebits_to_byte(bits + i, 8);
    }
    chksum ^= 0x3A;
    return chksum;
}

static uint64_t getJablontronCardId(uint64_t rawcode) {
    uint64_t id = 0;
    uint8_t bytes[] = {0, 0, 0, 0, 0};
    num_to_bytes(rawcode, 5, bytes);
    for (int i = 0; i < 5; i++) {
        id *= 100;
        id += NIBBLE_HIGH(bytes[i]) * 10 + NIBBLE_LOW(bytes[i]);
    }
    return id;
}

int demodJablotron(bool verbose) {
    (void) verbose; // unused so far
    //Differential Biphase / di-phase (inverted biphase)
    //get binary from ask wave
    if (ASKbiphaseDemod(0, 64, 1, 0, false) != PM3_SUCCESS) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: 错误 - Jablotron ASK 双相解调失败");
        return PM3_ESOFT;
    }
    size_t size = g_DemodBufferLen;
    int ans = detectJablotron(g_DemodBuffer, &size);
    if (ans < 0) {
        if (g_debugMode) {
            if (ans == -1)
                PrintAndLogEx(DEBUG, "DEBUG: 错误 - Jablotron: 找到的比特太少");
            else if (ans == -2)
                PrintAndLogEx(DEBUG, "DEBUG: 错误 - Jablotron: 未找到前导码");
            else if (ans == -3)
                PrintAndLogEx(DEBUG, "DEBUG: 错误 - Jablotron: 大小不正确: %zu", size);
            else if (ans == -5)
                PrintAndLogEx(DEBUG, "DEBUG: 错误 - Jablotron 校验和失败");
            else
                PrintAndLogEx(DEBUG, "DEBUG: 错误 - Jablotron 应答: %d", ans);
        }
        return PM3_ESOFT;
    }

    setDemodBuff(g_DemodBuffer, JABLOTRON_ARR_LEN, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);

    // bytebits_to_byte - uint32_t
    uint64_t rawid = ((uint64_t)(bytebits_to_byte(g_DemodBuffer + 16, 8) & 0xff) << 32) | bytebits_to_byte(g_DemodBuffer + 24, 32);
    uint64_t id = getJablontronCardId(rawid);

    PrintAndLogEx(SUCCESS, "Jablotron - Card: " _GREEN_("%"PRIx64) ", Raw: %08X%08X", id, raw1, raw2);

    uint8_t chksum = raw2 & 0xFF;
    bool isok = (chksum == jablontron_chksum(g_DemodBuffer));

    PrintAndLogEx(DEBUG, "校验和: %02X ( %s )", chksum, isok ? _GREEN_("ok") : _RED_("Fail"));

    id = DEC2BCD(id);
    // Printed format: 1410-nn-nnnn-nnnn
    PrintAndLogEx(SUCCESS, "Printed: " _GREEN_("1410-%02X-%04X-%04X"),
                  (uint8_t)(id >> 32) & 0xFF,
                  (uint16_t)(id >> 16) & 0xFFFF,
                  (uint16_t)id & 0xFFFF
                 );
    return PM3_SUCCESS;
}

//see ASKDemod for what args are accepted
static int CmdJablotronDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频 Jablotron 解调",
                  "尝试查找Jablotron前导码，如果找到则解码/解扰数据",
                  "lf jablotron demod\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodJablotron(true);
}

static int CmdJablotronReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频 Jablotron 读取",
                  "读取 jablotron 标签",
                  "lf jablotron reader -@   -> continuous reader mode"
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
        lf_read(false, 16000);
        demodJablotron(!cm);
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

static int CmdJablotronClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频 Jablotron 克隆",
                  "将 Jablotron 标签克隆到 T55x7、Q5/T5555 或 EM4305/4469 标签。\\n"
                  "Tag must be on the antenna when issuing this command.",
                  "lf jablotron clone --cn 01b669      -> encode for T55x7 tag\n"
                  "lf jablotron clone --cn 01b669 --q5 -> encode for Q5/T5555 tag\n"
                  "lf jablotron clone --cn 01b669 --em -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "cn", "<hex>", "Jablotron card ID - 5 bytes max"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[5] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "不能同时指定Q5和EM4305");
        return PM3_EINVARG;
    }

    uint32_t blocks[3] = {T55x7_MODULATION_DIPHASE | T55x7_BITRATE_RF_64 | 2 << T55x7_MAXBLOCK_SHIFT, 0, 0};
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(64) | 2 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_JABLOTRON_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }


    uint64_t fullcode = bytes_to_num(raw, raw_len);

    // clearing the topbit needed for the preambl detection.
    if ((fullcode & 0x7FFFFFFFFF) != fullcode) {
        fullcode &= 0x7FFFFFFFFF;
        PrintAndLogEx(INFO, "卡片号截断为39位: %"PRIx64, fullcode);
    }

    uint8_t *bits = calloc(JABLOTRON_ARR_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    if (getJablotronBits(fullcode, bits) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "标签比特流生成错误。");
        return PM3_ESOFT;
    }

    blocks[1] = bytebits_to_byte(bits, 32);
    blocks[2] = bytebits_to_byte(bits + 32, 32);

    free(bits);

    uint64_t id = getJablontronCardId(fullcode);

    PrintAndLogEx(INFO, "Preparing to clone Jablotron to " _YELLOW_("%s") " with FullCode: " _GREEN_("%"PRIx64)"  id: " _GREEN_("%"PRIx64), cardtype, fullcode, id);
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "完成！");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf jablotron reader`") " to verify");
    return res;
}

static int CmdJablotronSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频 Jablotron 模拟",
                  "启用对指定卡号的 jablotron 卡的模拟。\\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf jablotron sim --cn 01b669"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "cn", "<hex>", "Jablotron card ID - 5 bytes max"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[5] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);
    CLIParserFree(ctx);

    uint64_t fullcode = bytes_to_num(raw, raw_len);

    // clearing the topbit needed for the preambl detection.
    if ((fullcode & 0x7FFFFFFFFF) != fullcode) {
        fullcode &= 0x7FFFFFFFFF;
        PrintAndLogEx(INFO, "卡片号截断为39位: %"PRIx64, fullcode);
    }

    PrintAndLogEx(SUCCESS, "Simulating Jablotron - FullCode: " _YELLOW_("%"PRIx64), fullcode);

    uint8_t *bs = calloc(JABLOTRON_ARR_LEN, sizeof(uint8_t));
    if (bs == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    getJablotronBits(fullcode, bs);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + JABLOTRON_ARR_LEN);
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        free(bs);
        return PM3_EMALLOC;
    }
    payload->encoding =  2;
    payload->invert = 1;
    payload->separator = 0;
    payload->clock = 64;
    memcpy(payload->data, bs, JABLOTRON_ARR_LEN);

    free(bs);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + JABLOTRON_ARR_LEN);
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
    {"demod",   CmdJablotronDemod,  AlwaysAvailable, "从GraphBuffer解调Jablotron标签"},
    {"reader",  CmdJablotronReader, IfPm3Lf,         "尝试读取并提取标签数据"},
    {"clone",   CmdJablotronClone,  IfPm3Lf,         "克隆 jablotron 标签到 T55x7、Q5/T5555 或 EM4305/4469"},
    {"sim",     CmdJablotronSim,    IfPm3Lf,         "模拟jablotron标签"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFJablotron(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int getJablotronBits(uint64_t fullcode, uint8_t *bits) {
    //preamp
    num_to_bytebits(0xFFFF, 16, bits);

    //fullcode
    num_to_bytebits(fullcode, 40, bits + 16);

    //chksum byte
    uint8_t chksum = jablontron_chksum(bits);
    num_to_bytebits(chksum, 8, bits + 56);
    return PM3_SUCCESS;
}

// ASK/Diphase fc/64 (inverted Biphase)
// Note: this is not a demod, this is only a detection
// the parameter *bits needs to be demoded before call
// 0xFFFF preamble, 64bits
int detectJablotron(uint8_t *bits, size_t *size) {
    if (*size < JABLOTRON_ARR_LEN * 2) return -1; //make sure buffer has enough data
    size_t startIdx = 0;
    uint8_t preamble[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};
    if (preambleSearch(bits, preamble, sizeof(preamble), size, &startIdx) == 0)
        return -2; //preamble not found
    if (*size != JABLOTRON_ARR_LEN) return -3; // wrong demoded size

    uint8_t checkchksum = jablontron_chksum(bits + startIdx);
    uint8_t crc = bytebits_to_byte(bits + startIdx + 56, 8);
    if (checkchksum != crc) return -5;
    return (int)startIdx;
}

