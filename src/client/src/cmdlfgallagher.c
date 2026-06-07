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
// Low frequency GALLAGHER tag commands
// ASK/MAN, RF/32, 96 bits long (unknown cs) (0x00088060)
// sample Q5 ,  ASK RF/32, STT,  96 bits  (3blocks)   ( 0x9000F006)
//-----------------------------------------------------------------------------

#include "cmdlfgallagher.h"
#include "mifare/gallaghercore.h"
#include <string.h>        // memcpy
#include <ctype.h>         // tolower
#include <stdio.h>
#include "commonutil.h"    // ARRAYLEN
#include "common.h"
#include "cmdparser.h"     // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"       // preamble test
#include "protocols.h"     // t55xx defines
#include "cmdlft55xx.h"    // clone..
#include "crc.h"           // CRC8/Cardx
#include "cmdlfem4x05.h"   //
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

//see ASK/MAN Demod for what args are accepted
int demodGallagher(bool verbose) {
    (void) verbose; // unused so far
    bool st = true;
    if (ASKDemod_ext(32, 0, 100, 0, false, false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: 错误 - GALLAGHER: ASK解调失败");
        return PM3_ESOFT;
    }

    size_t size = g_DemodBufferLen;
    int ans = detectGallagher(g_DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - GALLAGHER: 找到的比特太少");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - GALLAGHER: 前导码未找到");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - GALLAGHER: 大小不正确: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: 错误 - GALLAGHER: 答案: %d", ans);

        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    // got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(g_DemodBuffer + 64, 32);

    // bytes
    uint8_t arr[8] = {0};
    for (int i = 0, pos = 0; i < ARRAYLEN(arr); i++) {
        // first 16 bits are the 7FEA prefix, then every 9th bit is a checksum-bit for the preceding byte
        pos = 16 + (9 * i);
        arr[i] = bytebits_to_byte(g_DemodBuffer + pos, 8);
    }

    // crc
    uint8_t crc = bytebits_to_byte(g_DemodBuffer + 16 + (9 * 8), 8);
    uint8_t calc_crc =  CRC8Cardx(arr, ARRAYLEN(arr));

    GallagherCredentials_t creds = {0};
    gallagher_decode_creds(arr, &creds);

    PrintAndLogEx(SUCCESS, "GALLAGHER - Region: " _GREEN_("%u") " Facility: " _GREEN_("%u") " Card No.: " _GREEN_("%u") " Issue Level: " _GREEN_("%u"),
                  creds.region_code, creds.facility_code, creds.card_number, creds.issue_level);
    PrintAndLogEx(SUCCESS, "   Displayed: " _GREEN_("%C%u"), creds.region_code + 'A', creds.facility_code);
    PrintAndLogEx(SUCCESS, "   Raw: %08X%08X%08X", raw1, raw2, raw3);
    PrintAndLogEx(SUCCESS, "   CRC: %02X - %02X (%s)", crc, calc_crc, (crc == calc_crc) ? "ok" : "fail");
    return PM3_SUCCESS;
}

static int CmdGallagherDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频 Gallagher 解调",
                  "尝试查找GALLAGHER前导码，如果找到则解码/解扰数据",
                  "低频 Gallagher 解调"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodGallagher(true);
}

static int CmdGallagherReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频 Gallagher 读取",
                  "读取 GALLAGHER 标签",
                  "lf gallagher reader -@   -> continuous reader mode"
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
        demodGallagher(!cm);
    } while (cm && (kbd_enter_pressed() == false));
    return PM3_SUCCESS;
}

static void setBitsInBlocks(uint32_t *blocks, uint8_t *pos, uint32_t data, uint8_t data_len) {
    for (int i = data_len - 1; i >= 0; i--) {
        uint8_t blk = *pos / 32;
        uint8_t bitPos = 31 - *pos % 32; // fill from left
        uint8_t bit = (data >> i) & 1;
        blocks[blk] |= bit << bitPos;
        (*pos)++;
    }
}

static void createBlocks(uint32_t *blocks, GallagherCredentials_t *creds) {
    // put data into the correct places (Gallagher obfuscation)
    uint8_t arr[8] = {0};
    gallagher_encode_creds(arr, creds);

    blocks[0] = blocks[1] = blocks[2] = 0;
    uint8_t pos = 0;

    // magic prefix
    setBitsInBlocks(blocks, &pos, 0x7fea, 16);

    for (int i = 0; i < ARRAYLEN(arr); i++) {
        // data byte
        setBitsInBlocks(blocks, &pos, arr[i], 8);

        // every byte is followed by a bit which is the inverse of the last bit
        setBitsInBlocks(blocks, &pos, !(arr[i] & 0x1), 1);
    }

    // checksum
    uint8_t crc = CRC8Cardx(arr, ARRAYLEN(arr));
    setBitsInBlocks(blocks, &pos, crc, 8);
}

static int CmdGallagherClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频 Gallagher 克隆",
                  "将 GALLAGHER 标签克隆到 T55x7、Q5/T5555 或 EM4305/4469 标签。",
                  "lf gallagher clone --raw 0FFD5461A9DA1346B2D1AC32      -> encode for T55x7 tag\n"
                  "lf gallagher clone --raw 0FFD5461A9DA1346B2D1AC32 --q5 -> encode for Q5/T5555 tag\n"
                  "lf gallagher clone --raw 0FFD5461A9DA1346B2D1AC32 --em -> encode for EM4305/4469\n"
                  "lf gallagher clone --rc 0 --fc 9876 --cn 1234 --il 1   -> encode for T55x7 tag from decoded data"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "原始十六进制数据，最多12字节"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_u64_0(NULL, "rc", "<decimal>", "区域代码，最多 4 位"),
        arg_u64_0(NULL, "fc", "<decimal>", "设施代码，最多2字节"),
        arg_u64_0(NULL, "cn", "<decimal>", "卡号，最多3字节"),
        arg_u64_0(NULL, "il", "<decimal>", "发行级别，最多4位"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof raw, &raw_len);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    uint64_t region_code = arg_get_u64_def(ctx, 4, -1); // uint4, input will be validated later
    uint64_t facility_code = arg_get_u64_def(ctx, 5, -1); // uint16
    uint64_t card_number = arg_get_u64_def(ctx, 6, -1); // uint24
    uint64_t issue_level = arg_get_u64_def(ctx, 7, -1); // uint4
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "不能同时指定Q5和EM4305");
        return PM3_EINVARG;
    }

    bool use_raw = (raw_len > 0);

    if (region_code == -1 && facility_code == -1 && card_number == -1 && issue_level == -1) {
        if (use_raw == false) {
            PrintAndLogEx(FAILED, "必须指定要克隆的原始数据，或rc/fc/cn/il");
            return PM3_EINVARG;
        }
    } else {
        // --raw and --rc/fc/cn/il are mutually exclusive
        if (use_raw) {
            PrintAndLogEx(FAILED, "不能同时指定raw和rc/fc/cn/il");
            return PM3_EINVARG;
        }
        if (gallagher_is_valid_creds(region_code, facility_code, card_number, issue_level) == false) {
            return PM3_EINVARG;
        }
    }

    uint32_t blocks[4];
    if (use_raw) {
        for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
            blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
        }
    } else {
        GallagherCredentials_t creds = {
            .region_code = region_code,
            .facility_code = facility_code,
            .card_number = card_number,
            .issue_level = issue_level,
        };
        // fill blocks 1 to 3 with Gallagher data
        createBlocks(blocks + 1, &creds);
    }

    //Pac - compat mode, NRZ, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | 3 << T55x7_MAXBLOCK_SHIFT;
    char cardtype[16] = {"T55x7"};

    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(32) | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_GALLAGHER_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    PrintAndLogEx(INFO, "Preparing to clone Gallagher to " _YELLOW_("%s") " from %s.",
                  cardtype,
                  use_raw ? "raw hex" : "specified data"
                 );
    print_blocks(blocks,  ARRAYLEN(blocks));

    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "完成！");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf gallagher reader`") " to verify");
    return res;
}

static int CmdGallagherSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "低频 Gallagher 模拟",
                  "启用对指定卡号的 GALLAGHER 卡的模拟。\\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n",
                  "lf gallagher sim --raw 0FFD5461A9DA1346B2D1AC32\n"
                  "lf gallagher sim --rc 0 --fc 9876 --cn 1234 --il 1"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "原始十六进制数据，最多12字节"),
        arg_u64_0(NULL, "rc", "<decimal>", "区域代码，最多 4 位"),
        arg_u64_0(NULL, "fc", "<decimal>", "设施代码，最多2字节"),
        arg_u64_0(NULL, "cn", "<decimal>", "卡号，最多3字节"),
        arg_u64_0(NULL, "il", "<decimal>", "发行级别，最多4位"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof raw, &raw_len);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint64_t region_code = arg_get_u64_def(ctx, 2, -1); // uint4, input will be validated later
    uint64_t facility_code = arg_get_u64_def(ctx, 3, -1); // uint16
    uint64_t card_number = arg_get_u64_def(ctx, 4, -1); // uint24
    uint64_t issue_level = arg_get_u64_def(ctx, 5, -1); // uint4
    CLIParserFree(ctx);

    bool use_raw = raw_len > 0;

    if (region_code == -1 && facility_code == -1 && card_number == -1 && issue_level == -1) {
        if (use_raw == false) {
            PrintAndLogEx(FAILED, "必须指定要克隆的原始数据，或rc/fc/cn/il");
            return PM3_EINVARG;
        }
    } else {
        // --raw and --rc/fc/cn/il are mutually exclusive
        if (use_raw) {
            PrintAndLogEx(FAILED, "不能同时指定raw和rc/fc/cn/il");
            return PM3_EINVARG;
        }
        if (gallagher_is_valid_creds(region_code, facility_code, card_number, issue_level) == false) {
            return PM3_EINVARG;
        }
    }

    if (use_raw == false) {
        // generate Gallagher data
        GallagherCredentials_t creds = {
            .region_code = region_code,
            .facility_code = facility_code,
            .card_number = card_number,
            .issue_level = issue_level,
        };
        uint32_t blocks[3];
        createBlocks(blocks, &creds);

        // convert to the normal 'raw' format
        for (int i = 0; i < ARRAYLEN(blocks); i++) {
            raw[(4 * i) + 0] = (blocks[i] >> 24) & 0xff;
            raw[(4 * i) + 1] = (blocks[i] >> 16) & 0xff;
            raw[(4 * i) + 2] = (blocks[i] >> 8) & 0xff;
            raw[(4 * i) + 3] = (blocks[i]) & 0xff;
        }
    }

    // ASK/MAN sim.
    PrintAndLogEx(SUCCESS, "Simulating Gallagher - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, sizeof(raw)));

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
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + sizeof(bs));
    free(payload);

    return lfsim_wait_check(CMD_LF_ASK_SIMULATE);
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,            AlwaysAvailable, "此帮助"},
    {"demod",  CmdGallagherDemod,  AlwaysAvailable, "从 GraphBuffer 解调 GALLAGHER 标签"},
    {"reader", CmdGallagherReader, IfPm3Lf,         "尝试读取并提取标签数据"},
    {"clone",  CmdGallagherClone,  IfPm3Lf,         "克隆GALLAGHER标签到T55x7、Q5/T5555或EM4305/4469"},
    {"sim",    CmdGallagherSim,    IfPm3Lf,         "模拟GALLAGHER标签"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFGallagher(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find Gallagher preamble in already demoded data
int detectGallagher(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = { 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0 };
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found

    if (*size != 96) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}
