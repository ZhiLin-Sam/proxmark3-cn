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
// Commands related to the German electronic Identification Card
//-----------------------------------------------------------------------------
#include "cmdhfepa.h"

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <ctype.h>        // tolower
#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "commonutil.h"   // ARRAYLEN
#include "comms.h"        // clearCommandBuffer
#include "ui.h"
#include "util_posix.h"

static int CmdHelp(const char *Cmd);

// Perform (part of) the PACE protocol
static int CmdHFEPACollectPACENonces(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf epa 挑战随机数",
                  "在执行部分PACE协议时尝试收集随机数。",
                  "hf epa cnonces --size 4 --num 4 --delay 1");

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "size", "<dec>", "nonce size"),
        arg_int1(NULL, "num", "<dec>", "number of nonces to collect"),
        arg_int1("d", "delay", "<dec>", "尝试间隔延迟"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);


    int m = arg_get_int_def(ctx, 1, 0);
    int n = arg_get_int_def(ctx, 2, 0);
    int d = arg_get_int_def(ctx, 3, 0);

    CLIParserFree(ctx);

    // values are expected to be > 0
    m = m > 0 ? m : 1;
    n = n > 0 ? n : 1;

    PrintAndLogEx(SUCCESS, "正在收集 %u 个 %u 字节随机数", n, m);
    PrintAndLogEx(SUCCESS, "起始: %" PRIu64, msclock() / 1000);

    struct p {
        uint32_t m;
    } PACKED payload;
    payload.m = m;

    for (uint32_t i = 0; i < n; i++) {
        // execute PACE

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_HF_EPA_COLLECT_NONCE, (uint8_t *)&payload, sizeof(payload));
        WaitForResponse(CMD_HF_EPA_COLLECT_NONCE, &resp);

        // check if command failed
        if (resp.oldarg[0] != 0) {
            PrintAndLogEx(FAILED, "步骤 % 中出错" PRId64 ", Return code: %" PRId64, resp.oldarg[0], resp.oldarg[1]);
        } else {
            size_t nonce_length = resp.oldarg[1];

            char *nonce = (char *) calloc(2 * nonce_length + 1, sizeof(uint8_t));
            if (nonce == NULL) {
                PrintAndLogEx(WARNING, "分配内存失败");
                return PM3_EMALLOC;
            }

            // print nonce
            PrintAndLogEx(SUCCESS, "长度：%zu，Nonce：%s", nonce_length, sprint_hex_inrow(resp.data.asBytes, nonce_length));
            free(nonce);
        }
        if (i < n - 1) {
            sleep(d);
        }
    }

    PrintAndLogEx(SUCCESS, "结束: %" PRIu64, msclock() / 1000);
    return PM3_SUCCESS;
}

// perform the PACE protocol by replaying APDUs
static int CmdHFEPAPACEReplay(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf epa 重放",
                  "通过重放给定的APDU执行PACE协议",
                  "hf epa replay --mse 0022C1A4 --get 1068000000 --map 1086000002 --pka 1234ABCDEF --ma 1A2B3C4D"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "mse", "<hex>", "msesa APDU"),
        arg_str1(NULL, "get", "<hex>", "gn APDU"),
        arg_str1(NULL, "map", "<hex>", "map APDU"),
        arg_str1(NULL, "pka", "<hex>", "pka APDU"),
        arg_str1(NULL, "ma", "<hex>", "ma APDU"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int msesa_len = 0;
    uint8_t msesa_apdu[41] = {0};
    CLIGetHexWithReturn(ctx, 1, msesa_apdu, &msesa_len);

    int gn_len = 0;
    uint8_t gn_apdu[8] = {0};
    CLIGetHexWithReturn(ctx, 2, gn_apdu, &gn_len);

    int map_len = 0;
    uint8_t map_apdu[75] = {0};
    CLIGetHexWithReturn(ctx, 3, map_apdu, &map_len);

    int pka_len = 0;
    uint8_t pka_apdu[75] = {0};
    CLIGetHexWithReturn(ctx, 4, pka_apdu, &pka_len);

    int ma_len = 0;
    uint8_t ma_apdu[18] = {0};
    CLIGetHexWithReturn(ctx, 5, ma_apdu, &ma_len);

    CLIParserFree(ctx);

    uint8_t apdu_lengths[5] = {msesa_len, gn_len, map_len, pka_len, ma_len};
    // pointers to the arrays to be able to iterate
    const uint8_t *apdus[] = {msesa_apdu, gn_apdu, map_apdu, pka_apdu, ma_apdu};

    // Proxmark response
    PacketResponseNG resp;

    // transfer the APDUs to the Proxmark3
    uint8_t data[PM3_CMD_DATA_SIZE];
    // fast push mode
    g_conn.block_after_ACK = true;
    for (int i = 0; i < ARRAYLEN(apdu_lengths); i++) {

        // transfer the APDU in several parts if necessary
        for (int j = 0; j * sizeof(data) < apdu_lengths[i]; j++) {
            // amount of data in this packet
            int packet_length = apdu_lengths[i] - (j * sizeof(data));
            if (packet_length > sizeof(data)) {
                packet_length = sizeof(data);
            }
            if ((i == ARRAYLEN(apdu_lengths) - 1) && (j * sizeof(data) >= apdu_lengths[i] - 1)) {
                // Disable fast mode on last packet
                g_conn.block_after_ACK = false;
            }
            memcpy(data, // + (j * sizeof(data)),
                   apdus[i] + (j * sizeof(data)),
                   packet_length);

            clearCommandBuffer();
            // arg0: APDU number
            // arg1: offset into the APDU
            SendCommandMIX(CMD_HF_EPA_REPLAY, i + 1, j * sizeof(data), packet_length, data, packet_length);
            if (WaitForResponseTimeout(CMD_HF_EPA_REPLAY, &resp, 2500) == false) {
                PrintAndLogEx(WARNING, "命令超时");
                return PM3_ETIMEOUT;
            }
            if (resp.oldarg[0] != 0) {
                PrintAndLogEx(WARNING, "APDU #%d 部分 %d 传输失败！", i, j);
                return PM3_ESOFT;
            }
        }
    }

    // now perform the replay
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_EPA_REPLAY, 0, 0, 0, NULL, 0);
    WaitForResponse(CMD_ACK, &resp);

    if (resp.oldarg[0] != 0) {
        PrintAndLogEx(SUCCESS, "\\nPACE重放在第%u步失败！", (uint32_t)resp.oldarg[0]);
        PrintAndLogEx(SUCCESS, "测量时间:");
        PrintAndLogEx(SUCCESS, "MSE 设置 AT: %u us", resp.data.asDwords[0]);
        PrintAndLogEx(SUCCESS, "GA 获取随机数：%u us", resp.data.asDwords[1]);
        PrintAndLogEx(SUCCESS, "GA 映射随机数：%u us", resp.data.asDwords[2]);
        PrintAndLogEx(SUCCESS, "GA 执行密钥协商：%u us", resp.data.asDwords[3]);
        PrintAndLogEx(SUCCESS, "GA 相互认证：%u us", resp.data.asDwords[4]);
    } else {
        PrintAndLogEx(SUCCESS, "PACE 重放成功！");
        PrintAndLogEx(SUCCESS, "MSE 设置 AT: %u us", resp.data.asDwords[0]);
        PrintAndLogEx(SUCCESS, "GA 获取随机数：%u us", resp.data.asDwords[1]);
        PrintAndLogEx(SUCCESS, "GA 映射随机数：%u us", resp.data.asDwords[2]);
        PrintAndLogEx(SUCCESS, "GA 执行密钥协商：%u us", resp.data.asDwords[3]);
        PrintAndLogEx(SUCCESS, "GA 相互认证：%u us", resp.data.asDwords[4]);
    }
    return PM3_SUCCESS;
}

// perform the PACE protocol by replaying APDUs
static int CmdHFEPAPACESimulate(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf epa 仿真",
                  "使用给定密码pwd（类型pty）模拟PACE协议。\\n"
                  "The crypto is performed on pc or proxmark",
                  "hf epa sim --pwd 112233445566\n"
                  "hf epa sim --pc --pty 1 --pwd 112233445566"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit1(NULL, "pc",           "perform crypto on PC"),
        arg_str1(NULL, "pty", "<hex>", "type of password"),
        arg_str1("p",  "pwd", "<hex>", "密码"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

//    bool use_pc = arg_get_lit(ctx, 1);
//  uint8_t pwd_type = 0;

    int plen = 0;
    uint8_t pwd[6] = {0};
    CLIGetHexWithReturn(ctx, 3, pwd, &plen);

    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "开始 PACE 模拟...");


    clearCommandBuffer();
    SendCommandMIX(CMD_HF_EPA_PACE_SIMULATE, 0, 0, 0, pwd, plen);
    PacketResponseNG resp;
    WaitForResponse(CMD_ACK, &resp);

    uint32_t *data = resp.data.asDwords;

    if (resp.oldarg[0] != 0) {
        PrintAndLogEx(INFO, "\\nPACE在第%u步失败！", (uint32_t)resp.oldarg[0]);
        PrintAndLogEx(INFO, "MSE 设置 AT: %u us", data[0]);
        PrintAndLogEx(INFO, "GA 获取随机数：%u us", data[1]);
        PrintAndLogEx(INFO, "GA 映射随机数：%u us", data[2]);
        PrintAndLogEx(INFO, "GA 执行密钥协商：%u us", data[3]);
        PrintAndLogEx(INFO, "GA 相互认证：%u us", data[4]);
        PrintAndLogEx(INFO, "----------------");
    } else {
        PrintAndLogEx(INFO, "PACE 成功！");
        PrintAndLogEx(INFO, "MSE 设置 AT: %u us", data[0]);
        PrintAndLogEx(INFO, "GA 获取随机数：%u us", data[1]);
        PrintAndLogEx(INFO, "GA 映射随机数：%u us", data[2]);
        PrintAndLogEx(INFO, "GA 执行密钥协商：%u us", data[3]);
        PrintAndLogEx(INFO, "GA 相互认证：%u us", data[4]);
        PrintAndLogEx(INFO, "----------------");
    }

    return PM3_SUCCESS;
}


static command_t CommandTable[] = {
    {"help",    CmdHelp,                   AlwaysAvailable, "此帮助"},
    {"cnonces", CmdHFEPACollectPACENonces, IfPm3Iso14443,   "获取指定大小的加密 PACE 随机数"},
    {"replay",  CmdHFEPAPACEReplay,        IfPm3Iso14443,   "通过重放给定的APDU执行PACE协议"},
    {"sim",     CmdHFEPAPACESimulate,      IfPm3Iso14443,   "模拟PACE协议"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFEPA(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
