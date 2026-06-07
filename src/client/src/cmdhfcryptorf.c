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
// High frequency CryptoRF commands (ISO14443B)
//-----------------------------------------------------------------------------

#include "cmdhfcryptorf.h"

#include <ctype.h>
#include "fileutils.h"

#include "cmdparser.h"    // command_t
#include "comms.h"        // clearCommandBuffer
#include "cmdtrace.h"
#include "crc16.h"
#include "protocols.h"    // definitions of ISO14B protocol
#include "iso14b.h"
#include "cliparser.h"    // cliparsing

#define TIMEOUT 2000

#ifndef CRYPTORF_MEM_SIZE
# define CRYPTORF_MEM_SIZE 1024
#endif

static int CmdHelp(const char *Cmd);

static iso14b_card_select_t last_known_card;
static void set_last_known_card(iso14b_card_select_t card) {
    last_known_card = card;
}

static int switch_off_field_cryptorf(void) {
    SetISODEPState(ISODEP_INACTIVE);
    iso14b_raw_cmd_t packet = {
        .flags = ISO14B_DISCONNECT,
        .timeout = 0,
        .rawlen = 0,
    };
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    return PM3_SUCCESS;
}

static int CmdHFCryptoRFList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf cryptorf", "cryptorf");
}

static int CmdHFCryptoRFSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf 仿真",
                  "模拟CryptoRF标签\\n"
                  _RED_("not implemented"),
                  "hf cryptorf 仿真");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_CRYPTORF_SIM, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdHFCryptoRFSniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf 嗅探",
                  "嗅读取器与标签之间的通信",
                  "hf cryptorf sniff\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_SNIFF, NULL, 0);
    PacketResponseNG resp;
    WaitForResponse(CMD_HF_ISO14443B_SNIFF, &resp);

    PrintAndLogEx(HINT, "提示：尝试 `" _YELLOW_("hf cryptorf list") "` to view captured tracelog");
    PrintAndLogEx(HINT, "提示：尝试 `" _YELLOW_("trace save -f hf_cryptorf_mytrace") "` to save tracelog for later analysing");
    return PM3_SUCCESS;
}

static bool get_14b_UID(iso14b_card_select_t *card) {

    if (card == NULL) {
        return false;
    }

    int8_t retry = 3;
    while (retry--) {

        iso14b_raw_cmd_t packet = {
            .flags = (ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT),
            .timeout = 0,
            .rawlen = 0,
        };
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {
            if (resp.status == PM3_SUCCESS) {
                memcpy(card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
                return true;
            }
        }
    } // retry

    if (retry <= 0) {
        PrintAndLogEx(FAILED, "命令执行超时");
    }

    return false;
}

// Print extended information about tag.
static int infoHFCryptoRF(bool verbose) {
    iso14b_raw_cmd_t packet = {
        .flags = (ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT),
        .timeout = 0,
        .rawlen = 0,
    };
    // 14b get and print UID only (general info)
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "命令执行超时");
        }
        switch_off_field_cryptorf();
        return false;
    }

    switch (resp.status) {
        case PM3_SUCCESS: {
            iso14b_card_select_t card;
            memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, " UID    : %s", sprint_hex(card.uid, card.uidlen));
            PrintAndLogEx(SUCCESS, " ATQB   : %s", sprint_hex(card.atqb, sizeof(card.atqb)));
            PrintAndLogEx(SUCCESS, " CHIPID : %02X", card.chipid);
            return PM3_SUCCESS;
        }
        case PM3_ELENGTH:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 ATTRIB 失败");
            break;
        case PM3_ECRC:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 CRC 失败");
            break;
        default:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b 卡片选择失败");
            break;
    }
    return PM3_ESOFT;
}

static int CmdHFCryptoRFInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf 信息",
                  "作为 CryptoRF 读取器。",
                  "hf cryptorf 信息");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "详细", "详细输出"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    int res = infoHFCryptoRF(verbose);
    if (res != PM3_SUCCESS && verbose) {
        PrintAndLogEx(FAILED, "未找到 CryptoRF / ISO14443-B 标签");
    }
    return res;
}

// get and print general info cryptoRF
int readHFCryptoRF(bool loop, bool verbose) {

    int res = PM3_ESOFT;
    do {
        iso14b_raw_cmd_t packet = {
            .flags = (ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT),
            .timeout = 0,
            .rawlen = 0,
        };
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

            if (loop) {
                if (resp.status != PM3_SUCCESS) {
                    continue;
                }
            } else {
                // when not in continuous mode
                if (resp.status != PM3_SUCCESS) {
                    if (verbose) {
                        PrintAndLogEx(WARNING, "cryptoRF / ISO14443-b 卡片选择失败");
                    }
                    res = PM3_EOPABORTED;
                    break;
                }
            }

            iso14b_card_select_t card;
            memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex_inrow(card.uid, card.uidlen));
            set_last_known_card(card);
        }
    } while (loop && (kbd_enter_pressed() == false));
    DropField();
    return res;
}

static int CmdHFCryptoRFReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf 读卡器",
                  "作为 cryptoRF 读取器。持续寻找 cryptoRF 标签，直到按下 Enter 或 pm3 按钮",
                  "hf cryptorf reader -@   -> continuous reader mode"
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
    return readHFCryptoRF(cm, false);
}

// need to write to file
static int CmdHFCryptoRFDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf 转储",
                  "转储CryptoRF标签的所有内存（512/4096位大小）",
                  "hf cryptorf dump\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "保存转储的文件名"),
        arg_lit0(NULL, "64", "64byte / 512bit memory"),
        arg_lit0(NULL, "512", "512byte / 4096bit memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool m64 = arg_get_lit(ctx, 2);
    bool m512 = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (m512 + m64 != 1) {
        PrintAndLogEx(INFO, "仅选择一个卡片内存大小");
        return PM3_EINVARG;
    }

    uint16_t cardsize;
    uint8_t blocks = 0;
    if (m64) {
        cardsize = (512 / 8) + 4;
        blocks = 0x0F;
    }
    if (m512) {
        cardsize = (4096 / 8) + 4;
        blocks = 0x7F;
    }

    iso14b_card_select_t card;
    if (get_14b_UID(&card) == false) {
        PrintAndLogEx(WARNING, "未找到标签。");
        return PM3_SUCCESS;
    }

    // detect blocksize from card :)
    PrintAndLogEx(INFO, "Reading memory from tag UID " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));

    // select tag
    iso14b_raw_cmd_t *packet = (iso14b_raw_cmd_t *)calloc(1, sizeof(iso14b_raw_cmd_t) + 2);
    if (packet == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }
    packet->flags = (ISO14B_CONNECT | ISO14B_SELECT_SR);
    packet->timeout = 0;
    packet->rawlen = 0;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t));
    PacketResponseNG resp;

    // select
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000)) {
        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "选择%d]失败", resp.status);
            free(packet);
            return switch_off_field_cryptorf();
        }
    }

    PrintAndLogEx(INFO, "." NOLF);

    uint8_t data[cardsize];
    memset(data, 0, sizeof(data));
    uint16_t blocknum = 0;

    for (int retry = 0; retry < 5; retry++) {

        // set up the read command
        packet->flags = (ISO14B_APPEND_CRC | ISO14B_RAW);
        packet->rawlen = 2;
        packet->raw[0] = ISO14443B_READ_BLK;
        packet->raw[1] = blocknum & 0xFF;

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t) + 2);
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000)) {

            if (resp.status != PM3_SUCCESS) {
                PrintAndLogEx(FAILED, "再重试一次");
                continue;
            }

            uint16_t len = resp.length;
            uint8_t *recv = resp.data.asBytes;

            if (check_crc(CRC_14443_B, recv, len) == false) {
                PrintAndLogEx(FAILED, "crc失败，再重试一次");
                continue;
            }

            memcpy(data + (blocknum * 4), resp.data.asBytes, 4);

            // last read
            if (blocknum == 0xFF) {
                break;
            }

            retry = 0;
            blocknum++;
            if (blocknum > blocks) {
                // read config block
                blocknum = 0xFF;
            }

            PrintAndLogEx(NORMAL, "." NOLF);
            fflush(stdout);
        }
    }
    free(packet);

    PrintAndLogEx(NORMAL, "");

    if (blocknum != 0xFF) {
        PrintAndLogEx(FAILED, "转储失败");
        return switch_off_field_cryptorf();
    }

    PrintAndLogEx(INFO, "block#   | data         | ascii");
    PrintAndLogEx(INFO, "---------+--------------+----------");

    for (int i = 0; i <= blocks; i++) {
        PrintAndLogEx(INFO,
                      "%3d/0x%02X | %s | %s",
                      i,
                      i,
                      sprint_hex(data + (i * 4), 4),
                      sprint_ascii(data + (i * 4), 4)
                     );
    }
    PrintAndLogEx(INFO, "---------+--------------+----------");
    PrintAndLogEx(NORMAL, "");

    size_t datalen = (blocks + 1) * 4;

    if (fnlen < 1) {
        PrintAndLogEx(INFO, "使用 UID 作为文件名");
        char *fptr = filename + snprintf(filename, sizeof(filename), "hf-cryptorf-");
        FillFileNameByUID(fptr, card.uid, "-dump", card.uidlen);
    }

    pm3_save_dump(filename, data, datalen, jsfCryptorf);

    return switch_off_field_cryptorf();
}

static int CmdHFCryptoRFELoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf 加载仿真",
                  "将CryptoRF标签转储(bin/eml/json)加载到设备上的模拟器内存",
                  "hf cryptorf eload -f hf-cryptorf-0102030405-dump.bin\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "指定转储文件的文件名"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    if (fnlen == 0) {
        PrintAndLogEx(ERR, "错误：请指定文件名");
        return PM3_EINVARG;
    }

    size_t datalen = CRYPTORF_MEM_SIZE;
    // set up buffer
    uint8_t *data = calloc(datalen, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    if (loadFile_safe(filename, ".bin", (void **)&data, &datalen) != PM3_SUCCESS) {
        free(data);
        PrintAndLogEx(WARNING, "错误，读取文件");
        return PM3_EFILE;
    }

    PrintAndLogEx(SUCCESS, "正在上传到模拟器内存");

    uint32_t bytes_sent = 0;
    /*
    //Send to device
    uint32_t bytes_remaining  = bytes_read;

    while (bytes_remaining > 0) {
        uint32_t bytes_in_packet = MIN(PM3_CMD_DATA_SIZE, bytes_remaining);
        if (bytes_in_packet == bytes_remaining) {
            // Disable fast mode on last packet
            g_conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_CRYPTORF_EML_MEMSET, bytes_sent, bytes_in_packet, 0, data + bytes_sent, bytes_in_packet);
        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;
    }
    */
    free(data);
    PrintAndLogEx(SUCCESS, "sent " _YELLOW_("%d") " bytes of data to device emulator memory", bytes_sent);
    return PM3_SUCCESS;
}

static int CmdHFCryptoRFESave(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf 保存仿真",
                  "将模拟器内存保存到文件 (bin/json)\\n"
                  "if filename is not supplied, UID will be used.",
                  "hf cryptorf esave\n"
                  "hf cryptorf esave -f filename"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "指定转储文件的文件名"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    size_t numofbytes = CRYPTORF_MEM_SIZE;

    // set up buffer
    uint8_t *data = calloc(numofbytes, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    // download emulator memory
    PrintAndLogEx(SUCCESS, "读取模拟器内存...");
    if (GetFromDevice(BIG_BUF_EML, data, numofbytes, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "失败，设备传输超时");
        free(data);
        return PM3_ETIMEOUT;
    }

    // user supplied filename?
    if (fnlen < 1) {
        PrintAndLogEx(INFO, "使用 UID 作为文件名");
        char *fptr = filename + snprintf(filename, sizeof(filename), "hf-cryptorf-");
        FillFileNameByUID(fptr, data, "-dump", 4);
    }

    pm3_save_dump(filename, data, numofbytes, jsfCryptorf);
    free(data);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,              AlwaysAvailable, "此帮助"},
    {"dump",    CmdHFCryptoRFDump,    IfPm3Iso14443b,  "读取CryptoRF标签的所有内存页面，保存到文件"},
    {"info",    CmdHFCryptoRFInfo,    IfPm3Iso14443b,  "标签信息"},
    {"list",    CmdHFCryptoRFList,    AlwaysAvailable,  "列出ISO 14443B历史"},
    {"reader",  CmdHFCryptoRFReader,  IfPm3Iso14443b,  "模拟 CryptoRF 读取器识别标签"},
    {"sim",     CmdHFCryptoRFSim,     IfPm3Iso14443b,  "伪造CryptoRF标签"},
    {"sniff",   CmdHFCryptoRFSniff,   IfPm3Iso14443b,  "窃听CryptoRF"},
    {"eload",   CmdHFCryptoRFELoad,   AlwaysAvailable, "上传文件到模拟器内存"},
    {"esave",   CmdHFCryptoRFESave,   AlwaysAvailable, "将模拟器内存保存到文件"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFCryptoRF(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
