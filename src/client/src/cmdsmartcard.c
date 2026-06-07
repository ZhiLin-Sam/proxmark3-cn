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
// Proxmark3 RDV40 Smartcard module commands
//-----------------------------------------------------------------------------
#include "cmdsmartcard.h"
#include <ctype.h>
#include <string.h>
#include "cmdparser.h"          // command_t
#include "commonutil.h"         // ARRAYLEN
#include "iso7816/iso7816core.h"
#include "protocols.h"
#include "cmdtrace.h"
#include "proxmark3.h"
#include "comms.h"              // getfromdevice
#include "emv/emvcore.h"        // decodeTVL
#include "crypto/libpcrypto.h"  // sha512hash
#include "ui.h"
#include "util.h"
#include "fileutils.h"
#include "crc16.h"              // crc
#include "cliparser.h"          // cliparsing
#include "atrs.h"               // ATR lookup

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
#include "mbedtls/net_sockets.h"
#pragma GCC diagnostic pop

#include "mifare.h"
#include "util_posix.h"
#include "cmdhf14a.h"
#include "cmdhf14b.h"

static int CmdHelp(const char *Cmd);

static int smart_loadjson(const char *preferredName, json_t **root) {

    json_error_t error;

    if (preferredName == NULL) {
        return 1;
    }

    char *path;
    int res = searchFile(&path, RESOURCES_SUBDIR, preferredName, ".json", false);
    if (res != PM3_SUCCESS) {
        return PM3_EFILE;
    }

    int retval = PM3_SUCCESS;
    *root = json_load_file(path, 0, &error);
    if (!*root) {
        PrintAndLogEx(ERR, "JSON(%s)错误在第%d行：%s", path, error.line, error.text);
        retval = PM3_ESOFT;
        goto out;
    }

    if (!json_is_array(*root)) {
        PrintAndLogEx(ERR, "无效的json (%s)格式。根必须为数组。", path);
        retval = PM3_ESOFT;
        goto out;
    }

    PrintAndLogEx(SUCCESS, "已加载文件 (%s) 成功。", path);
out:
    free(path);
    return retval;
}

static uint8_t GetATRTA1(const uint8_t *atr, size_t atrlen) {
    if (atrlen > 2) {
        uint8_t T0 = atr[1];
        if (T0 & 0x10)
            return atr[2];
    }

    return 0x11; // default value is 0x11, corresponding to fmax=5 MHz, Fi=372, Di=1.
}

static int DiArray[] = {
    0,  // b0000 RFU
    1,  // b0001
    2,
    4,
    8,
    16,
    32,  // b0110
    64,  // b0111. This was RFU in ISO/IEC 7816-3:1997 and former. Some card readers or drivers may erroneously reject cards using this value
    12,
    20,
    0,   // b1010 RFU
    0,
    0,   // ...
    0,
    0,
    0    // b1111 RFU
};

static int FiArray[] = {
    372,    // b0000 Historical note: in ISO/IEC 7816-3:1989, this was assigned to cards with internal clock
    372,    // b0001
    558,    // b0010
    744,    // b0011
    1116,   // b0100
    1488,   // b0101
    1860,   // b0110
    0,      // b0111 RFU
    0,      // b1000 RFU
    512,    // b1001
    768,    // b1010
    1024,   // b1011
    1536,   // b1100
    2048,   // b1101
    0,      // b1110 RFU
    0       // b1111 RFU
};

static float FArray[] = {
    4,    // b0000 Historical note: in ISO/IEC 7816-3:1989, this was assigned to cards with internal clock
    5,    // b0001
    6,    // b0010
    8,    // b0011
    12,   // b0100
    16,   // b0101
    20,   // b0110
    0,    // b0111 RFU
    0,    // b1000 RFU
    5,    // b1001
    7.5,  // b1010
    10,   // b1011
    15,   // b1100
    20,   // b1101
    0,    // b1110 RFU
    0     // b1111 RFU
};

static int GetATRDi(uint8_t *atr, size_t atrlen) {
    uint8_t TA1 = GetATRTA1(atr, atrlen);
    return DiArray[TA1 & 0x0F];  // The 4 low-order bits of TA1 (4th MSbit to 1st LSbit) encode Di
}

static int GetATRFi(uint8_t *atr, size_t atrlen) {
    uint8_t TA1 = GetATRTA1(atr, atrlen);
    return FiArray[TA1 >> 4];  // The 4 high-order bits of TA1 (8th MSbit to 5th LSbit) encode fmax and Fi
}

static float GetATRF(uint8_t *atr, size_t atrlen) {
    uint8_t TA1 = GetATRTA1(atr, atrlen);
    return FArray[TA1 >> 4];  // The 4 high-order bits of TA1 (8th MSbit to 5th LSbit) encode fmax and Fi
}

static void PrintATR(uint8_t *atr, size_t atrlen) {

    uint8_t T0 = atr[1];
    uint8_t K = T0 & 0x0F;
    uint8_t T1len = 0, TD1len = 0, TDilen = 0;
    bool protocol_T0_present = true;
    bool protocol_T15_present = false;

    if (T0 & 0x10) {
        PrintAndLogEx(INFO, "    - TA1 (Maximum clock frequency, proposed bit duration) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x20) {
        PrintAndLogEx(INFO, "    - TB1 (Deprecated: VPP requirements) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x40) {
        PrintAndLogEx(INFO, "    - TC1 (Extra delay between bytes required by card) [ 0x%02x ]", atr[2 + T1len]);
        T1len++;
    }

    if (T0 & 0x80) {
        uint8_t TD1 = atr[2 + T1len];
        PrintAndLogEx(INFO, "    - TD1 (First offered transmission protocol, presence of TA2..TD2) [ 0x%02x ] Protocol " _GREEN_("T%d"), TD1, TD1 & 0x0f);
        protocol_T0_present = false;
        if ((TD1 & 0x0f) == 0) {
            protocol_T0_present = true;
        }
        if ((TD1 & 0x0f) == 15) {
            protocol_T15_present = true;
        }

        T1len++;

        if (TD1 & 0x10) {
            PrintAndLogEx(INFO, "    - TA2 (Specific protocol and parameters to be used after the ATR) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x20) {
            PrintAndLogEx(INFO, "    - TB2 (Deprecated: VPP precise voltage requirement) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x40) {
            PrintAndLogEx(INFO, "    - TC2 (Maximum waiting time for protocol T=0) [ 0x%02x ]", atr[2 + T1len + TD1len]);
            TD1len++;
        }
        if (TD1 & 0x80) {
            uint8_t TDi = atr[2 + T1len + TD1len];
            PrintAndLogEx(INFO, "    - TD2 (A supported protocol or more global parameters, presence of TA3..TD3) [ 0x%02x ] Protocol " _GREEN_("T%d"), TDi, TDi & 0x0f);
            if ((TDi & 0x0f) == 0) {
                protocol_T0_present = true;
            }
            if ((TDi & 0x0f) == 15) {
                protocol_T15_present = true;
            }
            TD1len++;

            bool nextCycle = true;
            uint8_t vi = 3;
            while (nextCycle) {
                nextCycle = false;
                if (TDi & 0x10) {
                    PrintAndLogEx(INFO, "    - TA%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x20) {
                    PrintAndLogEx(INFO, "    - TB%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x40) {
                    PrintAndLogEx(INFO, "    - TC%d: 0x%02x", vi, atr[2 + T1len + TD1len + TDilen]);
                    TDilen++;
                }
                if (TDi & 0x80) {
                    TDi = atr[2 + T1len + TD1len + TDilen];
                    PrintAndLogEx(INFO, "    - TD%d [ 0x%02x ] Protocol T=%d", vi, TDi, TDi & 0x0f);
                    TDilen++;

                    nextCycle = true;
                    vi++;
                }
            }
        }
    }

    if (!protocol_T0_present || protocol_T15_present) { // there is CRC Check Byte TCK
        uint8_t vxor = 0;
        for (int i = 1; i < atrlen; i++)
            vxor ^= atr[i];

        if (vxor)
            PrintAndLogEx(WARNING, "无效校验和。应为0，实际为0x%02X", vxor);
        else
            PrintAndLogEx(INFO, "校验和正确。");
    }

    if (atr[0] != 0x3b)
        PrintAndLogEx(WARNING, "不是直接约定 [ 0x%02x ]", atr[0]);

    uint8_t calen = 2 + T1len + TD1len + TDilen + K;

    if (atrlen != calen && atrlen != calen + 1)  // may be CRC
        PrintAndLogEx(WARNING, "无效的 ATR 长度。len: %zu, T1len: %d, TD1len: %d, TDilen: %d, K: %d", atrlen, T1len, TD1len, TDilen, K);

    if (K > 0)
        PrintAndLogEx(DEBUG, "历史字节 | 长度 %02d | 格式 %02x", K, atr[2 + T1len + TD1len + TDilen]);

    if (K > 1) {
        PrintAndLogEx(INFO, "    Historical bytes ( %u )", K);
        print_buffer(&atr[2 + T1len + TD1len + TDilen], K, 1);
    }
}

static int smart_wait(uint8_t *out, int maxoutlen, bool verbose) {
    int i = 4;
    uint32_t len;
    do {
        clearCommandBuffer();
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_SMART_RAW, &resp, 1000)) {

            if (resp.status != PM3_SUCCESS) {
                if (verbose) PrintAndLogEx(WARNING, "智能卡响应状态失败");
                return -3;
            }

            len = resp.length;
            if (len == 0) {
                if (verbose) PrintAndLogEx(WARNING, "智能卡响应失败");
                return -2;
            }

            if (len > maxoutlen) {
                if (verbose) PrintAndLogEx(ERR, "响应过大。收到 %u，预期 %d", len, maxoutlen);
                return -4;
            }

            memcpy(out, resp.data.asBytes, len);
            if (len >= 2) {
                if (verbose) {


                    if (out[len - 2] == 0x90 && out[len - 1] == 0x00)  {
                        PrintAndLogEx(SUCCESS, _GREEN_("%02X%02X") " | %s", out[len - 2], out[len - 1], GetAPDUCodeDescription(out[len - 2], out[len - 1]));
                    } else {
                        PrintAndLogEx(SUCCESS, "%02X%02X | %s", out[len - 2], out[len - 1], GetAPDUCodeDescription(out[len - 2], out[len - 1]));
                    }
                }
            } else {
                if (verbose) {
                    PrintAndLogEx(SUCCESS, " %d | %s", len, sprint_hex_inrow_ex(out,  len, 8));
                }
            }
            return len;
        }
    } while (i--);

    if (verbose) {
        PrintAndLogEx(WARNING, "智能卡响应超时");
    }
    return -1;
}

static int smart_responseEx(uint8_t *out, int maxoutlen, bool verbose) {

    int datalen = smart_wait(out, maxoutlen, verbose);
    int totallen = datalen;
    bool needGetData = false;

    if (datalen < 2) {
        goto out;
    }

    if (out[datalen - 2] == 0x61 || out[datalen - 2] == 0x9F) {
        needGetData = true;
    }

    if (needGetData) {
        // Don't discard data we already received except the SW code.
        // If we only received 1 byte, this is the echo of INS, we discard it.
        totallen -= 2;
        if (totallen == 1) {
            totallen = 0;
        }
        int ofs = totallen;
        maxoutlen -= totallen;
        PrintAndLogEx(DEBUG, "保留数据 (%d 字节): %s", ofs, sprint_hex(out, ofs));

        int len = out[datalen - 1];
        if (len == 0 || len > MAX_APDU_SIZE) {
            // Cap the data length or the smartcard may send us a buffer we can't handle
            len = MAX_APDU_SIZE;
        }
        if (maxoutlen < len) {
            // We don't have enough buffer to hold the next part
            goto out;
        }

        if (verbose) PrintAndLogEx(INFO, "Requesting " _YELLOW_("0x%02X") " bytes response", len);

        uint8_t cmd_getresp[] = {0x00, ISO7816_GET_RESPONSE, 0x00, 0x00, len};
        smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + sizeof(cmd_getresp));
        if (payload == NULL) {
            PrintAndLogEx(WARNING, "分配内存失败");
            goto out;
        }
        payload->flags = SC_RAW | SC_LOG;
        payload->len = sizeof(cmd_getresp);
        payload->wait_delay = 0;
        memcpy(payload->data, cmd_getresp, sizeof(cmd_getresp));

        clearCommandBuffer();
        SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + sizeof(cmd_getresp));
        free(payload);

        datalen = smart_wait(&out[ofs], maxoutlen, verbose);

        if (datalen < 2) {
            goto out;
        }

        // data wo ACK
        if (datalen != len + 2) {
            // data with ACK
            if (datalen == len + 2 + 1) { // 2 - response, 1 - ACK
                if (out[ofs] != ISO7816_GET_RESPONSE) {
                    if (verbose) {
                        PrintAndLogEx(ERR, "GetResponse ACK错误。长度0x%x | data[0] %02X", len, out[0]);
                    }
                    datalen = 0;
                    goto out;
                }

                datalen--;
                memmove(&out[ofs], &out[ofs + 1], datalen);
                totallen += datalen;
            } else {
                // wrong length
                if (verbose) {
                    PrintAndLogEx(WARNING, "GetResponse长度错误。应为0x%02X，实际为0x%02X", len, datalen - 3);
                }
            }
        }
    }

out:
    return totallen;
}

static int smart_response(uint8_t *out, int maxoutlen) {
    return smart_responseEx(out, maxoutlen, true);
}

static int CmdSmartRaw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "智能卡原始命令",
                  "向卡片发送原始字节",
                  "smart raw -s -0 -d 00a404000e315041592e5359532e4444463031  -> `1PAY.SYS.DDF01` PPSE directory with get ATR\n"
                  "smart raw -0 -d 00a404000e325041592e5359532e4444463031     -> `2PAY.SYS.DDF01` PPSE directory\n"
                  "smart raw -0 -t -d 00a4040007a0000000041010                -> Mastercard\n"
                  "smart raw -0 -t -d 00a4040007a0000000031010                -> Visa"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("r", NULL, "do not read response"),
        arg_lit0("a", NULL, "active smartcard without select (reset sc module)"),
        arg_lit0("s", NULL, "active smartcard with select (get ATR)"),
        arg_lit0("t", "tlv", "如果可能，执行TLV解码器"),
        arg_lit0("0", NULL, "use protocol T=0"),
        arg_int0(NULL, "timeout", "<ms>", "Timeout in MS waiting for SIM to respond. (def 337ms)"),
        arg_str1("d", "数据", "<hex>", "要发送的字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool reply = (arg_get_lit(ctx, 1) == false);
    bool active = arg_get_lit(ctx, 2);
    bool active_select = arg_get_lit(ctx, 3);
    bool decode_tlv = arg_get_lit(ctx, 4);
    bool use_t0 = arg_get_lit(ctx, 5);
    int timeout = arg_get_int_def(ctx, 6, -1);

    int dlen = 0;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 7), data, sizeof(data), &dlen);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "解析字节错误");
        return PM3_EINVARG;
    }

    smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + dlen);
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }
    payload->len = dlen;
    memcpy(payload->data, data, dlen);

    payload->flags = SC_LOG;
    if (active || active_select) {

        payload->flags |= (SC_CONNECT | SC_CLEARLOG);
        if (active_select)
            payload->flags |= SC_SELECT;
    }

    payload->wait_delay = 0;
    if (timeout > -1) {
        payload->flags |= SC_WAIT;
        payload->wait_delay = timeout;
    }
    PrintAndLogEx(DEBUG, "SIM 卡超时... %u 毫秒", payload->wait_delay);

    if (dlen > 0) {
        if (use_t0)
            payload->flags |= SC_RAW_T0;
        else
            payload->flags |= SC_RAW;
    }

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (buf == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        free(payload);
        return PM3_EMALLOC;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + dlen);

    if (reply == false) {
        goto out;
    }

    // reading response from smart card
    int len = smart_response(buf, PM3_CMD_DATA_SIZE);
    if (len < 0) {
        free(payload);
        free(buf);
        return PM3_ESOFT;
    }

    if (buf[0] == 0x6C) {

        // request more bytes to download
        data[4] = buf[1];
        memcpy(payload->data, data, dlen);
        clearCommandBuffer();
        SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + dlen);

        len = smart_response(buf, PM3_CMD_DATA_SIZE);

        data[4] = 0;
    }

    if (decode_tlv && len > 4) {
        TLVPrintFromBuffer(buf, len - 2);
    } else {
        if (len > 2) {
            PrintAndLogEx(INFO, "响应数据：");
            PrintAndLogEx(INFO, " # | bytes                                           | ascii");
            PrintAndLogEx(INFO, "---+-------------------------------------------------+-----------------");
            print_hex_break(buf, len, 16);
        }
    }
    PrintAndLogEx(NORMAL, "");
out:
    free(payload);
    free(buf);
    return PM3_SUCCESS;
}

static int CmdSmartUpgrade(const char *Cmd) {
    PrintAndLogEx(INFO, "--------------------------------------------------------------------");
    PrintAndLogEx(WARNING, _RED_("WARNING") " - sim module firmware upgrade");
    PrintAndLogEx(WARNING, _RED_("A dangerous command, do wrong and you could brick the sim module"));
    PrintAndLogEx(INFO, "--------------------------------------------------------------------");
    PrintAndLogEx(NORMAL, "");

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "智能卡升级",
                  "升级RDV4模拟模块固件",
                  "smart upgrade -f sim014.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "指定固件文件名"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    char *bin_extension = filename;
    char *dot_position = NULL;
    while ((dot_position = strchr(bin_extension, '.')) != NULL) {
        bin_extension = dot_position + 1;
    }

    // generate filename for the related SHA512 hash file
    char sha512filename[FILE_PATH_SIZE] = {'\0'};
    if (!strcmp(bin_extension, "BIN") || !strcmp(bin_extension, "bin")) {
        memcpy(sha512filename, filename, strlen(filename) - strlen("bin"));
        strcat(sha512filename, "sha512.txt");
    } else {
        PrintAndLogEx(FAILED, "固件升级文件的扩展名必须为 .BIN");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "firmware file       " _YELLOW_("%s"), filename);
    PrintAndLogEx(INFO, "Checking integrity  " _YELLOW_("%s"), sha512filename);

    // load firmware file
    size_t firmware_size = 0;
    uint8_t *firmware = NULL;
    if (loadFile_safe(filename, "", (void **)&firmware, &firmware_size) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Firmware file " _YELLOW_("%s") " not found or locked.", filename);
        return PM3_EFILE;
    }

    // load sha512 file
    size_t sha512_size = 0;
    char *hashstring = NULL;
    if (loadFile_safe(sha512filename, "", (void **)&hashstring, &sha512_size) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "SHA-512 文件未找到或已锁定。");
        free(firmware);
        return PM3_EFILE;
    }

    if (sha512_size < 128) {
        PrintAndLogEx(FAILED, "SHA-512 文件大小错误");
        free(hashstring);
        free(firmware);
        return PM3_ESOFT;
    }
    hashstring[128] = '\0';

    int hash1n = 0;
    uint8_t hash_1[64];
    if (param_gethex_ex(hashstring, 0, hash_1, &hash1n) && hash1n != 128) {
        PrintAndLogEx(FAILED, "Couldn't read SHA-512 file. expect 128 hex bytes, got ( "_RED_("%d") " )", hash1n);
        free(hashstring);
        free(firmware);
        return PM3_ESOFT;
    }

    uint8_t hash_2[64];
    if (sha512hash(firmware, firmware_size, hash_2)) {
        PrintAndLogEx(FAILED, "无法计算固件的 SHA-512");
        free(hashstring);
        free(firmware);
        return PM3_ESOFT;
    }

    if (memcmp(hash_1, hash_2, 64)) {
        PrintAndLogEx(FAILED, "Couldn't verify integrity of firmware file " _RED_("(wrong SHA-512 hash)"));
        free(hashstring);
        free(firmware);
        return PM3_ESOFT;
    }
    free(hashstring);

    PrintAndLogEx(INFO, _GREEN_("Don\'t turn off your PM3!"));
    PrintAndLogEx(SUCCESS, "SIM模块固件上传至PM3...");

    PacketResponseNG resp;

    //Send to device
    uint32_t index = 0;
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = firmware_size;

    while (bytes_remaining > 0) {

        struct {
            uint32_t idx;
            uint32_t bytes_in_packet;
            uint16_t crc;
            uint8_t data[400];
        } PACKED upload;

        uint32_t bytes_in_packet = MIN(sizeof(upload.data), bytes_remaining);

        upload.idx = index + bytes_sent;
        upload.bytes_in_packet = bytes_in_packet;
        memcpy(upload.data, firmware + bytes_sent, bytes_in_packet);

        uint8_t a = 0, b = 0;
        compute_crc(CRC_14443_A, upload.data, bytes_in_packet, &a, &b);
        upload.crc = (a << 8 | b);

        clearCommandBuffer();
        SendCommandNG(CMD_SMART_UPLOAD, (uint8_t *)&upload, sizeof(upload));
        if (WaitForResponseTimeout(CMD_SMART_UPLOAD, &resp, 2000) == false) {
            PrintAndLogEx(WARNING, "等待回复超时");
            free(firmware);
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "上传到设备失败");
            free(firmware);
            return resp.status;
        }
        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;
        PrintAndLogEx(INPLACE, "已发送 %d 字节", bytes_sent);
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "SIM模块固件更新中...");

    // trigger the firmware upgrade
    clearCommandBuffer();
    struct {
        uint16_t fw_size;
        uint16_t crc;
    } PACKED payload;
    payload.fw_size = firmware_size;

    uint8_t a = 0, b = 0;
    compute_crc(CRC_14443_A, firmware, firmware_size, &a, &b);
    payload.crc = (a << 8 | b);

    free(firmware);
    SendCommandNG(CMD_SMART_UPGRADE, (uint8_t *)&payload, sizeof(payload));
    if (WaitForResponseTimeout(CMD_SMART_UPGRADE, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "等待回复超时");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Sim module firmware upgrade " _GREEN_("successful"));
        PrintAndLogEx(HINT, "提示: 运行 `" _YELLOW_("硬件 状态") "` to validate the fw version ");
    } else {
        PrintAndLogEx(FAILED, "Sim module firmware upgrade " _RED_("failed"));
    }
    return PM3_SUCCESS;
}

static int CmdSmartInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "智能卡信息",
                  "从智能卡提取更详细信息。",
                  "smart info -v"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "详细", "详细输出"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_ATR, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SMART_ATR, &resp, 2500) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "智能卡超时");
        }
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(WARNING, "智能卡选择失败");
        }
        return PM3_ESOFT;
    }

    smart_card_atr_t card;
    memcpy(&card, (smart_card_atr_t *)resp.data.asBytes, sizeof(smart_card_atr_t));

    // print header
    PrintAndLogEx(INFO, "--- " _CYAN_("Smartcard Information") " ---------");
    PrintAndLogEx(INFO, "ISO7816-3 ATR... %s", sprint_hex(card.atr, card.atr_len));
    // convert bytes to str.
    char *hexstr = calloc((card.atr_len << 1) + 1, sizeof(uint8_t));
    if (hexstr == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    hex_to_buffer((uint8_t *)hexstr, card.atr, card.atr_len, (card.atr_len << 1), 0, 0, true);
    PrintAndLogEx(INFO, "指纹..... %s", getAtrInfo(hexstr));
    free(hexstr);

    // print ATR
    PrintAndLogEx(INFO, "ATR");
    PrintATR(card.atr, card.atr_len);

    // print D/F (brom byte TA1 or defaults)
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "D/F (TA1)");
    int Di = GetATRDi(card.atr, card.atr_len);
    int Fi = GetATRFi(card.atr, card.atr_len);
    float F = GetATRF(card.atr, card.atr_len);
    if (GetATRTA1(card.atr, card.atr_len) == 0x11)
        PrintAndLogEx(INFO, "使用默认值...");

    PrintAndLogEx(INFO, "\t- Di %d", Di);
    PrintAndLogEx(INFO, "\t- Fi %d", Fi);
    PrintAndLogEx(INFO, "\t- F  %.1f MHz", F);

    if (Di && Fi) {
        PrintAndLogEx(INFO, "\\t- 周期/ETU %d", Fi / Di);
        PrintAndLogEx(INFO, "\\t- 在4 MHz下 %.1f 比特/秒", (float)4000000 / (Fi / Di));
        PrintAndLogEx(INFO, "\\t- 在Fmax (%.1fMHz)下 %.1f 比特/秒", (F * 1000000) / (Fi / Di), F);
    } else {
        PrintAndLogEx(WARNING, "\\t- Di或Fi为RFU。");
    };

    return PM3_SUCCESS;
}

static int CmdSmartReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "智能卡读卡器",
                  "作为智能卡读取器。",
                  "智能卡读卡器"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "详细", "详细输出"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_ATR, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SMART_ATR, &resp, 2500) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "智能卡选择失败");
        }
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(WARNING, "智能卡选择失败");
        }
        return PM3_ESOFT;
    }
    smart_card_atr_t *card = (smart_card_atr_t *)resp.data.asBytes;
    PrintAndLogEx(INFO, "ISO7816-3 ATR... %s", sprint_hex(card->atr, card->atr_len));

    // convert bytes to str.
    char *hexstr = calloc((card->atr_len << 1) + 1, sizeof(uint8_t));
    if (hexstr == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    hex_to_buffer((uint8_t *)hexstr, card->atr, card->atr_len, (card->atr_len << 1), 0, 0, true);
    PrintAndLogEx(INFO, "指纹..... %s", getAtrInfo(hexstr));
    free(hexstr);
    return PM3_SUCCESS;
}

static int CmdSmartSetClock(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "智能卡设置时钟",
                  "设置智能卡接口的时钟速度。",
                  "smart setclock --4mhz\n"
                  "smart setclock --16mhz"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "16mhz", "16 MHz clock speed"),
        arg_lit0(NULL, "8mhz", "8 MHz clock speed"),
        arg_lit0(NULL, "4mhz", "4 MHz clock speed"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    bool c16 = arg_get_lit(ctx, 1);
    bool c8 = arg_get_lit(ctx, 2);
    bool c4 = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if ((c16 + c8 + c4) > 1) {
        PrintAndLogEx(WARNING, "一次只能使用一个时钟速度");
        return PM3_EINVARG;
    }

    struct {
        uint32_t new_clk;
    } PACKED payload;

    if (c16)
        payload.new_clk = 0;
    else if (c8)
        payload.new_clk = 1;
    else if (c4)
        payload.new_clk = 2;

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_SETCLOCK, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SMART_SETCLOCK, &resp, 2500) == false) {
        PrintAndLogEx(WARNING, "智能卡选择失败");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "智能卡设置时钟失败");
        return PM3_ESOFT;
    }

    switch (payload.new_clk) {
        case 0:
            PrintAndLogEx(SUCCESS, "Clock changed to " _GREEN_("16") " MHz giving " _GREEN_("10800") " baudrate");
            break;
        case 1:
            PrintAndLogEx(SUCCESS, "Clock changed to " _GREEN_("8") " MHz giving " _GREEN_("21600") " baudrate");
            break;
        case 2:
            PrintAndLogEx(SUCCESS, "Clock changed to " _GREEN_("4") " MHz giving " _GREEN_("86400") " baudrate");
            break;
        default:
            break;
    }
    return PM3_SUCCESS;
}

static int CmdSmartList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "smart", "7816");
}

static void smart_brute_prim(void) {

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (buf == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return;
    }

    uint8_t get_card_data[] = {
        0x80, 0xCA, 0x9F, 0x13, 0x00,
        0x80, 0xCA, 0x9F, 0x17, 0x00,
        0x80, 0xCA, 0x9F, 0x36, 0x00,
        0x80, 0xCA, 0x9F, 0x4f, 0x00
    };

    PrintAndLogEx(INFO, "读取原语");

    for (int i = 0; i < ARRAYLEN(get_card_data); i += 5) {

        smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + 5);
        if (payload == NULL) {
            PrintAndLogEx(WARNING, "分配内存失败");
            free(buf);
            return;
        }
        payload->flags = SC_RAW_T0;
        payload->len = 5;
        payload->wait_delay = 0;
        memcpy(payload->data, get_card_data + i, 5);

        clearCommandBuffer();
        SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + 5);
        free(payload);

        int len = smart_responseEx(buf, PM3_CMD_DATA_SIZE, false);
        if (len > 2) {
            PrintAndLogEx(SUCCESS, "\tHEX  %d |: %s", len, sprint_hex(buf, len));
        }
    }
    free(buf);
}

static int smart_brute_sfi(bool decodeTLV) {

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (buf == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return 1;
    }

    int len;
    // READ RECORD
    uint8_t READ_RECORD[] = {0x00, 0xB2, 0x00, 0x00, 0x00};
    PrintAndLogEx(INFO, "开始SFI暴力破解");

    for (uint8_t sfi = 1; sfi <= 31; sfi++) {

        PrintAndLogEx(NORMAL, "." NOLF);

        for (uint16_t rec = 1; rec <= 255; rec++) {

            if (kbd_enter_pressed()) {
                PrintAndLogEx(WARNING, "\\n通过键盘中止！\\n");
                free(buf);
                return 1;
            }

            READ_RECORD[2] = rec;
            READ_RECORD[3] = (sfi << 3) | 4;

            smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) +  sizeof(READ_RECORD));
            if (payload == NULL) {
                PrintAndLogEx(WARNING, "分配内存失败");
                free(buf);
                return 1;
            }
            payload->flags = SC_RAW_T0;
            payload->len = sizeof(READ_RECORD);
            payload->wait_delay = 0;
            memcpy(payload->data, READ_RECORD, sizeof(READ_RECORD));

            clearCommandBuffer();
            SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) +  sizeof(READ_RECORD));

            len = smart_responseEx(buf, PM3_CMD_DATA_SIZE, false);

            if (buf[0] == 0x6C) {
                READ_RECORD[4] = buf[1];

                memcpy(payload->data, READ_RECORD, sizeof(READ_RECORD));
                clearCommandBuffer();
                SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) +  sizeof(READ_RECORD));
                len = smart_responseEx(buf, PM3_CMD_DATA_SIZE, false);

                READ_RECORD[4] = 0;
            }

            free(payload);

            if (len > 4) {

                PrintAndLogEx(SUCCESS, "\\n\\t 文件 %02d，记录 %02d 找到", sfi, rec);

                uint8_t modifier = (buf[0] == 0xC0) ? 1 : 0;

                if (decodeTLV) {
                    if (!TLVPrintFromBuffer(buf + modifier, len - 2 - modifier)) {
                        PrintAndLogEx(SUCCESS, "\tHEX: %s", sprint_hex(buf, len));
                    }
                }
            }
            memset(buf, 0x00, PM3_CMD_DATA_SIZE);
        }
    }
    free(buf);
    return 0;
}

static void smart_brute_options(bool decodeTLV) {

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (buf == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return;
    }

    // Get processing options command
    uint8_t GET_PROCESSING_OPTIONS[] = {0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00};

    smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + sizeof(GET_PROCESSING_OPTIONS));
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        free(buf);
        return;
    }
    payload->flags = SC_RAW_T0;
    payload->len = sizeof(GET_PROCESSING_OPTIONS);
    memcpy(payload->data, GET_PROCESSING_OPTIONS, sizeof(GET_PROCESSING_OPTIONS));

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + sizeof(GET_PROCESSING_OPTIONS));
    free(payload);

    int len = smart_responseEx(buf, PM3_CMD_DATA_SIZE, false);
    if (len > 4) {
        PrintAndLogEx(SUCCESS, "已获取处理选项");
        if (decodeTLV) {
            TLVPrintFromBuffer(buf, len - 2);
        }
    } else {
        PrintAndLogEx(FAILED, "获取处理选项失败");
    }

    free(buf);
}

static int CmdSmartBruteforceSFI(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "智能暴力破解",
                  "尝试使用已知的AID列表暴力破解SFI",
                  "smart brute -t"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("t", "tlv", "如果可能，执行TLV解码器"),
//        arg_lit0("0", NULL, "use protocol T=0"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool decode_tlv = arg_get_lit(ctx, 1);
//    bool use_t0 = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    const char *SELECT = "00a40400%02zu%s";

//  uint8_t GENERATE_AC[] = {0x80, 0xAE};
//  uint8_t GET_CHALLENGE[] = {0x00, 0x84, 0x00};
//  uint8_t GET_DATA[] = {0x80, 0xCA, 0x00, 0x00, 0x00};
//  uint8_t SELECT[] = {0x00, 0xA4, 0x04, 0x00};
//  uint8_t UNBLOCK_PIN[] = {0x84, 0x24, 0x00, 0x00, 0x00};
//  uint8_t VERIFY[] = {0x00, 0x20, 0x00, 0x80};

    PrintAndLogEx(INFO, "正在导入AID列表");
    json_t *root = NULL;
    smart_loadjson("aidlist", &root);

    uint8_t *buf = calloc(PM3_CMD_DATA_SIZE, sizeof(uint8_t));
    if (buf == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "正在选择卡片");
    if (!smart_select(false, NULL)) {
        free(buf);
        return PM3_ESOFT;
    }

    char *caid = NULL;

    for (int i = 0; i < json_array_size(root); i++) {

        PrintAndLogEx(NORMAL, "+" NOLF);

        if (caid)
            free(caid);

        json_t *data, *jaid;

        data = json_array_get(root, i);
        if (json_is_object(data) == false) {
            PrintAndLogEx(ERR, "\\n数据 %d 不是对象\\n", i + 1);
            json_decref(root);
            free(buf);
            return PM3_ESOFT;
        }

        jaid = json_object_get(data, "AID");
        if (json_is_string(jaid) == false) {
            PrintAndLogEx(ERR, "\\nAID数据[%d]不是字符串", i + 1);
            json_decref(root);
            free(buf);
            return PM3_ESOFT;
        }

        const char *aid = json_string_value(jaid);
        if (aid == false)
            continue;

        size_t aidlen = strlen(aid);
        caid = calloc(8 + 2 + aidlen + 1, sizeof(uint8_t));
        if (caid == NULL) {
            PrintAndLogEx(WARNING, "分配内存失败");
            json_decref(root);
            free(buf);
            return PM3_EMALLOC;
        }
        snprintf(caid, 8 + 2 + aidlen + 1, SELECT, aidlen >> 1, aid);

        int hexlen = 0;
        uint8_t cmddata[PM3_CMD_DATA_SIZE];
        int res = param_gethex_to_eol(caid, 0, cmddata, sizeof(cmddata), &hexlen);
        if (res)
            continue;

        smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + hexlen);
        if (payload == NULL) {
            PrintAndLogEx(WARNING, "分配内存失败");
            json_decref(root);
            free(buf);
            return PM3_EMALLOC;
        }
        payload->flags = SC_RAW_T0;
        payload->len = hexlen;
        payload->wait_delay = 0;
        memcpy(payload->data, cmddata, hexlen);
        clearCommandBuffer();
        SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + hexlen);
        free(payload);

        int len = smart_responseEx(buf, PM3_CMD_DATA_SIZE, false);
        if (len < 3)
            continue;

        json_t *jvendor, *jname;
        jvendor = json_object_get(data, "Vendor");
        if (json_is_string(jvendor) == false) {
            PrintAndLogEx(ERR, "厂商数据 [%d] 不是字符串", i + 1);
            continue;
        }

        const char *vendor = json_string_value(jvendor);
        if (!vendor)
            continue;

        jname = json_object_get(data, "Name");
        if (json_is_string(jname) == false) {
            PrintAndLogEx(ERR, "名称数据 [%d] 不是字符串", i + 1);
            continue;
        }
        const char *name = json_string_value(jname);
        if (!name)
            continue;

        PrintAndLogEx(SUCCESS, "\nAID %s | %s | %s", aid, vendor, name);

        smart_brute_options(decode_tlv);

        smart_brute_prim();

        smart_brute_sfi(decode_tlv);

        PrintAndLogEx(SUCCESS, "\\nSFI暴力破解完成\\n");
    }

    if (caid)
        free(caid);

    free(buf);
    json_decref(root);

    PrintAndLogEx(SUCCESS, "\\n搜索完成。");
    return PM3_SUCCESS;
}

static int CmdPCSC(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "智能卡 PCSC",
                  "通过 vpcd 使 pm3 对主机操作系统智能卡驱动程序可用，以便与其他软件（如 GlobalPlatform Pro）一起使用",
                  "Requires the virtual smartcard daemon to be installed and running\n"
                  "  see https://frankmorgner.github.io/vsmartcard/virtualsmartcard/README.html\n"
                  "note:\n"
                  "  `-v` shows APDU transactions between OS and card\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "host", "<str>", "vpcd socket host (default: localhost)"),
        arg_str0("p", "port", "<int>", "vpcd套接字端口（默认：35963）"),
        arg_lit0("v", "详细", "显示操作系统与卡片之间的APDU事务"),
        arg_lit0("a", NULL, "use ISO 14443A contactless interface"),
        arg_lit0("b", NULL, "use ISO 14443B contactless interface"),
//        arg_lit0("v", NULL, "use ISO 15693 contactless interface"),
        arg_lit0("c", NULL, "use ISO 7816 contact interface"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t host[100] = {0};
    int hostLen = sizeof(host) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
    CLIGetStrWithReturn(ctx, 1, host, &hostLen);
    if (hostLen == 0) {
        strcpy((char *) host, "localhost");
    }

    uint8_t port[7] = {0};
    int portLen = sizeof(port) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
    CLIGetStrWithReturn(ctx, 2, port, &portLen);
    if (portLen == 0) {
        strcpy((char *) port, "35963");
    }

    bool verbose = arg_get_lit(ctx, 3);
    bool use14a = arg_get_lit(ctx, 4);
    bool use14b = arg_get_lit(ctx, 5);
//    bool use15 = arg_get_lit(ctx, 6);
    bool use_contact = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    mbedtls_net_context netCtx;
    mbedtls_net_init(&netCtx);

    PrintAndLogEx(INFO, "将PM3中继到主机操作系统pcsc守护进程");
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");

    uint8_t cmdbuf[512] = {0};
    iso14a_card_select_t card14a;
    iso14b_card_select_t card14b;
    smart_card_atr_t card;

    bool have_card = false;
    Iso7816CommandChannel card_type = CC_CONTACT;
    isodep_state_t cl_proto = ISODEP_INACTIVE;
    bool field_activated = false;

    // main loop
    do {

        if (have_card) {
            int bytes_read = mbedtls_net_recv_timeout(&netCtx, cmdbuf, sizeof(cmdbuf), 100);

            if (bytes_read == MBEDTLS_ERR_SSL_TIMEOUT || bytes_read == MBEDTLS_ERR_SSL_WANT_READ) {
                continue;
            }

            if (bytes_read > 0) {

                if (cmdbuf[1] == 0x01 && cmdbuf[2] == 0x04) { // vpcd GET ATR
                    uint8_t atr[256] = {0};
                    int atrLen = 0;

                    switch (card_type) {
                        case CC_CONTACT: {
                            memcpy(atr, card.atr, card.atr_len);
                            atrLen = card.atr_len;
                            break;
                        }
                        case CC_CONTACTLESS: {

                            if (cl_proto == ISODEP_NFCA) {
                                atsToEmulatedAtr(card14a.ats, atr, &atrLen);
                            }
                            if (cl_proto == ISODEP_NFCB) {
                                atqbToEmulatedAtr(card14b.atqb, card14b.cid, atr, &atrLen);
                            }
                            if (cl_proto == ISODEP_NFCV) {
                                // Not implemented
                            }
                            break;
                        }
                        default: {
                            break;
                        }
                    }

                    // ISO 7816-3 specifies that ATRs can be 2 to 33 bytes long
                    // but some custom cards may support up to 256 bytes long ATRs
                    uint8_t res[2 + 256] = {0};
                    res[1] = atrLen;
                    memcpy(res + 2, atr, atrLen);
                    mbedtls_net_send(&netCtx, res, 2 + atrLen);

                } else if (cmdbuf[1] != 0x01) { // vpcd APDU
                    int apduLen = (cmdbuf[0] << 8) + cmdbuf[1];

                    uint8_t apduRes[APDU_RES_LEN] = {0};
                    int apduResLen = 0;

                    if (verbose) {
                        PrintAndLogEx(INFO, ">> %s", sprint_hex(cmdbuf + 2, apduLen));
                    }

                    switch (card_type) {
                        case CC_CONTACT: {
                            if (ExchangeAPDUSC(false, cmdbuf + 2, apduLen, !field_activated, true, apduRes, sizeof(apduRes), &apduResLen) != PM3_SUCCESS) {
                                have_card = false;
                                mbedtls_net_close(&netCtx);
                                continue;
                            }
                            break;
                        }
                        case CC_CONTACTLESS: {

                            if (cl_proto == ISODEP_NFCA) {
                                if (ExchangeAPDU14a(cmdbuf + 2, apduLen, !field_activated, true, apduRes, sizeof(apduRes), &apduResLen) != PM3_SUCCESS) {
                                    have_card = false;
                                    mbedtls_net_close(&netCtx);
                                    continue;
                                }
                            }
                            if (cl_proto == ISODEP_NFCB) {

                                if (exchange_14b_apdu(cmdbuf + 2, apduLen, !field_activated, true, apduRes, sizeof(apduRes), &apduResLen, 0))   {
                                    have_card = false;
                                    mbedtls_net_close(&netCtx);
                                    continue;
                                }
                            }
                            if (cl_proto == ISODEP_NFCV) {
                                // Not implemented
                            }
                            break;
                        }

                        default: {
                            break;
                        }
                    }

                    field_activated = true;

                    if (verbose) {
                        PrintAndLogEx(INFO, "<< %s", sprint_hex(apduRes, apduResLen));
                    }

                    uint8_t res[APDU_RES_LEN + 2] = {0};
                    res[0] = (apduResLen >> 8) & 0xFF;
                    res[1] = apduResLen & 0xFF;
                    memcpy(res + 2, apduRes, apduResLen);
                    mbedtls_net_send(&netCtx, res, 2 + apduResLen);
                }
            }
        } else {

            if (use14a && IfPm3Iso14443a() && SelectCard14443A_4(false, false, &card14a) == PM3_SUCCESS) {
                have_card = true;
                card_type = CC_CONTACTLESS;
                cl_proto = ISODEP_NFCA;
            }

            if (use14b && IfPm3Iso14443b() && select_card_14443b_4(false, &card14b) == PM3_SUCCESS) {
                have_card = true;
                card_type = CC_CONTACTLESS;
                cl_proto = ISODEP_NFCB;
            }

            // ISO 15.

            if (use_contact && IfPm3Iso14443() && smart_select(false, &card)) {
                have_card = true;
                card_type = CC_CONTACT;
            }

            if (have_card) {
                field_activated = false;
                if (mbedtls_net_connect(&netCtx, (char *) host, (char *) port, MBEDTLS_NET_PROTO_TCP)) {
                    PrintAndLogEx(FAILED, "连接到vpcd套接字失败。请确保已安装并运行vpcd");
                    mbedtls_net_close(&netCtx);
                    mbedtls_net_free(&netCtx);
                    DropField();
                    return PM3_EINVARG;
                }
            }
            msleep(300);
        }

    } while (kbd_enter_pressed() == false);

    mbedtls_net_close(&netCtx);
    mbedtls_net_free(&netCtx);
    DropField();

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"----------", CmdHelp,               IfPm3Iso14443a,  "------------------- " _CYAN_("常规") " -------------------"},
    {"help",       CmdHelp,               AlwaysAvailable, "此帮助"},
    {"list",       CmdSmartList,          AlwaysAvailable, "列出ISO 7816历史"},
    {"----------", CmdHelp,               IfPm3Iso14443a,  "------------------- " _CYAN_("操作") " -------------------"},
    {"brute",      CmdSmartBruteforceSFI, IfPm3Smartcard,  "暴力破解SFI"},
    {"info",       CmdSmartInfo,          IfPm3Smartcard,  "标签信息"},
    {"pcsc",       CmdPCSC,               AlwaysAvailable, "将pm3转换为pcsc读卡器并通过vpcd中继到主机操作系统"},
    {"reader",     CmdSmartReader,        IfPm3Smartcard,  "模拟 IS07816 读取器"},
    {"raw",        CmdSmartRaw,           IfPm3Smartcard,  "向标签发送原始十六进制数据"},
    {"upgrade",    CmdSmartUpgrade,       AlwaysAvailable, "升级模拟模块固件"},
    {"setclock",   CmdSmartSetClock,      IfPm3Smartcard,  "设置时钟速度"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdSmartcard(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int ExchangeAPDUSC(bool verbose, uint8_t *datain, int datainlen, bool activateCard, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {

    *dataoutlen = 0;

    smart_card_raw_t *payload = calloc(1, sizeof(smart_card_raw_t) + datainlen);
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }
    payload->flags = (SC_RAW_T0 | SC_LOG);
    if (activateCard) {
        payload->flags |= (SC_SELECT | SC_CONNECT);
    }
    payload->len = datainlen;
    payload->wait_delay = 0;
    memcpy(payload->data, datain, datainlen);

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + datainlen);

    int len = smart_responseEx(dataout, maxdataoutlen, verbose);
    if (len < 0) {
        free(payload);
        return PM3_ESOFT;
    }

    // retry
    if (len > 1 && dataout[len - 2] == 0x6c && datainlen > 4) {

        payload->flags = SC_RAW_T0;
        payload->len = 5;
        // transfer length via T=0
        datain[4] = dataout[len - 1];
        memcpy(payload->data, datain, 5);
        clearCommandBuffer();
        SendCommandNG(CMD_SMART_RAW, (uint8_t *)payload, sizeof(smart_card_raw_t) + 5);
        datain[4] = 0;
        len = smart_responseEx(dataout, maxdataoutlen, verbose);
        if (len < 0) {
            free(payload);
            return PM3_ESOFT;
        }
    }

    free(payload);
    *dataoutlen = len;
    return PM3_SUCCESS;
}

bool smart_select(bool verbose, smart_card_atr_t *atr) {
    if (atr) {
        memset(atr, 0, sizeof(smart_card_atr_t));
    }

    clearCommandBuffer();
    SendCommandNG(CMD_SMART_ATR, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SMART_ATR, &resp, 2500) == false) {
        if (verbose) PrintAndLogEx(WARNING, "智能卡选择超时");
        return false;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) PrintAndLogEx(WARNING, "智能卡选择失败");
        return false;
    }

    smart_card_atr_t card;
    memcpy(&card, (smart_card_atr_t *)resp.data.asBytes, sizeof(smart_card_atr_t));

    if (atr) {
        memcpy(atr, &card, sizeof(smart_card_atr_t));
    }

    if (verbose)
        PrintAndLogEx(INFO, "ISO7816-3 ATR : %s", sprint_hex(card.atr, card.atr_len));

    return true;
}
