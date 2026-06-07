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
// High frequency FIDO U2F and FIDO2 contactless authenticators
//-----------------------------------------------------------------------------
//
//  Documentation here:
//
// FIDO Alliance specifications
// https://fidoalliance.org/download/
// FIDO NFC Protocol Specification v1.0
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-nfc-protocol-v1.2-ps-20170411.html
// FIDO U2F Raw Message Formats
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
//-----------------------------------------------------------------------------

#include "cmdhffido.h"
#include <unistd.h>
#include "cmdparser.h"    // command_t
#include "commonutil.h"
#include "comms.h"
#include "proxmark3.h"
#include "iso7816/iso7816core.h"
#include "emv/emvjson.h"
#include "cliparser.h"
#include "crypto/asn1utils.h"
#include "crypto/libpcrypto.h"
#include "fido/cbortools.h"
#include "fido/fidocore.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "cmdtrace.h"
#include "util.h"
#include "fileutils.h"   // laodFileJSONroot
#include "protocols.h"   // ISO7816 APDU return codes

#define DEF_FIDO_SIZE        2048
#define DEF_FIDO_PARAM_FILE  "hf_fido2_defparams.json"

static int CmdHelp(const char *Cmd);

static int CmdHFFidoList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf fido", "14a");
}

static int CmdHFFidoInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fido 信息",
                  "从Fido标签获取信息。",
                  "hf fido 信息");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // info about 14a part
    infoHF14A(false, false, false);

    // FIDO info
    PrintAndLogEx(INFO, "-----------" _CYAN_("FIDO Info") "---------------------------------");
    SetAPDULogging(false);

    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res) {
        DropField();
        return res;
    }

    if (sw != ISO7816_OK) {
        if (sw) {
            PrintAndLogEx(INFO, "不是 FIDO 卡。APDU 响应: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        } else {
            PrintAndLogEx(ERR, "APDU交换错误。卡片返回0x0000");
        }
        DropField();
        return PM3_SUCCESS;
    }

    if (strncmp((char *)buf, "U2F_V2", 7) == 0) {
        if (strncmp((char *)buf, "FIDO_2_0", 8) == 0) {
            PrintAndLogEx(INFO, "FIDO2认证器");
            PrintAndLogEx(INFO, "Version... " _YELLOW_("%.*s"), (int)len, buf);
        } else {
            PrintAndLogEx(INFO, "FIDO认证器（非标准U2F）");
            PrintAndLogEx(INFO, "非 U2F 认证器");
            PrintAndLogEx(INFO, "version... ");
            print_buffer((const unsigned char *)buf, len, 1);
        }
    } else {
        PrintAndLogEx(INFO, "检测到FIDO U2F认证器");
        PrintAndLogEx(INFO, "Version... " _YELLOW_("%.*s"), (int)len, buf);
    }

    res = FIDO2GetInfo(buf, sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "FIDO2版本不存在（%04x - %s）。", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_SUCCESS;
    }

    if (buf[0]) {
        PrintAndLogEx(ERR, "FIDO2获取版本错误：%d - %s", buf[0], fido2GetCmdErrorDescription(buf[0]));
        return PM3_SUCCESS;
    }

    if (len > 1) {
        PrintAndLogEx(SUCCESS, "FIDO2版本CBOR解码：");
        TinyCborPrintFIDOPackage(fido2CmdGetInfo, true, &buf[1], len - 1);
    } else {
        PrintAndLogEx(ERR, "FIDO2版本长度错误");
    }
    return PM3_SUCCESS;
}

static int CmdHFFidoRegister(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fido 注册",
                  "启动U2F令牌注册。需要两个32字节哈希数。\\n"
                  "challenge parameter (32b) and application parameter (32b).\n"
                  "The default config filename is  `fido2_defparams.json`\n"
                  "note:\n"
                  "   `-vv` shows  full certificates data\n"
                  "\n",
                  "hf fido reg                   -> execute command with 2 parameters, filled 0x00\n"
                  "hf fido reg --cp s0 --ap s1   -> execute command with plain parameters\n"
                  "hf fido reg --cpx 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f --apx 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f\n"
                  "hf fido reg -f fido2-params   -> execute command with custom config file\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu", "显示 APDU 请求和响应"),
        arg_litn("v",  "详细",  0, 2, "详细输出"),
        arg_lit0("t",  "tlv",  "以TLV表示显示DER证书内容"),
        arg_str0("f",  "file", "<fn>",  "参数的JSON输入文件名"),
        arg_str0(NULL, "cp",   "<str>", "Challenge parameter (1..16 chars)"),
        arg_str0(NULL, "ap",   "<str>", "Application parameter (1..16 chars)"),
        arg_str0(NULL, "cpx",  "<hex>", "Challenge parameter (32 bytes hex)"),
        arg_str0(NULL, "apx",  "<hex>", "Application parameter (32 bytes hex)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool verbose2 = arg_get_lit(ctx, 2) > 1;
    bool showDERTLV = arg_get_lit(ctx, 3);
    bool cpplain = arg_get_str_len(ctx, 5);
    bool applain = arg_get_str_len(ctx, 6);
    bool cphex = arg_get_str_len(ctx, 7);
    bool aphex = arg_get_str_len(ctx, 8);

    uint8_t data[64] = {0};
    int chlen = 0;
    uint8_t cdata[250] = {0};
    int applen = 0;
    uint8_t adata[250] = {0};

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    // default name
    if (fnlen == 0) {
        strcat(filename, DEF_FIDO_PARAM_FILE);
        fnlen = strlen(filename);
    }

    json_t *root = NULL;
    int res = loadFileJSONroot(filename, (void **)&root, verbose);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    size_t jlen = 0;
    JsonLoadBufAsHex(root, "$.ChallengeParam", data, 32, &jlen);
    JsonLoadBufAsHex(root, "$.ApplicationParam", &data[32], 32, &jlen);

    if (cpplain) {
        memset(cdata, 0x00, 32);
        chlen = sizeof(cdata) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
        CLIGetStrWithReturn(ctx, 5, cdata, &chlen);
        if (chlen > 16) {
            PrintAndLogEx(ERR, "错误：ASCII 模式下的挑战参数长度必须小于 16 个字符，实际为：%d", chlen);
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (cphex && cpplain == false) {
        chlen = sizeof(cdata);
        CLIGetHexWithReturn(ctx, 7, cdata, &chlen);
        if (chlen && chlen != 32) {
            PrintAndLogEx(ERR, "错误：挑战参数长度必须为 32 字节。");
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (chlen)
        memmove(data, cdata, 32);

    if (applain) {
        memset(adata, 0x00, 32);
        applen = sizeof(adata) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
        CLIGetStrWithReturn(ctx, 6, adata, &applen);
        if (applen > 16) {
            PrintAndLogEx(ERR, "错误：ASCII 模式下的应用参数长度必须小于 16 个字符，实际为：%d", applen);
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (aphex && applain == false) {
        applen = sizeof(adata);
        CLIGetHexWithReturn(ctx, 8, adata, &applen);
        if (applen && applen != 32) {
            PrintAndLogEx(ERR, "错误：应用参数长度必须为 32 字节。");
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (applen) {
        memmove(&data[32], adata, 32);
    }

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);

    // challenge parameter [32 bytes] - The challenge parameter is the SHA-256 hash of the Client Data, a stringified JSON data structure that the FIDO Client prepares
    // application parameter [32 bytes] - The application parameter is the SHA-256 hash of the UTF-8 encoding of the application identity

    uint8_t buf[2048] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);

    if (res) {
        PrintAndLogEx(ERR, "无法选择验证器。res=%x。退出...", res);
        DropField();
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "无法选择FIDO应用。APDU响应状态：%04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        json_decref(root);
        return PM3_ESOFT;
    }

    res = FIDORegister(data, buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLogEx(ERR, "无法执行注册命令。res=%x。退出...", res);
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "错误：执行注册命令。APDU响应状态：%04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    if (APDULogging)
        PrintAndLogEx(INFO, "---------------------------------------------------------------");

    PrintAndLogEx(INFO, "数据长度：%zu", len);

    if (verbose2) {
        PrintAndLogEx(INFO, "------------ " _CYAN_("数据") " ----------------------");
        print_buffer((const unsigned char *)buf, len, 1);
        PrintAndLogEx(INFO, "-------------" _CYAN_("数据") " ----------------------");
    }

    if (buf[0] != 0x05) {
        PrintAndLogEx(ERR, "错误：第一个字节必须为0x05，但实际为%2x", buf[0]);
        json_decref(root);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "用户公钥: %s", sprint_hex(&buf[1], 65));

    uint8_t keyHandleLen = buf[66];
    PrintAndLogEx(SUCCESS, "密钥句柄[%d]: %s", keyHandleLen, sprint_hex(&buf[67], keyHandleLen));

    int derp = 67 + keyHandleLen;
    int derLen = (buf[derp + 2] << 8) + buf[derp + 3] + 4;
    if (verbose2) {
        PrintAndLogEx(INFO, "DER 证书[%d]:", derLen);
        PrintAndLogEx(INFO, "------------------DER-------------------");
        PrintAndLogEx(INFO, "%s", sprint_hex(buf + derp, derLen));
        PrintAndLogEx(INFO, "----------------DER---------------------");
    } else {
        if (verbose)
            PrintAndLogEx(INFO, "------------------DER-------------------");
        PrintAndLogEx(INFO, "DER 证书[%d]: %s...", derLen, sprint_hex(&buf[derp], 20));
    }

    // check and print DER certificate
    uint8_t public_key[65] = {0};

    // print DER certificate in TLV view
    if (showDERTLV) {
        PrintAndLogEx(INFO, "----------------DER TLV-----------------");
        asn1_print(&buf[derp], derLen, "  ");
        PrintAndLogEx(INFO, "----------------DER TLV-----------------");
    }

    FIDOCheckDERAndGetKey(&buf[derp], derLen, verbose, public_key, sizeof(public_key));

    // get hash
    int hashp = 1 + 65 + 1 + keyHandleLen + derLen;
    PrintAndLogEx(SUCCESS, "Hash[%zu]: %s", len - hashp, sprint_hex(&buf[hashp], len - hashp));

    // check ANSI X9.62 format ECDSA signature (on P-256)
    uint8_t rval[300] = {0};
    uint8_t sval[300] = {0};
    res = ecdsa_asn1_get_signature(&buf[hashp], len - hashp, rval, sval);
    if (res == PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(INFO, "  r: %s", sprint_hex(rval, 32));
            PrintAndLogEx(INFO, "  s: %s", sprint_hex(sval, 32));
        }

        uint8_t xbuf[4096] = {0};
        size_t xbuflen = 0;
        res = FillBuffer(xbuf, sizeof(xbuf), &xbuflen,
                         "\x00", 1,
                         &data[32], 32,           // application parameter
                         &data[0], 32,            // challenge parameter
                         &buf[67], keyHandleLen,  // keyHandle
                         &buf[1], 65,             // user public key
                         (uint8_t *)NULL, 0);
        (void)res;
        //PrintAndLogEx(INFO, "--xbuf(%d)[%d]: %s", res, xbuflen, sprint_hex(xbuf, xbuflen));
        res = ecdsa_signature_verify(MBEDTLS_ECP_DP_SECP256R1, public_key, xbuf, xbuflen, &buf[hashp], len - hashp, true);
        if (res) {
            if (res == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
                PrintAndLogEx(WARNING, "Signature is ( " _RED_("not valid") " )");
            } else {
                PrintAndLogEx(WARNING, "其他签名检查错误: %x %s", (res < 0) ? -res : res, ecdsa_get_error(res));
            }
        } else {
            PrintAndLogEx(SUCCESS, "Signature is ( " _GREEN_("ok") " )");
        }

    } else {
        PrintAndLogEx(WARNING, "Invalid signature. res = %d. ( " _RED_("fail") " )", res);
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "auth command: ");
    char command[500] = {0};
    snprintf(command, sizeof(command), "hf fido auth --kh %s", sprint_hex_inrow(&buf[67], keyHandleLen));
    if (chlen) {
        size_t command_len = strlen(command);
        snprintf(command + command_len, sizeof(command) - command_len, " --%s %s", cpplain ? "cp" : "cpx", cpplain ? (char *)cdata : sprint_hex_inrow(cdata, 32));
    }
    if (applen) {
        size_t command_len = strlen(command);
        snprintf(command + command_len, sizeof(command) - command_len, " --%s %s", applain ? "cp" : "cpx", applain ? (char *)adata : sprint_hex_inrow(adata, 32));
    }
    PrintAndLogEx(INFO, "%s", command);

    if (root) {
        JsonSaveBufAsHex(root, "ChallengeParam", data, 32);
        JsonSaveBufAsHex(root, "ApplicationParam", &data[32], 32);
        JsonSaveBufAsHexCompact(root, "PublicKey", &buf[1], 65);
        JsonSaveInt(root, "KeyHandleLen", keyHandleLen);
        JsonSaveBufAsHexCompact(root, "KeyHandle", &buf[67], keyHandleLen);
        JsonSaveBufAsHexCompact(root, "DER", &buf[67 + keyHandleLen], derLen);

        res = saveFileJSONrootEx(filename, root, JSON_INDENT(2), verbose, true, spDump);
        (void)res;
    }
    json_decref(root);
    return PM3_SUCCESS;
}

static int CmdHFFidoAuthenticate(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fido 认证",
                  "启动U2F令牌认证。需要密钥句柄和两个32字节哈希数。\\n"
                  "key handle(var 0..255), challenge parameter (32b) and application parameter (32b)\n"
                  "The default config filename is  `fido2_defparams.json`\n"
                  "\n",
                  "hf fido auth --kh 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f -> execute command with 2 parameters, filled 0x00 and key handle\n"
                  "hf fido auth \n"
                  "--kh 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f\n"
                  "--cpx 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f \n"
                  "--apx 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f -> execute command with parameters");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",      "显示 APDU 请求和响应"),
        arg_lit0("v",  "详细",   "详细输出"),
        arg_rem("default mode:",    "不强制用户存在并签名"),
        arg_lit0("u",  "user",      "模式：强制用户存在并签名"),
        arg_lit0("c",  "check",     "模式：仅检查"),
        arg_str0("f",  "file",  "<fn>",  "参数的JSON文件名"),
        arg_str0("k",  "key",   "<hex>", "用于验证签名的公钥"),
        arg_str0(NULL, "kh",    "<hex>", "Key handle (var 0..255b)"),
        arg_str0(NULL, "cp",    "<str>", "Challenge parameter (1..16 chars)"),
        arg_str0(NULL, "ap",    "<str>", "Application parameter (1..16 chars)"),
        arg_str0(NULL, "cpx",   "<hex>", "Challenge parameter (32 bytes hex)"),
        arg_str0(NULL, "apx",   "<hex>", "Application parameter (32 bytes hex)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);

    uint8_t controlByte = 0x08;
    if (arg_get_lit(ctx, 4))
        controlByte = 0x03;

    if (arg_get_lit(ctx, 5))
        controlByte = 0x07;

    uint8_t data[512] = {0};
    uint8_t hdata[256] = {0};
    bool public_key_loaded = false;
    uint8_t public_key[65] = {0};
    int hdatalen = 0;
    uint8_t keyHandleLen = 0;

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    // default name
    if (fnlen == 0) {
        strcat(filename, DEF_FIDO_PARAM_FILE);
        fnlen = strlen(filename);
    }

    json_t *root = NULL;
    int res = loadFileJSONroot(filename, (void **)&root, verbose);
    if (res != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    size_t jlen = 0;
    JsonLoadBufAsHex(root, "$.ChallengeParam", data, 32, &jlen);
    JsonLoadBufAsHex(root, "$.ApplicationParam", &data[32], 32, &jlen);
    JsonLoadBufAsHex(root, "$.KeyHandle", &data[65], 512 - 67, &jlen);
    keyHandleLen = jlen & 0xff;
    data[64] = keyHandleLen;
    JsonLoadBufAsHex(root, "$.PublicKey", public_key, 65, &jlen);
    public_key_loaded = (jlen > 0);

    // public key
    CLIGetHexWithReturn(ctx, 7, hdata, &hdatalen);
    if (hdatalen && hdatalen != 65) {
        PrintAndLogEx(ERR, "错误：公钥长度必须仅为65字节。");
        CLIParserFree(ctx);
        json_decref(root);
        return PM3_EINVARG;
    }

    if (hdatalen) {
        memmove(public_key, hdata, hdatalen);
        public_key_loaded = true;
    }

    CLIGetHexWithReturn(ctx, 8, hdata, &hdatalen);
    if (hdatalen > 255) {
        PrintAndLogEx(ERR, "错误：密钥句柄长度必须小于255。");
        CLIParserFree(ctx);
        json_decref(root);
        return PM3_EINVARG;
    }

    printf("-- hlen=%d\n", hdatalen);
    if (hdatalen) {
        keyHandleLen = hdatalen;
        data[64] = keyHandleLen;
        memmove(&data[65], hdata, keyHandleLen);
        hdatalen = 0;
    }

    bool cpplain = arg_get_str_len(ctx, 9);
    bool applain = arg_get_str_len(ctx, 10);
    bool cphex = arg_get_str_len(ctx, 11);
    bool aphex = arg_get_str_len(ctx, 12);

    if (cpplain) {
        memset(hdata, 0x00, 32);
        hdatalen = sizeof(hdata) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
        CLIGetStrWithReturn(ctx, 9, hdata, &hdatalen);
        if (hdatalen > 16) {
            PrintAndLogEx(ERR, "错误：ASCII 模式下的挑战参数长度必须小于 16 个字符，实际为：%d", hdatalen);
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (cphex && cpplain == false) {
        hdatalen = sizeof(hdata);
        CLIGetHexWithReturn(ctx, 11, hdata, &hdatalen);
        if (hdatalen && hdatalen != 32) {
            PrintAndLogEx(ERR, "错误：挑战参数长度必须为 32 字节。");
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (hdatalen) {
        memmove(data, hdata, 32);
        hdatalen = 0;
    }

    if (applain) {
        memset(hdata, 0x00, 32);
        hdatalen = sizeof(hdata) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
        CLIGetStrWithReturn(ctx, 10, hdata, &hdatalen);
        if (hdatalen > 16) {
            PrintAndLogEx(ERR, "错误：ASCII 模式下的应用参数长度必须小于 16 个字符，实际为：%d", hdatalen);
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (aphex && applain == false) {
        hdatalen = sizeof(hdata);
        CLIGetHexWithReturn(ctx, 12, hdata, &hdatalen);
        if (hdatalen && hdatalen != 32) {
            PrintAndLogEx(ERR, "错误：应用参数长度必须为 32 字节。");
            CLIParserFree(ctx);
            json_decref(root);
            return PM3_EINVARG;
        }
    }
    if (hdatalen) {
        memmove(&data[32], hdata, 32);
        hdatalen = 0;
    }

    CLIParserFree(ctx);

    SetAPDULogging(APDULogging);

    // (in parameter) control byte 0x07 - check only, 0x03 - user presence + cign. 0x08 - sign only
    // challenge parameter [32 bytes]
    // application parameter [32 bytes]
    // key handle length [1b] = N
    // key handle [N]

    uint8_t datalen = 32 + 32 + 1 + keyHandleLen;

    uint8_t buf[2048] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res) {
        PrintAndLogEx(ERR, "无法选择验证器。res=%x。退出...", res);
        DropField();
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "无法选择FIDO应用。APDU响应状态：%04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        json_decref(root);
        return PM3_ESOFT;
    }

    res = FIDOAuthentication(data, datalen, controlByte,  buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLogEx(ERR, "无法执行认证命令。res=%x。退出...", res);
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "错误：执行认证命令。APDU响应状态：%04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        json_decref(root);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "---------------------------------------------------------------");
    PrintAndLogEx(SUCCESS, "用户存在: %s", (buf[0] ? "verified" : "not verified"));
    uint32_t cntr = (uint32_t)bytes_to_num(&buf[1], 4);
    PrintAndLogEx(SUCCESS, "计数器: %d", cntr);
    PrintAndLogEx(SUCCESS, "Hash[%zu]: %s", len - 5, sprint_hex(&buf[5], len - 5));

    // check ANSI X9.62 format ECDSA signature (on P-256)
    uint8_t rval[300] = {0};
    uint8_t sval[300] = {0};
    res = ecdsa_asn1_get_signature(&buf[5], len - 5, rval, sval);
    if (res == PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(INFO, "  r: %s", sprint_hex(rval, 32));
            PrintAndLogEx(INFO, "  s: %s", sprint_hex(sval, 32));
        }
        if (public_key_loaded) {
            uint8_t xbuf[4096] = {0};
            size_t xbuflen = 0;
            res = FillBuffer(xbuf, sizeof(xbuf), &xbuflen,
                             &data[32], 32, // application parameter
                             &buf[0], 1,    // user presence
                             &buf[1], 4,    // counter
                             data, 32,      // challenge parameter
                             (uint8_t *)NULL, 0);
            (void)res;
            //PrintAndLogEx(INFO, "--xbuf(%d)[%d]: %s", res, xbuflen, sprint_hex(xbuf, xbuflen));
            res = ecdsa_signature_verify(MBEDTLS_ECP_DP_SECP256R1, public_key, xbuf, xbuflen, &buf[5], len - 5, true);
            if (res) {
                if (res == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
                    PrintAndLogEx(WARNING, "Signature is ( " _RED_("not valid") " )");
                } else {
                    PrintAndLogEx(WARNING, "其他签名检查错误: %x %s", (res < 0) ? -res : res, ecdsa_get_error(res));
                }
            } else {
                PrintAndLogEx(SUCCESS, "Signature is ( " _GREEN_("ok") " )");
            }
        } else {
            PrintAndLogEx(WARNING, "未提供公钥。无法检查签名。");
        }
    } else {
        PrintAndLogEx(WARNING, "Invalid signature. res = %d. ( " _RED_("fail") " )", res);
    }

    if (root) {
        JsonSaveBufAsHex(root, "ChallengeParam", data, 32);
        JsonSaveBufAsHex(root, "ApplicationParam", &data[32], 32);
        JsonSaveInt(root, "KeyHandleLen", keyHandleLen);
        JsonSaveBufAsHexCompact(root, "KeyHandle", &data[65], keyHandleLen);
        JsonSaveInt(root, "Counter", cntr);

        res = saveFileJSONrootEx(filename, root, JSON_INDENT(2), verbose, true, spDump);
        (void)res;
    }
    json_decref(root);
    return PM3_ESOFT;
}

static int CmdHFFido2MakeCredential(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fido 生成",
                  "执行FIDO2 Make Credential命令。需要包含参数的json文件。\\n"
                  "Sample file `fido2_defparams.json` in `client/resources/`.\n"
                  "- for yubikey there must be only one option `\"rk\": true` or false\n"
                  "note:\n"
                  "   `-vv` shows  full certificates data\n",
                  "hf fido make               --> use default parameters file `fido2_defparams.json`\n"
                  "hf fido make -f test.json  --> use parameters file `text.json`"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "apdu", "显示 APDU 请求和响应"),
        arg_litn("v", "详细", 0, 2, "详细输出"),
        arg_lit0("t", "tlv",  "以TLV表示显示DER证书内容"),
        arg_lit0("c", "cbor", "显示 CBOR 解码数据"),
        arg_str0("f", "file", "<fn>", "参数JSON文件名"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool verbose2 = arg_get_lit(ctx, 2) > 1;
    bool showDERTLV = arg_get_lit(ctx, 3);
    bool showCBOR = arg_get_lit(ctx, 4);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    // default name
    if (fnlen == 0) {
        strcat(filename, DEF_FIDO_PARAM_FILE);
        fnlen = strlen(filename);
    }

    json_t *root = NULL;
    loadFileJSONroot(filename, (void **)&root, verbose);
    if (root == NULL) {
        return PM3_EFILE;
    }

    SetAPDULogging(APDULogging);

    uint8_t data[DEF_FIDO_SIZE] = {0};
    size_t datalen = 0;
    uint8_t buf[DEF_FIDO_SIZE] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res) {
        PrintAndLogEx(ERR, "无法选择验证器。res=%x。退出...", res);
        DropField();
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "无法选择FIDO应用。APDU响应状态：%04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        json_decref(root);
        return PM3_ESOFT;
    }

    res = FIDO2CreateMakeCredentionalReq(root, data, sizeof(data), &datalen);
    if (res) {
        json_decref(root);
        return res;
    }

    if (showCBOR) {
        PrintAndLogEx(INFO, "CBOR 创建凭证请求：");
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
        TinyCborPrintFIDOPackage(fido2CmdMakeCredential, false, data, datalen);
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
    }

    res = FIDO2MakeCredential(data, datalen, buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLogEx(ERR, "无法执行生成凭证命令。res=%x。退出...", res);
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "错误：执行创建凭证命令。APDU响应状态：%04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        json_decref(root);
        return PM3_EFILE;
    }

    if (buf[0]) {
        PrintAndLogEx(ERR, "FIDO2创建凭证错误：%d - %s", buf[0], fido2GetCmdErrorDescription(buf[0]));
        json_decref(root);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "MakeCredential 结果 %zu 字节 ( 成功 )", len);
    if (showCBOR) {
        PrintAndLogEx(SUCCESS, "CBOR 创建凭证响应：");
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
        TinyCborPrintFIDOPackage(fido2CmdMakeCredential, true, &buf[1], len - 1);
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
    }

    // parse returned cbor
    FIDO2MakeCredentionalParseRes(root, &buf[1], len - 1, verbose, verbose2, showCBOR, showDERTLV);

    res = saveFileJSONrootEx(filename, root, JSON_INDENT(2), verbose, true, spDump);
    (void)res;
    json_decref(root);
    return res;
}

static int CmdHFFido2GetAssertion(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fido 断言",
                  "执行FIDO2 Get Assertion命令。需要包含参数的json文件。\\n"
                  "Sample file `fido2_defparams.json` in `client/resources/`.\n"
                  "- Needs if `rk` option is `false` (authenticator doesn't store credential to its memory)\n"
                  "- for yubikey there must be only one option `\"up\": true` or false\n"
                  "note:\n"
                  "   `-vv` shows  full certificates data\n",
                  "hf fido assert                  --> default parameters file `fido2_defparams.json`\n"
                  "hf fido assert -f test.json -l  --> use parameters file `text.json` and add to request CredentialId");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "apdu", "显示 APDU 请求和响应"),
        arg_litn("v", "详细", 0, 2, "详细输出"),
        arg_lit0("c", "cbor", "显示 CBOR 解码数据"),
        arg_lit0("l", "list", "从 json 添加 CredentialId 到允许列表"),
        arg_str0("f", "file", "<fn>", "参数JSON文件名"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    bool verbose = arg_get_lit(ctx, 2);
    bool verbose2 = arg_get_lit(ctx, 2) > 1;
    bool showCBOR = arg_get_lit(ctx, 3);
    bool createAllowList = arg_get_lit(ctx, 4);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    // default name
    if (fnlen == 0) {
        strcat(filename, DEF_FIDO_PARAM_FILE);
        fnlen = strlen(filename);
    }

    json_t *root = NULL;
    loadFileJSONroot(filename, (void **)&root, verbose);
    if (root == NULL) {
        return PM3_EFILE;
    }

    SetAPDULogging(APDULogging);

    uint8_t data[DEF_FIDO_SIZE] = {0};
    size_t datalen = 0;
    uint8_t buf[DEF_FIDO_SIZE] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    DropField();
    int res = FIDOSelect(true, true, buf, sizeof(buf), &len, &sw);
    if (res) {
        PrintAndLogEx(ERR, "无法选择验证器。res=%x。退出中...", res);
        DropField();
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "无法选择FIDO应用。APDU响应状态：%04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        json_decref(root);
        return PM3_ESOFT;
    }

    res = FIDO2CreateGetAssertionReq(root, data, sizeof(data), &datalen, createAllowList);
    if (res) {
        json_decref(root);
        return res;
    }

    if (showCBOR) {
        PrintAndLogEx(SUCCESS, "CBOR 获取断言请求：");
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
        TinyCborPrintFIDOPackage(fido2CmdGetAssertion, false, data, datalen);
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
    }

    res = FIDO2GetAssertion(data, datalen, buf,  sizeof(buf), &len, &sw);
    DropField();
    if (res) {
        PrintAndLogEx(ERR, "无法执行获取断言命令。res=%x。退出...", res);
        json_decref(root);
        return res;
    }

    if (sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "错误：执行获取断言命令。APDU响应状态：%04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        json_decref(root);
        return PM3_ESOFT;
    }

    if (buf[0]) {
        PrintAndLogEx(ERR, "FIDO2获取断言错误：%d - %s", buf[0], fido2GetCmdErrorDescription(buf[0]));
        json_decref(root);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "GetAssertion 结果 (%zu b) 正常。", len);
    if (showCBOR) {
        PrintAndLogEx(SUCCESS, "CBOR 获取断言响应：");
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
        TinyCborPrintFIDOPackage(fido2CmdGetAssertion, true, &buf[1], len - 1);
        PrintAndLogEx(INFO, "---------------- " _CYAN_("CBOR") " ------------------");
    }

    // parse returned cbor
    FIDO2GetAssertionParseRes(root, &buf[1], len - 1, verbose, verbose2, showCBOR);

    res = saveFileJSONrootEx(filename, root, JSON_INDENT(2), verbose, true, spDump);
    (void)res;
    json_decref(root);
    return res;
}

static command_t CommandTable[] = {
    {"help",      CmdHelp,                   AlwaysAvailable, "此帮助。"},
    {"list",      CmdHFFidoList,             AlwaysAvailable, "列出ISO 14443A历史"},
    {"-----------", CmdHelp,                   IfPm3Iso14443a,  "------------------- " _CYAN_("操作") " -------------------"},
    {"info",        CmdHFFidoInfo,             IfPm3Iso14443a,  "标签信息"},
    {"reg",       CmdHFFidoRegister,         IfPm3Iso14443a,  "FIDO U2F注册消息。"},
    {"auth",      CmdHFFidoAuthenticate,     IfPm3Iso14443a,  "FIDO U2F认证消息。"},
    {"make",      CmdHFFido2MakeCredential,  IfPm3Iso14443a,  "FIDO2 MakeCredential命令。"},
    {"assert",    CmdHFFido2GetAssertion,    IfPm3Iso14443a,  "FIDO2 GetAssertion命令。"},
    {NULL, NULL, 0, NULL}
};

int CmdHFFido(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
