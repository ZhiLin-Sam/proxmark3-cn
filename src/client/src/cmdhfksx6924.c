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
// Commands for KS X 6924 transit cards (T-Money, Snapper+)
//-----------------------------------------------------------------------------
// This is used in T-Money (South Korea) and Snapper plus (Wellington, New
// Zealand).
//
// References:
// - https://github.com/micolous/metrodroid/wiki/T-Money (in English)
// - https://github.com/micolous/metrodroid/wiki/Snapper (in English)
// - https://kssn.net/StdKS/ks_detail.asp?k1=X&k2=6924-1&k3=4
//   (KS X 6924, only available in Korean)
// - http://www.tta.or.kr/include/Download.jsp?filename=stnfile/TTAK.KO-12.0240_%5B2%5D.pdf
//   (TTAK.KO 12.0240, only available in Korean)
//-----------------------------------------------------------------------------


#include "cmdhfksx6924.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include "comms.h"
#include "cmdmain.h"
#include "util.h"
#include "ui.h"
#include "proxmark3.h"
#include "cliparser.h"
#include "ksx6924/ksx6924core.h"
#include "emv/tlv.h"
#include "iso7816/apduinfo.h"
#include "cmdhf14a.h"
#include "protocols.h"   // ISO7816 APDU return codes

static int CmdHelp(const char *Cmd);

static int get_and_print_balance(void) {
    uint32_t balance = 0;
    if (KSX6924GetBalance(&balance) == false) {
        PrintAndLogEx(ERR, "获取余额时出错");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Current balance: " _YELLOW_("%u") " won/cents", balance);
    return PM3_SUCCESS;
}

static int CmdHFKSX6924Balance(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 余额",
                  "获取当前钱包余额",
                  "hf ksx6924 balance\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "保持场开启以用于下一个命令"),
        arg_lit0("a", "apdu", "显示 APDU 请求和响应"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keep = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (KSX6924TrySelect()) {
        get_and_print_balance();
    }

    if (keep == false) {
        DropField();
    }

    return PM3_SUCCESS;
}

static int CmdHFKSX6924Info(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 信息",
                  "获取关于KS X 6924交通卡的信息。\\n"
                  "This application is used by T-Money (South Korea) and\n"
                  "Snapper+ (Wellington, New Zealand).",
                  "hf ksx6924 info\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "保持场开启以用于下一个命令"),
        arg_lit0("a", "apdu", "显示 APDU 请求和响应"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keep = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    // KSX6924 info
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = KSX6924Select(true, true, buf, sizeof(buf), &len, &sw);

    if (res || (len == 0)) {
        if (keep == false) {
            DropField();
        }
        return res;
    }

    if (sw != ISO7816_OK) {
        if (sw) {
            PrintAndLogEx(INFO, "不是 KS X 6924 卡！APDU 响应: %04x - %s",
                          sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        } else {
            PrintAndLogEx(ERR, "APDU交换错误。卡片返回0x0000。");
        }
        goto end;
    }


    // PrintAndLogEx(DEBUG, "APDU response: %s", sprint_hex(buf, len));

    // FCI Response is a BER-TLV, we are interested in tag 6F,B0 only.
    const uint8_t *p = buf;
    struct tlv fci_tag;
    memset(&fci_tag, 0, sizeof(fci_tag));

    while (len > 0) {
        memset(&fci_tag, 0, sizeof(fci_tag));
        bool ret = tlv_parse_tl(&p, &len, &fci_tag);

        if (!ret) {
            PrintAndLogEx(FAILED, "解析FCI错误！");
            goto end;
        }

        // PrintAndLog("tag %02x, len %d, value %s",
        //             fci_tag.tag, fci_tag.len,
        //             sprint_hex(p, fci_tag.len));

        if (fci_tag.tag == 0x6f) { /* FCI template */
            break;
        } else {
            p += fci_tag.len;
            continue;
        }
    }

    if (fci_tag.tag != 0x6f) {
        PrintAndLogEx(ERR, "在 SELECT 响应中找不到标签 6F (FCI)");
        goto end;
    }

    // We now are at Tag 6F (FCI template), get Tag B0 inside of it
    while (len > 0) {
        memset(&fci_tag, 0, sizeof(fci_tag));
        bool ret = tlv_parse_tl(&p, &len, &fci_tag);

        if (!ret) {
            PrintAndLogEx(ERR, "解析FCI错误！");
            goto end;
        }

        // PrintAndLog("tag %02x, len %d, value %s",
        //             fci_tag.tag, fci_tag.len,
        //             sprint_hex(p, fci_tag.len));

        if (fci_tag.tag == 0xb0) { /* KS X 6924 purse info */
            break;
        } else {
            p += fci_tag.len;
            continue;
        }
    }

    if (fci_tag.tag != 0xb0) {
        PrintAndLogEx(FAILED, "在 FCI 中找不到标签 B0 (KS X 6924 钱包信息)");
        goto end;
    }

    struct ksx6924_purse_info purseInfo;
    bool ret = KSX6924ParsePurseInfo(p, fci_tag.len, &purseInfo);

    if (!ret) {
        PrintAndLogEx(FAILED, "解析KS X 6924钱包信息错误");
        goto end;
    }

    KSX6924PrintPurseInfo(&purseInfo);

    get_and_print_balance();

end:
    if (keep == false) {
        DropField();
    }
    return PM3_SUCCESS;
}

static int CmdHFKSX6924Select(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 选择",
                  "选择 KS X 6924 应用程序，并保持场激活",
                  "hf ksx6924 select\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "apdu", "显示 APDU 请求和响应"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (KSX6924TrySelect()) {
        PrintAndLogEx(SUCCESS, "卡片已选中，场已开启");
    } else {
        // Wrong app, drop field.
        DropField();
    }

    return PM3_SUCCESS;
}

static int CmdHFKSX6924Initialize(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 初始化",
                  "使用 Mpda（购买交易货币）执行交易初始化",
                  "hf ksx6924 init 000003e8 -> Mpda\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep", "保持场开启以用于下一个命令"),
        arg_lit0("a",  "apdu", "显示 APDU 请求和响应"),
        arg_str1(NULL, NULL,  "<Mpda 4 bytes hex>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keep = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);

    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;
    CLIGetHexWithReturn(ctx, 3, data, &datalen);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (datalen != 4) {
        PrintAndLogEx(WARNING, "Mpda 参数必须为 4 字节长 (例如: 000003e8)");
        return PM3_EINVARG;
    }

    // try selecting card
    if (KSX6924TrySelect() == false) {
        goto end;
    }

    uint8_t resp[APDU_RES_LEN] = {0};
    size_t resp_len = 0;
    if (KSX6924InitializeCard(data[0], data[1], data[2], data[3], resp, &resp_len) == false) {
        goto end;
    }

    uint8_t *r = resp;
    struct ksx6924_initialize_card_response initCardResponse;
    bool ret = KSX6924ParseInitializeCardResponse(r, resp_len, &initCardResponse);

    if (!ret) {
        PrintAndLogEx(FAILED, "解析KS X 6924初始化卡片响应错误");
        goto end;
    }

    KSX6924PrintInitializeCardResponse(&initCardResponse);

end:
    if (keep == false) {
        DropField();
    }

    return PM3_SUCCESS;
}

static int CmdHFKSX6924PRec(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 精度",
                  "执行专有读取记录命令。\\n"
                  "Data format is unknown. Other records are available with 'emv getrec'.\n",
                  "hf ksx6924 prec 0b -> read proprietary record 0x0b");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",   "keep", "保持场开启以用于下一个命令"),
        arg_lit0("a",   "apdu", "显示 APDU 请求和响应"),
        arg_str1(NULL,  NULL,  "<record 1byte HEX>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keep = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);

    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;
    CLIGetHexWithReturn(ctx, 3, data, &datalen);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (datalen != 1) {
        PrintAndLogEx(WARNING, "记录参数必须为1字节长（例如：0f）");
        return PM3_EINVARG;
    }

    if (KSX6924TrySelect() == false) {
        goto end;
    }

    PrintAndLogEx(SUCCESS, "正在获取记录 %02x ...", data[0]);

    uint8_t recordData[0x10] = {0};
    if (KSX6924ProprietaryGetRecord(data[0], recordData, sizeof(recordData))) {
        PrintAndLogEx(SUCCESS, "  %s", sprint_hex(recordData, sizeof(recordData)));
    } else {
        PrintAndLogEx(FAILED, "获取记录时出错");
    }

end:
    if (keep == false) {
        DropField();
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",       CmdHelp,                AlwaysAvailable, "此帮助"},
    {"select",     CmdHFKSX6924Select,     IfPm3Iso14443a,  "选择应用，并保持场激活"},
    {"info",       CmdHFKSX6924Info,       IfPm3Iso14443a,  "标签信息"},
    {"balance",    CmdHFKSX6924Balance,    IfPm3Iso14443a,  "获取当前钱包余额"},
    {"init",       CmdHFKSX6924Initialize, IfPm3Iso14443a,  "使用Mpda执行交易初始化"},
    {"prec",       CmdHFKSX6924PRec,       IfPm3Iso14443a,  "发送专有获取记录命令（CLA=90, INS=4C）"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFKSX6924(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}



