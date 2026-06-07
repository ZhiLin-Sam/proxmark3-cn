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
// Analyse bytes commands
//-----------------------------------------------------------------------------
#include "cmdusart.h"

#include <stdlib.h>       // size_t
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "cmdparser.h"    // command_t
#include "cliparser.h"    //
#include "commonutil.h"   // ARRAYLEN
#include "comms.h"
#include "util_posix.h"
#include "usart_defs.h"
#include "ui.h"           // PrintAndLog

static int CmdHelp(const char *Cmd);

static int usart_tx(uint8_t *data, size_t len) {
    clearCommandBuffer();
    SendCommandNG(CMD_USART_TX, data, len);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_USART_TX, &resp, 1000) == false) {
        return PM3_ETIMEOUT;
    }
    return resp.status;
}

static int usart_rx(uint8_t *data, size_t *len, uint32_t waittime) {
    clearCommandBuffer();
    struct {
        uint32_t waittime;
    } PACKED payload;
    payload.waittime = waittime;
    SendCommandNG(CMD_USART_RX, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_USART_RX, &resp, waittime + 500) == false) {
        return PM3_ETIMEOUT;
    }
    if (resp.status == PM3_SUCCESS) {
        *len = resp.length;
        memcpy(data, resp.data.asBytes, resp.length);
    }
    return resp.status;
}

static int usart_txrx(uint8_t *srcdata, size_t srclen, uint8_t *dstdata, size_t *dstlen, uint32_t waittime) {
    clearCommandBuffer();
    struct payload_header {
        uint32_t waittime;
    } PACKED;
    struct {
        struct payload_header header;
        uint8_t data[PM3_CMD_DATA_SIZE - sizeof(uint32_t)];
    } PACKED payload;

    payload.header.waittime = waittime;

    if (srclen >= sizeof(payload.data)) {
        return PM3_EOVFLOW;
    }

    memcpy(payload.data, srcdata, srclen);
    SendCommandNG(CMD_USART_TXRX, (uint8_t *)&payload, srclen + sizeof(payload.header));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_USART_TXRX, &resp, waittime + 500) == false) {
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        *dstlen = resp.length;
        memcpy(dstdata, resp.data.asBytes, resp.length);
    }
    return resp.status;
}

static int set_usart_config(uint32_t baudrate, uint8_t parity) {
    clearCommandBuffer();
    struct {
        uint32_t baudrate;
        uint8_t parity;
    } PACKED payload;
    payload.baudrate = baudrate;
    payload.parity = parity;
    SendCommandNG(CMD_USART_CONFIG, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_USART_CONFIG, &resp, 1000) == false) {
        return PM3_ETIMEOUT;
    }
    return resp.status;
}

static int CmdUsartConfig(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "USART 配置",
                  "配置USART。\\n"
                  "WARNING: it will have side-effects if used in USART HOST mode!\n"
                  "The changes are not permanent, restart Proxmark3 to get default settings back.",
                  "usart config -b 9600\n"
                  "usart config -b 9600 --none\n"
                  "usart config -E"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("b", "baud", "<dec>", "波特率"),
        arg_lit0("N", "无", "奇偶校验"),
        arg_lit0("E", "even", "偶校验"),
        arg_lit0("O", "odd", "奇校验"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint32_t baudrate = arg_get_u32_def(ctx, 1, 0);
    bool pn = arg_get_lit(ctx, 2);
    bool pe = arg_get_lit(ctx, 3);
    bool po = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if ((pn + pe + po) > 1) {
        PrintAndLogEx(WARNING, "一次只能使用一种奇偶校验");
        return PM3_EINVARG;
    }

    uint8_t parity = 0;
    if (pn)
        parity = 'N';
    else if (po)
        parity = 'O';
    else if (pe)
        parity = 'E';

    return set_usart_config(baudrate, parity);
}

// module command not universal so specific commands needed if anyone DIY'd their own Blueshark.
bool BT_EXTENSION_HC04 = false;
bool BT_EXTENSION_HC05_BLUESHARK = false;

static int usart_bt_testcomm(uint32_t baudrate, uint8_t parity) {
    int ret = set_usart_config(baudrate, parity);
    if (ret != PM3_SUCCESS)
        return ret;

    const char *string = "AT+VERSION";
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;

    PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s 在 %u 8%c1", strlen(string), (int)strlen(string), string, baudrate, parity);

    // 1000, such large timeout needed
    ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
        if (str_startswith((char *)data, "hc01.comV2.0") ||
                str_startswith((char *)data, "www.hc01.com") ||
                str_startswith((char *)data, "BT SPP V4.0")) {

            PrintAndLogEx(SUCCESS, "Add-on " _GREEN_("found!"));

            // if it fully match HC-04's attribute
            if (str_startswith((char *)data, "www.hc01.com V2.5, 2022-04-26")) {
                BT_EXTENSION_HC04 = true;
                PrintAndLogEx(INFO, "蓝牙模块识别为 HC-04。");
            }

            // if it fully match Blueshark HC-05's attribute
            if (str_startswith((char *)data, "hc01.comV2.0")) {
                BT_EXTENSION_HC05_BLUESHARK = true;
                PrintAndLogEx(INFO, "蓝牙模块识别为 Blueshark HC-05。");
            }
            return PM3_SUCCESS;
        }
    }
    return PM3_ENODATA;
}

static int CmdUsartBtFactory(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "USART 蓝牙恢复出厂设置",
                  "将蓝牙附加组件重置为出厂设置\\n"
                  "This requires\n"
                  "    1) BTpower to be turned ON\n"
                  "    2) BT add-on to NOT be connected\n"
                  "      => the add-on blue LED must blink\n\n"
                  _RED_("WARNING:") _CYAN_(" process only if strictly needed!"),
                  "USART 蓝牙恢复出厂设置"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

// take care to define compatible settings:
# define BTADDON_BAUD_AT  "AT+BAUD8"
# define BTADDON_BAUD_NUM "115200"

    uint32_t baudrate = 0;
    uint8_t parity = 0;

    if (USART_BAUD_RATE != atoi(BTADDON_BAUD_NUM)) {
        PrintAndLogEx(WARNING, _RED_("WARNING:") " current Proxmark3 firmware has default USART baudrate = %i", USART_BAUD_RATE);
        PrintAndLogEx(WARNING, "Current btfactory implementation is hardcoded to " BTADDON_BAUD_NUM " bauds");
        return PM3_ENOTIMPL;
    }

    PrintAndLogEx(WARNING, _RED_("WARNING: process only if strictly needed!"));
    PrintAndLogEx(WARNING, "这需要蓝牙开启且未连接！");
    PrintAndLogEx(WARNING, "Is the add-on blue light blinking? (Say 'n' if you want to abort) [y/n]");

    char input[3];
    if ((fgets(input, sizeof(input), stdin) == NULL) || (strncmp(input, "y\n", sizeof(input)) != 0)) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(FAILED, "正在中止。");
        return PM3_EOPABORTED;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "正在尝试检测当前设置...请耐心等待。");

    bool found = usart_bt_testcomm(USART_BAUD_RATE, USART_PARITY) == PM3_SUCCESS;
    if (found) {
        baudrate = USART_BAUD_RATE;
        parity = USART_PARITY;
    } else {
        uint32_t brs[] = {1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600, 1382400};
        uint8_t ps[] = { 'N', 'O', 'E' };
        for (uint8_t ip = 0; (ip < ARRAYLEN(ps)) && (!found); ip++) {
            for (uint8_t ibr = 0; (ibr < ARRAYLEN(brs)) && (!found); ibr++) {
                found = usart_bt_testcomm(brs[ibr], ps[ip]) == PM3_SUCCESS;
                if (found) {
                    baudrate = brs[ibr];
                    parity = ps[ip];
                }
            }
        }
    }

    if (!found) {
        PrintAndLogEx(FAILED, "抱歉，未找到附加组件。中止。如果您自己DIY了，请向我们报告您的型号和手册。");
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "正在将附加组件重新配置为默认设置。");
    const char *string;
    uint8_t data[PM3_CMD_DATA_SIZE];
    size_t len = 0;
    memset(data, 0, sizeof(data));

    if (BT_EXTENSION_HC04 == true) {
        string = "AT+NAME=PM3_RDV4.0";
    } else {
        string = "AT+NAMEPM3_RDV4.0";
    }

    PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

    int ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
        if (strstr((char *)data, "OK")) {
            PrintAndLogEx(SUCCESS, "Name set to " _GREEN_("PM3_RDV4.0"));
        } else {
            PrintAndLogEx(WARNING, "Unexpected response to AT+NAME: " _YELLOW_("%.*s"), (int)len, data);
        }
    } else {
        PrintAndLogEx(WARNING, "与附加设备失去联系，请重试");
        return PM3_ESOFT;
    }

    msleep(500);

    memset(data, 0, sizeof(data));
    len = 0;
    string = "AT+ROLE=S";
    PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

    ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
        if (strstr((char *)data, "OK")) {
            PrintAndLogEx(SUCCESS, "Role set to " _GREEN_("Slave"));
        } else {
            PrintAndLogEx(WARNING, "Unexpected response to AT+ROLE=S: " _YELLOW_("%.*s"), (int)len, data);
        }
    } else {
        PrintAndLogEx(WARNING, "与附加设备失去联系，请重试");
        return PM3_ESOFT;
    }

    msleep(500);

    memset(data, 0, sizeof(data));
    len = 0;

    if (BT_EXTENSION_HC04 == true) {
        string = "AT+PIN=1234";
    } else {
        string = "AT+PIN1234";
    }

    PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

    ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
    if (ret == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
        if (strstr((char *)data, "OK")) {
            PrintAndLogEx(SUCCESS, "PIN set to " _GREEN_("1234"));
        } else {
            PrintAndLogEx(WARNING, "Unexpected response to AT+PIN: " _YELLOW_("%.*s"), (int)len, data);
        }
    } else {
        PrintAndLogEx(WARNING, "与附加设备失去联系，请重试");
        return PM3_ESOFT;
    }

    msleep(500);

    if (BT_EXTENSION_HC04 != true) {
        // parity must be changed before baudrate
        if (parity != USART_PARITY) {
            memset(data, 0, sizeof(data));
            len = 0;
            string = "AT+PN";
            PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

            ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
            if (ret == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
                if (strcmp((char *)data, "OK None") == 0) {
                    PrintAndLogEx(SUCCESS, "Parity set to " _GREEN_("None"));
                } else {
                    PrintAndLogEx(WARNING, "Unexpected response to AT+P: " _YELLOW_("%.*s"), (int)len, data);
                }
            } else {
                PrintAndLogEx(WARNING, "与附加设备失去联系，请重试");
                return PM3_ESOFT;
            }
        }

        if (baudrate != USART_BAUD_RATE) {
            memset(data, 0, sizeof(data));
            len = 0;
            string = BTADDON_BAUD_AT;
            PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

            ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
            if (ret == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
                if (strcmp((char *)data, "OK" BTADDON_BAUD_NUM) == 0) {
                    PrintAndLogEx(SUCCESS, "Baudrate set to " _GREEN_(BTADDON_BAUD_NUM));
                } else {
                    PrintAndLogEx(WARNING, "Unexpected response to AT+BAUD: " _YELLOW_("%.*s"), (int)len, data);
                }
            } else {
                PrintAndLogEx(WARNING, "与附加设备失去联系，请重试");
                return PM3_ESOFT;
            }
        }
    } else {

        memset(data, 0, sizeof(data));
        len = 0;
        string = "AT+BAUD=115200,N";
        PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(string), (int)strlen(string), string);

        ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 1000);
        if (ret == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
            if (strstr((char *)data, "OK") != NULL) {
                PrintAndLogEx(SUCCESS, "Parity set to " _GREEN_("None") " and Baudrate set to " _GREEN_("115200"));
            } else {
                PrintAndLogEx(WARNING, "Unexpected response to AT+BAUD: " _YELLOW_("%.*s"), (int)len, data);
            }
        } else {
            PrintAndLogEx(WARNING, "与附加设备失去联系，请重试");
            return PM3_ESOFT;
        }
    }

    if ((baudrate != USART_BAUD_RATE) || (parity != USART_PARITY)) {
        PrintAndLogEx(WARNING, "附加模块 UART 设置已更改，请关闭并重新打开蓝牙附加模块，然后按 Enter。");
        while (!kbd_enter_pressed()) {
            msleep(200);
        }
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "正在尝试使用新设置连接附加模块。");
        found = usart_bt_testcomm(USART_BAUD_RATE, USART_PARITY) == PM3_SUCCESS;
        if (!found) {
            PrintAndLogEx(WARNING, "与附加设备失去联系，请重试");
            return PM3_ESOFT;
        }
    }

    PrintAndLogEx(SUCCESS, "Add-on successfully " _GREEN_("reset"));
    return PM3_SUCCESS;
}

static int CmdUsartBtPin(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "USART 蓝牙 PIN 码",
                  "更改蓝牙附加PIN码。\\n"
                  "WARNING: this requires\n"
                  "    1) BTpower to be turned ON\n"
                  "    2) BT add-on to NOT be connected\n"
                  "      => the add-on blue LED must blink",
                  "usart btpin -p 1234"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("p", "pin", "<dec>", "所需PIN码（4位数字）"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int plen = 4;
    char pin[5] = { 0, 0, 0, 0, 0 };
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)pin, sizeof(pin), &plen);
    CLIParserFree(ctx);

    if (plen != 4) {
        PrintAndLogEx(FAILED, "PIN 必须为 4 位数字");
        return PM3_EINVARG;
    }

    for (uint8_t i = 0; i < plen; i++) {
        if (isdigit(pin[i]) == false) {
            PrintAndLogEx(FAILED, "PIN 必须为 4 位数字");
            return PM3_EINVARG;
        }
    }

    char string[6 + sizeof(pin)] = {0};
    snprintf(string, sizeof(string), "AT+PIN%s", pin);
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    int ret = usart_txrx((uint8_t *)string, strlen(string), data, &len, 600);

    if (ret == PM3_ENODATA) {
        PrintAndLogEx(FAILED, "附加模块无响应，是否已开启并闪烁？");
        return ret;
    }

    if (ret != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "命令失败，ret=%i", ret);
        return ret;
    }

    if (strcmp((char *)data, "OKsetPIN") == 0) {
        PrintAndLogEx(NORMAL, "PIN changed " _GREEN_("successfully"));
    } else {
        PrintAndLogEx(WARNING, "意外的应答: %.*s", (int)len, data);
    }
    return PM3_SUCCESS;
}

static int CmdUsartTX(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "USART 发送",
                  "通过 USART 发送字符串。\\n"
                  "WARNING:  it will have side-effects if used in USART HOST mode!",
                  "usart tx -d \"AT+VERSION\"\n"
                  "usart tx -d \"AT+VERSION\\r\\n\""
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "数据", "<str>", "要发送的字符串"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int slen = 0;
    char s[PM3_CMD_DATA_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)s, sizeof(s), &slen);
    CLIParserFree(ctx);

    char clean[PM3_CMD_DATA_SIZE] = {0};
    size_t i2 = 0;
    size_t n = strlen(s);

    // strip / replace
    for (size_t i = 0; i < n; i++) {
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == '\\')) {
            i++;
            clean[i2++] = '\\';
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == '"')) {
            i++;
            clean[i2++] = '"';
            continue;
        }
        if (s[i] == '"') {
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == 'r')) {
            i++;
            clean[i2++] = '\r';
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == 'n')) {
            i++;
            clean[i2++] = '\n';
            continue;
        }
        clean[i2++] = s[i];
    }
    return usart_tx((uint8_t *)clean, strlen(clean));
}

static int CmdUsartRX(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "USART 接收",
                  "通过USART接收字符串。\\n"
                  "WARNING: it will have side-effects if used in USART HOST mode!\n",
                  "usart rx -t 2000     ->  2 second timeout"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("t", "timeout", "<dec>", "超时时间（毫秒），默认为0毫秒"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t waittime = arg_get_u32_def(ctx, 1, 0);
    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    int ret = usart_rx(data, &len, waittime);
    if (ret != PM3_SUCCESS)
        return ret;

    PrintAndLogEx(SUCCESS, "RX:%.*s", (int)len, data);
    return PM3_SUCCESS;
}

static int CmdUsartTXRX(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "USART 收发",
                  "通过 USART 发送字符串并等待响应。\\n"
                  "WARNING: if used in USART HOST mode, you can only send AT commands\n"
                  "to add-on when BT connection is not established (LED needs to be blinking)\n"
                  _RED_("Any other usage in USART HOST mode will have side-effects!"),

                  "usart txrx -d \"AT+VERSION\"               -> Talking to BT add-on (when no connection)\n"
                  "usart txrx -t 2000 -d \"AT+SOMESTUFF\\r\\n\" -> Talking to a target requiring longer time and end-of-line chars"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("t", "timeout", "<dec>", "超时时间（毫秒），默认为1000毫秒"),
        arg_str1("d", "数据", "<str>", "要发送的字符串"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t waittime = arg_get_u32_def(ctx, 1, 1000);
    int slen = 0;
    char s[PM3_CMD_DATA_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)s, sizeof(s), &slen);
    CLIParserFree(ctx);

    char clean[PM3_CMD_DATA_SIZE] = {0};
    size_t j = 0;
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == '\\')) {
            i++;
            clean[j++] = '\\';
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == '"')) {
            i++;
            clean[j++] = '"';
            continue;
        }
        if (s[i] == '"') {
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == 'r')) {
            i++;
            clean[j++] = '\r';
            continue;
        }
        if ((i < n - 1) && (s[i] == '\\') && (s[i + 1] == 'n')) {
            i++;
            clean[j++] = '\n';
            continue;
        }
        clean[j++] = s[i];
    }

    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    PrintAndLogEx(SUCCESS, "TX (%3zu):%.*s", strlen(clean), (int)strlen(clean), clean);
    int ret = usart_txrx((uint8_t *)clean, strlen(clean), data, &len, waittime);
    if (ret != PM3_SUCCESS)
        return ret;

    PrintAndLogEx(SUCCESS, "RX (%3zu):%.*s", len, (int)len, data);
    return PM3_SUCCESS;
}

static int CmdUsartTXhex(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "USART 十六进制发送",
                  "通过 USART 发送字节。\\n"
                  "WARNING:  it will have side-effects if used in USART HOST mode!",
                  "usart txhex -d 504d33620a80000000010100f09f988ef09fa5b36233"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "数据", "<hex>", "要发送的字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int dlen = 0;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), data, sizeof(data), &dlen);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "解析字节错误");
        return PM3_EINVARG;
    }
    return usart_tx(data, dlen);
}

static int CmdUsartRXhex(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "USART 十六进制接收",
                  "通过USART接收字节。\\n"
                  "WARNING: it will have side-effects if used in USART HOST mode!\n",
                  "usart rxhex -t 2000  -> 2 second timeout"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("t", "timeout", "<dec>", "超时时间（毫秒），默认为0毫秒"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t waittime = arg_get_u32_def(ctx, 1, 0);
    CLIParserFree(ctx);

    uint8_t data[PM3_CMD_DATA_SIZE] = {0x00};
    size_t len = 0;
    int ret = usart_rx(data, &len, waittime);
    if (ret != PM3_SUCCESS)
        return ret;

    print_hex_break(data, len, 32);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",         CmdHelp,            AlwaysAvailable,          "此帮助"},
    {"btpin",        CmdUsartBtPin,      IfPm3FpcUsartFromUsb,     "更改蓝牙附加PIN"},
    {"btfactory",    CmdUsartBtFactory,  IfPm3FpcUsartFromUsb,     "将蓝牙附加模块重置为出厂设置"},
    {"tx",           CmdUsartTX,         IfPm3FpcUsartDevFromUsb,  "通过USART发送字符串"},
    {"rx",           CmdUsartRX,         IfPm3FpcUsartDevFromUsb,  "通过USART接收字符串"},
    {"txrx",         CmdUsartTXRX,       IfPm3FpcUsartDevFromUsb,  "通过USART发送字符串并等待响应"},
    {"txhex",        CmdUsartTXhex,      IfPm3FpcUsartDevFromUsb,  "通过USART发送字节"},
    {"rxhex",        CmdUsartRXhex,      IfPm3FpcUsartDevFromUsb,  "通过USART接收字节"},
    {"config",       CmdUsartConfig,     IfPm3FpcUsartDevFromUsb,  "配置USART"},
//    {"bridge",       CmdUsartBridge,     IfPm3FpcUsartDevFromUsb,  "Bridge USB-CDC & USART"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdUsart(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
