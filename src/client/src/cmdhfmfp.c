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
// High frequency MIFARE  Plus commands
//-----------------------------------------------------------------------------

#include "cmdhfmfp.h"
#include "cmdhfmfdes.h"
#include <string.h>
#include "cmdparser.h"    // command_t
#include "commonutil.h"  // ARRAYLEN
#include "comms.h"
#include "ui.h"
#include "util.h"
#include "cmdhf14a.h"
#include "mifare/mifare4.h"
#include "mifare/mad.h"
#include "nfc/ndef.h"
#include "cliparser.h"
#include "mifare/mifaredefault.h"
#include "util_posix.h"
#include "fileutils.h"
#include "protocols.h"
#include "crypto/libpcrypto.h"
#include "cmdhfmf.h"    // printblock, header
#include "mifare/mifarehost.h"  // mf_read_sector (SL1 CRYPTO1)
#include "cmdtrace.h"
#include "crypto/originality.h"

static const uint8_t mfp_default_key[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint16_t mfp_card_adresses[] = {0x9000, 0x9001, 0x9002, 0x9003, 0x9004, 0x9006, 0x9007, 0xA000, 0xA001, 0xA080, 0xA081, 0xC000, 0xC001};

#define MFP_KEY_FILE_SIZE  14 + (2 * 64 * (AES_KEY_LEN + 1))
#define MFP_CHK_KEY_TRIES  (2)

static int CmdHelp(const char *Cmd);

/*
  The 7 MSBits (= n) code the storage size itself based on 2^n,
  the LSBit is set to '0' if the size is exactly 2^n
    and set to '1' if the storage size is between 2^n and 2^(n+1).
    For this version of DESFire the 7 MSBits are set to 0x0C (2^12 = 4096) and the LSBit is '0'.
*/
static char *getCardSizeStr(uint8_t fsize) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    uint16_t usize = 1 << ((fsize >> 1) + 1);
    uint16_t lsize = 1 << (fsize >> 1);

    // is  LSB set?
    if (fsize & 1)
        snprintf(retStr, sizeof(buf), "0x%02X ( " _GREEN_("%d - %d bytes") " )", fsize, usize, lsize);
    else
        snprintf(retStr, sizeof(buf), "0x%02X ( " _GREEN_("%d bytes") " )", fsize, lsize);
    return buf;
}

static char *getProtocolStr(uint8_t id, bool hw) {

    static char buf[50] = {0x00};
    char *retStr = buf;

    if (id == 0x04) {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-3 MIFARE, 14443-4") " )", id);
    } else if (id == 0x05) {
        if (hw)
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-2, 14443-3") " )", id);
        else
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("ISO 14443-3, 14443-4") " )", id);
    } else {
        snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Unknown") " )", id);
    }
    return buf;
}

static char *getVersionStr(uint8_t type, uint8_t major, uint8_t minor) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    if (type == 0x01 && major == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire MF3ICD40") " )", major, minor);
    else if (major == 0x10 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("NTAG413DNA") " )", major, minor);
    else if (type == 0x01 && major == 0x01 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV1") " )", major, minor);
    else if (type == 0x01 && major == 0x12 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV2") " )", major, minor);
    else if (type == 0x01 && major == 0x22 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV2 XL") " )", major, minor);
    else if (type == 0x01 && major == 0x42 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV2") " )", major, minor);
    else if (type == 0x01 && major == 0x33 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire EV3") " )", major, minor);
    else if (type == 0x01 && major == 0x30 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("DESFire Light") " )", major, minor);
    else if (type == 0x02 && major == 0x11 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("Plus EV1") " )", major, minor);
    else if (type == 0x02 && major == 0x22 && minor == 0x00)
        snprintf(retStr, sizeof(buf), "%x.%x ( " _GREEN_("Plus EV2") " )", major, minor);
    else
        snprintf(retStr, sizeof(buf), "%x.%x ( " _YELLOW_("Unknown") " )", major, minor);
    return buf;
}

static char *getTypeStr(uint8_t type) {

    static char buf[40] = {0x00};
    char *retStr = buf;

    switch (type) {
        case 0x01:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("DESFire") " )", type);
            break;
        case 0x02:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Plus") " )", type);
            break;
        case 0x03:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Ultralight") " )", type);
            break;
        case 0x04:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("NTAG") " )", type);
            break;
        case 0x81:
            snprintf(retStr, sizeof(buf), "0x%02X ( " _YELLOW_("Smartcard") " )", type);
            break;
        default:
            break;
    }
    return buf;
}

// --- GET SIGNATURE
static int plus_print_signature(uint8_t *uid, uint8_t uidlen, uint8_t *signature, int signature_len) {
    int index = originality_check_verify(uid, uidlen, signature, signature_len, PK_MFP);
    return originality_check_print(signature, signature_len, index);
}

static int get_plus_signature(uint8_t *signature, int *signature_len) {

    mfpSetVerboseMode(false);

    uint8_t data[59] = {0};
    int resplen = 0, retval = PM3_SUCCESS;
    MFPGetSignature(true, false, data, sizeof(data), &resplen);

    if (resplen == 59) {
        memcpy(signature, data + 1, 56);
        *signature_len = 56;
    } else {
        *signature_len = 0;
        retval = PM3_ESOFT;
    }

    return retval;
}

// GET VERSION
static int plus_print_version(uint8_t *version) {
    if ((version[14] == 0x00) && (version[15] == 0x04)) {
        PrintAndLogEx(SUCCESS, "UID: " _GREEN_("%s"), sprint_hex(version + 16, 4));
        PrintAndLogEx(SUCCESS, "Batch number: " _GREEN_("%s"), sprint_hex(version + 20, 5));
        PrintAndLogEx(SUCCESS, "Production date: week " _GREEN_("%02x") " / " _GREEN_("20%02x"), version[7 + 7 + 6 + 5], version[7 + 7 + 7 + 4 + 1]);
    } else {
        PrintAndLogEx(SUCCESS, "UID: " _GREEN_("%s"), sprint_hex(version + 14, 7));
        PrintAndLogEx(SUCCESS, "Batch number: " _GREEN_("%s"), sprint_hex(version + 21, 5));
        PrintAndLogEx(SUCCESS, "Production date: week " _GREEN_("%02x") " / " _GREEN_("20%02x"), version[7 + 7 + 7 + 5], version[7 + 7 + 7 + 5 + 1]);
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Hardware Information"));
    PrintAndLogEx(INFO, "          Raw : %s", sprint_hex(version, 7));
    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(version[0]));
    PrintAndLogEx(INFO, "          Type: %s", getTypeStr(version[1]));
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), version[2]);
    PrintAndLogEx(INFO, "       Version: %s", getVersionStr(version[1], version[3], version[4]));
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(version[5]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(version[6], true));
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Software Information"));
    PrintAndLogEx(INFO, "          Raw : %s", sprint_hex(version + 7, 6));
    PrintAndLogEx(INFO, "     Vendor Id: " _YELLOW_("%s"), getTagInfo(version[7]));
    PrintAndLogEx(INFO, "          Type: %s", getTypeStr(version[8]));
    PrintAndLogEx(INFO, "       Subtype: " _YELLOW_("0x%02X"), version[9]);
    PrintAndLogEx(INFO, "       Version: " _YELLOW_("%d.%d"),  version[10], version[11]);
    PrintAndLogEx(INFO, "  Storage size: %s", getCardSizeStr(version[12]));
    PrintAndLogEx(INFO, "      Protocol: %s", getProtocolStr(version[13], false));
    return PM3_SUCCESS;
}

static int get_plus_version(uint8_t *version, int *version_len) {

    int resplen = 0, retval = PM3_SUCCESS;
    mfpSetVerboseMode(false);
    MFPGetVersion(true, false, version, *version_len, &resplen);

    *version_len = resplen;
    if (resplen != 28) {
        retval = PM3_ESOFT;
    }
    return retval;
}

static int mfp_read_card_id(iso14a_card_select_t *card, int *nxptype) {

    if (card == NULL) {
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_CLEARTRACE | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(DEBUG, "ISO14443A卡片选择失败");
        DropField();
        return PM3_ERFTRANS;
    }

    uint64_t select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK with ATS, 2: OK no ATS, 3: proprietary
    if (select_status == 0) {
        PrintAndLogEx(ERR, "No card present or card not responding");
        DropField();
        return PM3_ERFTRANS;
    }

    memcpy(card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    if (nxptype) {

        uint8_t ats_hist_pos = 0;
        if ((card->ats_len > 3) && (card->ats[0] > 1)) {
            ats_hist_pos = 2;
            ats_hist_pos += (card->ats[1] & 0x10) == 0x10;
            ats_hist_pos += (card->ats[1] & 0x20) == 0x20;
            ats_hist_pos += (card->ats[1] & 0x40) == 0x40;
        }

        version_hw_t version_hw = {0};
        // if 4b UID or NXP, try to get version
        int res = hf14a_getversion_data(card, select_status, &version_hw);
        DropField();

        bool version_hw_available = (res == PM3_SUCCESS);

        *nxptype = detect_nxp_card(card->sak
                                   , ((card->atqa[1] << 8) + card->atqa[0])
                                   , select_status
                                   , card->ats_len - ats_hist_pos
                                   , card->ats + ats_hist_pos
                                   , version_hw_available
                                   , &version_hw
                                  );
    }
    return PM3_SUCCESS;
}

static int mfp_load_keygen_keys(uint8_t **pkeyBlock, uint32_t *pkeycnt, uint8_t *uid) {

    // Handle dymanica keys

    return PM3_SUCCESS;
}

static int mfp_load_keys(uint8_t **pkeyBlock, uint32_t *pkeycnt, uint8_t *userkey, int userkeylen, const char *filename, int fnlen, uint8_t *uid, bool load_default) {
    // Handle Keys
    *pkeycnt = 0;
    *pkeyBlock = NULL;
    uint8_t *p;

    // Handle KDF uid based keys
    if (uid) {
        mfp_load_keygen_keys(pkeyBlock, pkeycnt, uid);
    }

    // Handle user supplied key
    // (it considers *pkeycnt and *pkeyBlock as possibly non-null so logic can be easily reordered)
    if (userkeylen >= AES_KEY_LEN) {
        int numKeys = userkeylen / AES_KEY_LEN;
        p = realloc(*pkeyBlock, (*pkeycnt + numKeys) * AES_KEY_LEN);
        if (p == NULL) {
            PrintAndLogEx(WARNING, "分配内存失败");
            free(*pkeyBlock);
            return PM3_EMALLOC;
        }
        *pkeyBlock = p;

        memcpy(*pkeyBlock, userkey, numKeys * AES_KEY_LEN);

        for (int i = 0; i < numKeys; i++) {
            PrintAndLogEx(DEBUG, _YELLOW_("%2d") " - %s", i, sprint_hex_inrow(*pkeyBlock + i * AES_KEY_LEN, AES_KEY_LEN));
        }
        *pkeycnt += numKeys;
        PrintAndLogEx(SUCCESS, "loaded " _GREEN_("%d") " user keys", numKeys);
    }

    if (load_default) {
        // Handle default keys
        p = realloc(*pkeyBlock, (*pkeycnt + g_mifare_plus_default_keys_len) * AES_KEY_LEN);
        if (p == NULL) {
            PrintAndLogEx(WARNING, "分配内存失败");
            free(*pkeyBlock);
            return PM3_EMALLOC;
        }
        *pkeyBlock = p;

        // Copy default keys to list
        size_t cnt = 0;
        for (cnt = 0; cnt < g_mifare_plus_default_keys_len; cnt++) {

            int len = hex_to_bytes(g_mifare_plus_default_keys[cnt], (uint8_t *)(*pkeyBlock + (*pkeycnt + cnt) * AES_KEY_LEN), AES_KEY_LEN);

            PrintAndLogEx(DEBUG, _YELLOW_("%2u") " - %s", *pkeycnt + cnt, sprint_hex_inrow(*pkeyBlock + (*pkeycnt + cnt) * AES_KEY_LEN, AES_KEY_LEN));
            if (len != AES_KEY_LEN) {
                break;
            }
        }
        *pkeycnt += cnt;
        PrintAndLogEx(SUCCESS, "loaded " _GREEN_("%zu") " hardcoded keys", cnt);
    }

    // Handle user supplied dictionary file
    if (fnlen > 0) {

        uint32_t loaded_numKeys = 0;
        uint8_t *dict_keys = NULL;

        int res = loadFileDICTIONARY_safe(filename, (void **) &dict_keys, AES_KEY_LEN, &loaded_numKeys);

        if (res != PM3_SUCCESS || loaded_numKeys == 0 || dict_keys == NULL) {
            PrintAndLogEx(FAILED, "加载字典时发生错误！");
            free(dict_keys);
            free(*pkeyBlock);
            return PM3_EFILE;

        } else {

            p = realloc(*pkeyBlock, (*pkeycnt + loaded_numKeys) * AES_KEY_LEN);
            if (p == NULL) {
                PrintAndLogEx(WARNING, "分配内存失败");
                free(dict_keys);
                free(*pkeyBlock);
                return PM3_EMALLOC;
            }
            *pkeyBlock = p;

            memcpy(*pkeyBlock + *pkeycnt * AES_KEY_LEN, dict_keys, loaded_numKeys * AES_KEY_LEN);

            *pkeycnt += loaded_numKeys;

            free(dict_keys);
        }
    }
    return PM3_SUCCESS;
}


static int CmdHFMFPInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 信息",
                  "从MIFARE Plus标签获取信息。",
                  "hf mfp 信息");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");

    // Mifare Plus info
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_CLEARTRACE, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
        PrintAndLogEx(DEBUG, "ISO14443A卡片选择超时");
        DropField();
        return false;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    uint64_t select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision

    bool Version4BUID = false;
    bool supportVersion = false;
    bool supportSignature = false;

    // version check
    uint8_t version[30] = {0};
    uint8_t uid4b[4] = {0};
    uint8_t uid7b[7] = {0};
    int version_len = sizeof(version);
    if (get_plus_version(version, &version_len) == PM3_SUCCESS) {
        plus_print_version(version);
        supportVersion = true;
        if ((version[14] == 0x00) && (version[15] == 0x04)) {
            Version4BUID = true;
            memcpy(uid4b, version + 16, 4);
        } else {
            memcpy(uid7b, version + 14, 7);
        }
    } else {
        // info about 14a part, historical bytes.
        infoHF14A(false, false, false);
    }

    // Signature originality check
    uint8_t signature[56] = {0};
    int signature_len = sizeof(signature);
    if (get_plus_signature(signature, &signature_len) == PM3_SUCCESS) {
        if (supportVersion) {
            if (Version4BUID) {
                plus_print_signature(uid4b, 4, signature, signature_len);
            } else {
                plus_print_signature(uid7b, 7, signature, signature_len);
            }
        } else {
            plus_print_signature(card.uid, card.uidlen, signature, signature_len);
        }
        supportSignature = true;
    }

    if (select_status == 1 || select_status == 2) {

        PrintAndLogEx(INFO, "--- " _CYAN_("指纹"));

        bool isPlus = false;

        if (supportVersion) {

            int cardtype = getCardType(version[1], version[3], version[4]);
            switch (cardtype) {
                case PLUS_EV1: {
                    if (supportSignature) {
                        PrintAndLogEx(INFO, "Tech..... " _GREEN_("MIFARE Plus EV1"));
                    } else {
                        PrintAndLogEx(INFO, "Tech..... " _YELLOW_("MIFARE Plus SE/X"));
                    }
                    isPlus = true;
                    break;
                }
                case PLUS_EV2: {
                    if (supportSignature) {
                        PrintAndLogEx(INFO, "Tech..... " _GREEN_("MIFARE Plus EV2"));
                    } else {
                        PrintAndLogEx(INFO, "Tech..... " _YELLOW_("MIFARE Plus EV2 ???"));
                    }
                    isPlus = true;
                    break;
                }
                case DESFIRE_MF3ICD40:
                case DESFIRE_EV1:
                case DESFIRE_EV2:
                case DESFIRE_EV2_XL:
                case DESFIRE_EV3:
                case DESFIRE_LIGHT: {
                    PrintAndLogEx(HINT, "提示：尝试 `" _YELLOW_("hf mfdes 信息") "` Card seems to be MIFARE DESFire");
                    PrintAndLogEx(NORMAL, "");
                    DropField();
                    return PM3_SUCCESS;
                }
                default: {
                    PrintAndLogEx(INFO, "Tech..... Unknown ( " _YELLOW_("%u") " )", cardtype);
                    break;
                }
            }
        }

        // MIFARE Type Identification Procedure
        // https://www.nxp.com/docs/en/application-note/AN10833.pdf
        uint16_t ATQA = card.atqa[0] + (card.atqa[1] << 8);

        if (ATQA & 0x0004) {
            PrintAndLogEx(INFO, "Size..... " _GREEN_("2K") " (%s UID)", (ATQA & 0x0040) ? "7" : "4");
            isPlus = true;
        }
        if (ATQA & 0x0002) {
            PrintAndLogEx(INFO, "Size..... " _GREEN_("4K") " (%s UID)", (ATQA & 0x0040) ? "7" : "4");
            isPlus = true;
        }

        uint8_t SLmode = 0xFF;
        if (isPlus) {
            if (card.sak == 0x08) {
                PrintAndLogEx(INFO, "SAK...... " _GREEN_("2K 7b UID"));
                if (select_status == 2) SLmode = 1;
            }
            if (card.sak == 0x18) {
                PrintAndLogEx(INFO, "SAK...... " _GREEN_("4K 7b UID"));
                if (select_status == 2) SLmode = 1;
            }
            if (card.sak == 0x10) {
                PrintAndLogEx(INFO, "SAK...... " _GREEN_("2K"));
                if (select_status == 2) SLmode = 2;
            }
            if (card.sak == 0x11) {
                PrintAndLogEx(INFO, "SAK...... " _GREEN_("4K"));
                if (select_status == 2) SLmode = 2;
            }
        }

        if (card.sak == 0x20) {
            if (card.ats_len > 0) {
                PrintAndLogEx(INFO, "SAK...... " _GREEN_("MIFARE Plus SL0/SL3") " or " _GREEN_("MIFARE DESFire"));
                SLmode = 3;
                // check SL0
                uint8_t data[128] = {0};
                int datalen = 0;
                // https://github.com/Proxmark/proxmark3/blob/master/client/luascripts/mifarePlus.lua#L161
                uint8_t cmd[3 + 16] = {0xa8, 0x90, 0x90, 0x00};
                int res = ExchangeRAW14a(cmd, sizeof(cmd), true, false, data, sizeof(data), &datalen, false);
                if (res != PM3_SUCCESS) {
                    PrintAndLogEx(INFO, "识别失败");
                    PrintAndLogEx(NORMAL, "");
                    DropField();
                    return PM3_SUCCESS;
                }
                // DESFire answers 0x1C or 67 00
                // Plus answers 0x0B, 0x09, 0x06
                // 6D00 is "INS code not supported" in APDU
                if (
                    data[0] != 0x0B &&
                    data[0] != 0x09 &&
                    data[0] != 0x1C &&
                    data[0] != 0x67 &&
                    data[0] != 0x6D &&
                    data[0] != 0x6E) {

                    PrintAndLogEx(INFO, _RED_("Send copy to iceman of this command output!"));
                    PrintAndLogEx(INFO, "数据... %s", sprint_hex(data, datalen));
                }

                if ((memcmp(data, "\x67\x00", 2) == 0) ||   // wrong length
                        (memcmp(data, "\x1C\x83\x0C", 3) == 0)  // desfire answers
                   ) {
                    PrintAndLogEx(INFO, "Result... " _RED_("MIFARE DESFire"));
                    PrintAndLogEx(NORMAL, "");
                    DropField();
                    return PM3_SUCCESS;

//                } else if (memcmp(data, "\x68\x82", 2) == 0) {  // Secure message not supported
                } else if (memcmp(data, "\x6D\x00", 2) == 0) {
//                } else if (memcmp(data, "\x6E\x00", 2) == 0) {  // Class not supported
                    isPlus = false;
                } else {
                    PrintAndLogEx(INFO, "Result... " _GREEN_("MIFARE Plus SL0/SL3"));
                }

                if ((datalen > 1) && (data[0] == 0x09)) {
                    SLmode = 0;
                }
            }
        }


        if (isPlus) {
            // How do we detect SL0 / SL1 / SL2 / SL3 modes?!?
            PrintAndLogEx(INFO, "--- " _CYAN_("Security Level (SL)"));

            if (SLmode != 0xFF)
                PrintAndLogEx(SUCCESS, "SL mode... " _YELLOW_("SL%d"), SLmode);
            else
                PrintAndLogEx(WARNING, "SL mode... " _YELLOW_("unknown"));

            switch (SLmode) {
                case 0:
                    PrintAndLogEx(INFO, "SL 0: 初始交付配置，用于卡片个性化");
                    break;
                case 1:
                    PrintAndLogEx(INFO, "SL 1: 向后功能兼容模式（与 MIFARE Classic 1K / 4K），可选 AES 认证");
                    break;
                case 2:
                    PrintAndLogEx(INFO, "SL 2: 基于 AES 的三次握手认证，随后进行 MIFARE CRYPTO1 认证，通信由 MIFARE CRYPTO1 保护");
                    break;
                case 3:
                    PrintAndLogEx(INFO, "SL 3: 基于 AES 的三次握手认证，数据操作命令由 AES 加密和基于 AES 的 MAC 方法保护。");
                    break;
                default:
                    break;
            }
        }
    } else {
        PrintAndLogEx(INFO, "MIFARE Plus 信息不可用");
    }
    PrintAndLogEx(NORMAL, "");
    DropField();
    return PM3_SUCCESS;
}

static int CmdHFMFPWritePerso(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 写入持久化",
                  "执行Write Perso命令。仅可在SL0模式下使用。",
                  "Use this command to program AES keys, as well as personalize other data on the tag.\n"
                  "You can program:\n"
                  "* Address 00 [00-FF]: Memory blocks (as well as ACLs and Crypto1 keys)\n"
                  "* Address 40 [00-40]: AES sector keys\n"
                  "* Address 90 [00-04]: AES administrative keys\n"
                  "* Address A0 [00, 01, 80, 81]: Virtual Card keys\n"
                  "* Address B0 [00-03]: Configuration data (DO NOT TOUCH B003)\n"
                  "Examples:\n"
                  "hf mfp wrp --adr 4000 --data 000102030405060708090a0b0c0d0e0f  -> write key (00..0f) to key number 4000 \n"
                  "hf mfp wrp --adr 4000                                          -> write default key(0xff..0xff) to key number 4000\n"
                  "hf mfp wrp --adr b000 -d FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF      -> allow 255 commands without MAC in configuration block (B000)\n"
                  "hf mfp wrp --adr 0003 -d 1234561234567F078869B0B1B2B3B4B5      -> write crypto1 keys A: 123456123456 and B: B0B1B2B3B4B5 to block 3\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "详细", "详细输出"),
        arg_str1("a", "adr",  "<hex>", "地址，2 个十六进制字节"),
        arg_str0("d", "数据", "<hex>", "数据，16个十六进制字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);

    uint8_t addr[64] = {0};
    int addrLen = 0;
    CLIGetHexWithReturn(ctx, 2, addr, &addrLen);

    uint8_t datain[64] = {0};
    int datainLen = 0;
    CLIGetHexWithReturn(ctx, 3, datain, &datainLen);
    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    if (!datainLen) {
        memmove(datain, mfp_default_key, 16);
        datainLen = 16;
    }

    if (addrLen != 2) {
        PrintAndLogEx(ERR, "地址长度必须为 2 字节。实际为 %d", addrLen);
        return PM3_EINVARG;
    }
    if (datainLen != 16) {
        PrintAndLogEx(ERR, "数据长度必须为 16 字节。实际为 %d", datainLen);
        return PM3_EINVARG;
    }

    uint8_t data[250] = {0};
    int datalen = 0;

    int res = MFPWritePerso(addr, datain, true, false, data, sizeof(data), &datalen);
    if (res) {
        PrintAndLogEx(ERR, "交换错误：%d", res);
        return res;
    }

    if (datalen != 3) {
        PrintAndLogEx(ERR, "命令必须返回 3 字节。得到 %d", datalen);
        return PM3_ESOFT;
    }

    if (data[0] != 0x90) {
        PrintAndLogEx(ERR, "命令错误: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Write ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static int CmdHFMFPInitPerso(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 初始化持久化",
                  "为所有卡密钥执行Write Perso命令。仅可在SL0模式下使用。",
                  "hf mfp initp --key 000102030405060708090a0b0c0d0e0f  -> fill all the keys with key (00..0f)\n"
                  "hf mfp initp -vv                                     -> fill all the keys with default key(0xff..0xff) and show all the data exchange"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_litn("v",  "详细", 0, 2, "详细输出"),
        arg_str0("k", "key", "<hex>", "密钥，16个十六进制字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool verbose2 = arg_get_lit(ctx, 1) > 1;

    uint8_t key[256] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 2, key, &keylen);
    CLIParserFree(ctx);

    if (keylen && keylen != 16) {
        PrintAndLogEx(FAILED, "密钥长度必须为 16 字节，实际为 %d", keylen);
        return PM3_EINVARG;
    }

    if (keylen == 0) {
        memmove(key, mfp_default_key, sizeof(mfp_default_key));
    }

    uint8_t keyNum[2] = {0};
    uint8_t data[250] = {0};
    int datalen = 0;
    int res;

    mfpSetVerboseMode(verbose2);
    for (uint16_t sn = 0x4000; sn < 0x4050; sn++) {
        keyNum[0] = sn >> 8;
        keyNum[1] = sn & 0xff;
        res = MFPWritePerso(keyNum, key, (sn == 0x4000), true, data, sizeof(data), &datalen);
        if (!res && (datalen == 3) && data[0] == 0x09) {
            PrintAndLogEx(INFO, "检测到 2K 卡。");
            break;
        }
        if (res || (datalen != 3) || data[0] != 0x90) {
            PrintAndLogEx(ERR, "地址 %04x 写入错误", sn);
            break;
        }
    }

    mfpSetVerboseMode(verbose);
    for (int i = 0; i < ARRAYLEN(mfp_card_adresses); i++) {
        keyNum[0] = mfp_card_adresses[i] >> 8;
        keyNum[1] = mfp_card_adresses[i] & 0xff;
        res = MFPWritePerso(keyNum, key, false, true, data, sizeof(data), &datalen);
        if (!res && (datalen == 3) && data[0] == 0x09) {
            PrintAndLogEx(WARNING, "已跳过[%04x]...", mfp_card_adresses[i]);
        } else {
            if (res || (datalen != 3) || data[0] != 0x90) {
                PrintAndLogEx(ERR, "地址 %04x 写入错误", mfp_card_adresses[i]);
                break;
            }
        }
    }
    DropField();

    if (res)
        return res;

    PrintAndLogEx(INFO, "完成！");
    return PM3_SUCCESS;
}

static int CmdHFMFPCommitPerso(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 提交持久化",
                  "执行Commit Perso命令。仅可在SL0模式下使用。\\n"
                  "OBS! This command will not be executed if \n"
                  "CardConfigKey, CardMasterKey and L3SwitchKey AES keys are not written.",
                  "hf mfp commitp\n"
                  //                "hf mfp commitp --sl 1"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "详细", "详细输出"),
//        arg_int0(NULL,  "sl", "<dec>", "SL mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
//    int slmode = arg_get_int(ctx, 2);
    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    uint8_t data[250] = {0};
    int datalen = 0;

    int res = MFPCommitPerso(true, false, data, sizeof(data), &datalen);
    if (res) {
        PrintAndLogEx(ERR, "交换错误：%d", res);
        return res;
    }

    if (datalen != 3) {
        PrintAndLogEx(ERR, "命令必须返回 3 字节。得到 %d", datalen);
        return PM3_EINVARG;
    }

    if (data[0] != 0x90) {
        PrintAndLogEx(ERR, "命令错误: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        return PM3_EINVARG;
    }
    PrintAndLogEx(INFO, "Switched security level ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static int CmdHFMFPAcl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp ACL",
                  "打印解码的 MIFARE Plus 访问权限 (ACL), \\n"
                  "  A = key A\n"
                  "  B = key B\n"
                  "  AB = both key A and B\n"
                  "  ACCESS = access bytes inside sector trailer block\n"
                  "  Increment, decrement, transfer, restore is for value blocks",
                  "hf mf acl\n"
                  "hf mf acl -d 0FFF0780\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "数据", "<hex>", "ACL 字节指定为 4 个十六进制字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int acllen = 0;
    uint8_t acl[4] = {0};

    CLIGetHexWithReturn(ctx, 1, acl, &acllen);
    CLIParserFree(ctx);

    if (acllen && acllen != 4) {
        PrintAndLogEx(FAILED, "ACL 长度必须为 4 字节。实际为 %d", acllen);
        return PM3_EINVARG;
    }

    PrintAndLogEx(NORMAL, "");

    // look up common default ACL bytes and print a fingerprint line about it.
    if (memcmp(acl, "\x0F\xFF\x07\x80", 4) == 0) {
        PrintAndLogEx(INFO, "ACL... " _GREEN_("%s") " (transport configuration)", sprint_hex(acl, sizeof(acl)));
    } else {
        PrintAndLogEx(INFO, "ACL... " _GREEN_("%s"), sprint_hex(acl, sizeof(acl)));
    }
    if (mfValidateAccessConditions(acl + 1) == false || ((acl[0] >> 4) != ((~acl[0]) & 0xF))) {
        PrintAndLogEx(ERR, _RED_("Invalid Access Conditions, NEVER write these on a card!"));
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "  # | Access rights");
    PrintAndLogEx(INFO, "----+-----------------------------------------------------------------");
    for (int i = 0; i < 4; i++) {
        PrintAndLogEx(INFO, "%3d | " _YELLOW_("%s"), i, mfGetAccessConditionsDesc(i, acl + 1));
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "  # | Block data exchange formats");
    PrintAndLogEx(INFO, "----+-----------------------------------------------------------------");
    // When a tag is moved to SL3, its' 6th byte of Crypto1 key A becomes a new ACL byte.
    // Automatically it becomes 0F. This allows you to read all blocks plaintext.
    // However, bits can be flipped in order to limit this. Notably, bits in this byte are set like this:
    // B3 B2 B1 B0 ~B3 ~B2 ~B1 ~B0
    // So if you set bit B3, you will ONLY be able to read/write the ACL block encrypted.
    for (int i = 0; i < 4; i++) {
        // This line could have used a ? _YELLOW_ : _GREEN_, but CC doesn't like it that way.
        if ((acl[0] >> (4 + i)) & 1)
            PrintAndLogEx(INFO, "%3d | " _YELLOW_("encrypted only"), i);
        else
            PrintAndLogEx(INFO, "%3d | " _GREEN_("encrypted or plaintext"), i);
    }

    return PM3_SUCCESS;
}

static int CmdHFMFPAuth(const char *Cmd) {
    uint8_t keyn[250] = {0};
    int keynlen = 0;
    uint8_t key[250] = {0};
    int keylen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 认证",
                  "为MIFARE Plus卡执行AES认证命令",
                  "hf mfp auth --ki 4000 --key 000102030405060708090a0b0c0d0e0f      -> executes authentication\n"
                  "hf mfp auth --ki 9003 --key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -v   -> executes authentication and shows all the system data"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "详细", "详细输出"),
        arg_str1(NULL, "ki", "<hex>", "Key number, 2 hex bytes"),
        arg_str1("k",  "key", "<hex>", "密钥，16个十六进制字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    CLIGetHexWithReturn(ctx, 2, keyn, &keynlen);
    CLIGetHexWithReturn(ctx, 3, key, &keylen);
    CLIParserFree(ctx);

    if (keynlen != 2) {
        PrintAndLogEx(ERR, "错误：<密钥编号>必须为2字节。实际为%d", keynlen);
        return PM3_EINVARG;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "错误：<密钥>必须为16字节。实际为%d", keylen);
        return PM3_EINVARG;
    }

    return MifareAuth4(NULL, keyn, key, true, false, true, verbose, false);
}

int mfp_data_crypt(mf4Session_t *mf4session, uint8_t *dati, uint8_t *dato, bool rev) {
    uint8_t kenc[MFBLOCK_SIZE];
    memcpy(kenc, mf4session->Kenc, MFBLOCK_SIZE);

    uint8_t ti[4];
    memcpy(ti, mf4session->TI, 4);

    uint8_t ctr[1];
    uint8_t IV[MFBLOCK_SIZE] = { 0 };

    if (rev) {

        ctr[0] = (uint8_t)(mf4session->R_Ctr & 0xFF);

        for (int i = 0; i < 9; i += 4) {
            memcpy(&IV[i], ctr, 1);
        }

        memcpy(&IV[12], ti, 4); // For reads TI is LS

    } else {

        ctr[0] = (uint8_t)(mf4session->W_Ctr & 0xFF);

        for (int i = 3; i < MFBLOCK_SIZE; i += 4) {
            memcpy(&IV[i], ctr, 1);
        }

        memcpy(&IV[0], ti, 4); // For writes TI is MS
    }

    if (rev) {
        aes_decode(IV, kenc, dati, dato, MFBLOCK_SIZE);
    } else {
        aes_encode(IV, kenc, dati, dato, MFBLOCK_SIZE);
    }

    return PM3_SUCCESS;
}

static int CmdHFMFPRdbl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 读取块",
                  "从MIFARE Plus卡读取块",
                  "hf mfp rdbl --blk 0 --key 000102030405060708090a0b0c0d0e0f   -> executes authentication and read block 0 data\n"
                  "hf mfp rdbl --blk 1 -v                                       -> executes authentication and shows sector 1 data with default key 0xFF..0xFF"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "详细", "详细输出"),
        arg_int0("n",  "count", "<dec>", "块数（默认：1）"),
        arg_lit0("b",  "keyb", "使用密钥 B（默认：密钥 A）"),
        arg_lit0("p", "plain", "不在读卡器和卡之间使用加密通信模式"),
        arg_lit0(NULL, "nmc", "Do not append MAC to command"),
        arg_lit0(NULL, "nmr", "Do not expect MAC in reply"),
        arg_int1(NULL, "blk", "<0..255>", "块号"),
        arg_str0("k", "key", "<hex>", "密钥，16个十六进制字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);
    int blocksCount = arg_get_int_def(ctx, 2, 1);
    bool keyB = arg_get_lit(ctx, 3);
    bool plain = arg_get_lit(ctx, 4);
    bool nomaccmd = arg_get_lit(ctx, 5);
    bool nomacres = arg_get_lit(ctx, 6);
    uint32_t blockn = arg_get_int(ctx, 7);

    uint8_t keyn[2] = {0};
    uint8_t key[250] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 8, key, &keylen);
    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    if (keylen == 0) {
        memmove(key, mfp_default_key, 16);
        keylen = 16;
    }

    if (blockn > 255) {
        PrintAndLogEx(ERR, "<block number> 必须在 [0..255] 范围内。实际为 %d", blockn);
        return PM3_EINVARG;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<key> 必须是 16 字节。实际为 %d", keylen);
        return PM3_EINVARG;
    }

    // 3 blocks - wo iso14443-4 chaining
    if (blocksCount > 3) {
        PrintAndLogEx(ERR, "块数必须小于3。得到%d", blocksCount);
        return PM3_EINVARG;
    }

    if (blocksCount > 1 && mfIsSectorTrailer(blockn)) {
        PrintAndLogEx(WARNING, "警告：尾部！");
    }

    uint8_t sectorNum = mfSectorNum(blockn & 0xff);
    uint16_t uKeyNum = 0x4000 + sectorNum * 2 + (keyB ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose) {
        PrintAndLogEx(INFO, "--block:%d 扇区[%u]:%02x 密钥:%04x", blockn, mfNumBlocksPerSector(sectorNum), sectorNum, uKeyNum);
    }

    mf4Session_t mf4session;
    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "认证错误: %d", res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    res = MFPReadBlock(&mf4session, plain, nomaccmd, nomacres, blockn & 0xff, blocksCount, false, false, data, sizeof(data), &datalen, mac);
    if (res) {
        PrintAndLogEx(ERR, "读取错误：%d", res);
        return res;
    }

    if (datalen && data[0] != 0x90) {
        PrintAndLogEx(ERR, "卡片读取错误：%02x %s", data[0], mfpGetErrorDescription(data[0]));
        return PM3_ESOFT;
    }
    //PrintAndLogEx(INFO, "%i", 8 && (!macres || 0xff));
    if (datalen != 1 + blocksCount * 16 + (nomacres ? 0 : 8) + 2) {
        PrintAndLogEx(ERR, "错误返回长度：%d", datalen);
        return PM3_ESOFT;
    }

    if (plain == false) {
        mfp_data_crypt(&mf4session, &data[1], &data[1], true);
    }

    uint8_t sector = mfSectorNum(blockn);
    mf_print_sector_hdr(sector);

    int indx = blockn;
    for (int i = 0; i < blocksCount; i++)  {
        mf_print_block_one(indx, data + 1 + (i * MFBLOCK_SIZE), verbose);
        indx++;
    }

    if (memcmp(&data[(blocksCount * 16) + 1], mac, 8) && !nomacres) {
        PrintAndLogEx(WARNING, "警告：mac不相等...");
        PrintAndLogEx(WARNING, "MAC   card... " _YELLOW_("%s"), sprint_hex_inrow(&data[1 + (blocksCount * MFBLOCK_SIZE)], 8));
        PrintAndLogEx(WARNING, "MAC reader... " _YELLOW_("%s"), sprint_hex_inrow(mac, sizeof(mac)));
    } else if (!nomacres) {
        if (verbose) {
            PrintAndLogEx(INFO, "MAC... " _YELLOW_("%s"), sprint_hex_inrow(&data[1 + (blocksCount * MFBLOCK_SIZE)], 8));
        }
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFMFPRdsc(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 读取扇区",
                  "从MIFARE Plus卡读取一个扇区",
                  "hf mfp rdsc -s 0 --key 000102030405060708090a0b0c0d0e0f   -> executes authentication and read sector 0 data\n"
                  "hf mfp rdsc -s 1 -v                                       -> executes authentication and shows sector 1 data with default key"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "详细", "详细输出"),
        arg_lit0("b",  "keyb",    "使用密钥 B（默认：密钥 A）"),
        arg_lit0("p", "plain", "不在读卡器和卡之间使用加密通信模式"),
        arg_lit0(NULL, "nmc", "Do not append MAC to command"),
        arg_lit0(NULL, "nmr", "Do not expect MAC in reply"),
        arg_int1("s",  "sn",      "<0..255>", "扇区号"),
        arg_str0("k",  "key",     "<hex>", "密钥，16个十六进制字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);
    bool keyB = arg_get_lit(ctx, 2);
    bool plain = arg_get_lit(ctx, 3);
    bool nomaccmd = arg_get_lit(ctx, 4);
    bool nomacres = arg_get_lit(ctx, 5);
    uint32_t sectorNum = arg_get_int(ctx, 6);
    uint8_t keyn[2] = {0};
    uint8_t key[250] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 7, key, &keylen);
    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    if (keylen == 0) {
        memmove(key, mfp_default_key, 16);
        keylen = 16;
    }

    if (sectorNum > 39) {
        PrintAndLogEx(ERR, "<sector number> 必须在 [0..39] 范围内。实际为 %d", sectorNum);
        return PM3_EINVARG;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<key> 必须是 16 字节。实际为 %d", keylen);
        return PM3_EINVARG;
    }

    uint16_t uKeyNum = 0x4000 + sectorNum * 2 + (keyB ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose) {
        PrintAndLogEx(INFO, "--sector[%u]:%02x key:%04x", mfNumBlocksPerSector(sectorNum), sectorNum, uKeyNum);
    }

    mf4Session_t mf4session;
    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "认证错误: %d", res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};

    mf_print_sector_hdr(sectorNum);

    for (int blockno = mfFirstBlockOfSector(sectorNum); blockno < mfFirstBlockOfSector(sectorNum) + mfNumBlocksPerSector(sectorNum); blockno++) {

        res = MFPReadBlock(&mf4session, plain, nomaccmd, nomacres, blockno & 0xff, 1, false, true, data, sizeof(data), &datalen, mac);
        if (res) {
            PrintAndLogEx(ERR, "读取错误：%d", res);
            DropField();
            return res;
        }

        if (datalen && data[0] != 0x90) {
            PrintAndLogEx(ERR, "卡片读取错误：%02x %s", data[0], mfpGetErrorDescription(data[0]));
            DropField();
            return PM3_ESOFT;
        }

        if (datalen != 1 + MFBLOCK_SIZE + (nomacres ? 0 : 8) + 2) {
            PrintAndLogEx(ERR, "错误返回长度：%d", datalen);
            DropField();
            return PM3_ESOFT;
        }

        if (plain == false) {
            mfp_data_crypt(&mf4session, &data[1], &data[1], true);
        }

        mf_print_block_one(blockno, data + 1, verbose);

        if (memcmp(&data[1 + 16], mac, 8) && !nomacres) {
            PrintAndLogEx(WARNING, "警告：块 %d 上的mac不相等...", blockno);
            PrintAndLogEx(WARNING, "MAC   card... " _YELLOW_("%s"), sprint_hex_inrow(&data[1 + MFBLOCK_SIZE], 8));
            PrintAndLogEx(WARNING, "MAC reader... " _YELLOW_("%s"), sprint_hex_inrow(mac, sizeof(mac)));
        } else if (!nomacres) {
            if (verbose) {
                PrintAndLogEx(INFO, "MAC... " _YELLOW_("%s"), sprint_hex_inrow(&data[1 + MFBLOCK_SIZE], 8));
            }
        }
    }
    PrintAndLogEx(NORMAL, "");
    DropField();
    return PM3_SUCCESS;
}

static int mfp_analyse_st_block(uint8_t blockno, uint8_t *block, bool force) {

    if (mfIsSectorTrailer(blockno) == false) {
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "检测到扇区尾部写入");

    // ensure access right isn't messed up.
    if (mfValidateAccessConditions(block + 6) == false || ((block[5] >> 4) != ((~block[5]) & 0xF))) {
        PrintAndLogEx(WARNING, "检测到无效的访问条件，正在替换为默认值");
        memcpy(block + 5, "\x0F\xFF\x07\x80\x69", 5);
    }

    bool ro_detected = false;
    //uint8_t bar = mfNumBlocksPerSector(mfSectorNum(blockno));
    uint8_t bar = 4;
    for (uint8_t foo = 0; foo < bar; foo++) {
        if (mfReadOnlyAccessConditions(foo, &block[6])) {
            // WARNING: Sectors 33+ assume ACLs apply to groups of 4 blocks, not 1 block.
            // The code as-is is bugged and actually wastes iterations. If you have 16 blocks, it'll run all 16 but only error out like it's a 4-block sector.
            if (blockno < 128)
                PrintAndLogEx(WARNING, "Strict ReadOnly Access Conditions on block " _YELLOW_("%u") " detected", blockno - bar + 1 + foo);
            else
                PrintAndLogEx(WARNING, "Strict ReadOnly Access Conditions on blocks " _YELLOW_("%u-%u") " detected", blockno - bar * 4 + 1 + foo * 5, blockno - bar * 4 + 1 + foo * 5 + 4);
            ro_detected = true;
        }
    }
    if (ro_detected) {
        if (force) {
            PrintAndLogEx(WARNING, " --force override, continuing...");
        } else {
            PrintAndLogEx(INFO, "退出，请运行 `" _YELLOW_("hf mf acl -d %s") "` to understand", sprint_hex_inrow(&block[6], 3));
            PrintAndLogEx(INFO, "使用`" _YELLOW_("--force") "` to override and write this data");
            return PM3_EINVARG;
        }
    } else {
        PrintAndLogEx(SUCCESS, "ST checks ( " _GREEN_("ok") " )");
    }

    return PM3_SUCCESS;
}

static int CmdHFMFPWrbl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 写入块",
                  "向MIFARE Plus卡写入一个块",
                  "hf mfp wrbl --blk 1 -d ff0000000000000000000000000000ff --key 000102030405060708090a0b0c0d0e0f -> write block 1 data\n"
                  "hf mfp wrbl --blk 2 -d ff0000000000000000000000000000ff -v                                     -> write block 2 data with default key 0xFF..0xFF"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "详细", "详细输出"),
        arg_lit0("b",  "keyb",    "使用密钥 B（默认：密钥 A）"),
        arg_int1(NULL, "blk",     "<0..255>", "块号"),
        arg_lit0("p", "plain", "不使用加密传输"),
        arg_lit0(NULL, "nmr", "Do not expect MAC in response"),
        arg_str1("d",  "数据",    "<hex>", "数据，16个十六进制字节"),
        arg_str0("k",  "key",     "<hex>", "密钥，16个十六进制字节"),
        arg_lit0(NULL, "force", "Override warnings"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);
    bool keyB = arg_get_lit(ctx, 2);
    uint32_t blockNum = arg_get_int(ctx, 3);
    bool plain = arg_get_lit(ctx, 4);
    bool nomacres = arg_get_lit(ctx, 5);

    uint8_t datain[250] = {0};
    int datainlen = 0;
    CLIGetHexWithReturn(ctx, 6, datain, &datainlen);

    uint8_t key[250] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 7, key, &keylen);
    bool force = arg_get_lit(ctx, 8);

    CLIParserFree(ctx);

    uint8_t keyn[2] = {0};

    mfpSetVerboseMode(verbose);

    if (!keylen) {
        memmove(key, mfp_default_key, 16);
        keylen = 16;
    }

    if (blockNum > 255) {
        PrintAndLogEx(ERR, "<block number> 必须在 [0..255] 范围内。实际为 %d", blockNum);
        return PM3_EINVARG;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<key> 必须是 16 字节。实际为 %d", keylen);
        return PM3_EINVARG;
    }

    if (datainlen != 16) {
        PrintAndLogEx(ERR, "<data> 必须是 16 字节。实际为 %d", datainlen);
        return PM3_EINVARG;
    }
    // Necessary checks before doing any actual computing + tag interaction
    // Block 0 detection
    if (blockNum == 0) {
        PrintAndLogEx(FAILED, "无法在 Mifare Plus 上写入块 0");
        return PM3_EINVARG;
    }
    // ACL validity check
    if (mfp_analyse_st_block(blockNum, datain, force) != PM3_SUCCESS) {
        return PM3_EINVARG;
    }

    uint8_t sectorNum = mfSectorNum(blockNum & 0xff);
    uint16_t uKeyNum = 0x4000 + sectorNum * 2 + (keyB ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose) {
        PrintAndLogEx(INFO, "--block:%d 扇区[%u]:%02x 密钥:%04x", blockNum & 0xff, mfNumBlocksPerSector(sectorNum), sectorNum, uKeyNum);
    }

    mf4Session_t mf4session;
    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "认证错误: %d", res);
        return res;
    }

    if (plain == false) {
        mfp_data_crypt(&mf4session, &datain[0], &datain[0], false);
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    res = MFPWriteBlock(&mf4session, plain, nomacres, blockNum & 0xff, 0x00, datain, false, false, data, sizeof(data), &datalen, mac);
    if (res) {
        PrintAndLogEx(ERR, "写入错误: %d", res);
        DropField();
        return res;
    }

    if (datalen != 3 && (datalen != 3 + (nomacres ? 0 : 8))) {
        PrintAndLogEx(ERR, "错误返回长度：%d", datalen);
        DropField();
        return PM3_ESOFT;
    }

    if (datalen && data[0] != 0x90) {
        PrintAndLogEx(ERR, "卡片写入错误: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        DropField();
        return PM3_ESOFT;
    }

    if (memcmp(&data[1], mac, 8) && !nomacres) {
        PrintAndLogEx(WARNING, "警告：mac不相等...");
        PrintAndLogEx(WARNING, "MAC   card: %s", sprint_hex(&data[1], 8));
        PrintAndLogEx(WARNING, "MAC读取器: %s", sprint_hex(mac, 8));
    } else if (!nomacres) {
        if (verbose)
            PrintAndLogEx(INFO, "MAC: %s", sprint_hex(&data[1], 8));
    }

    DropField();
    PrintAndLogEx(INFO, "Write ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static int CmdHFMFPChKey(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 更改密钥",
                  "更改Mifare Plus标签上的密钥",
                  "This requires the key that can update the key that you are trying to update.\n"
                  "hf mfp chkey --ki 401f -d FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF --key A0A1A2A3A4A5A6A7A0A1A2A3A4A5A6A7 -> Change key B for Sector 15 from MAD to default\n"
                  "hf mfp chkey --ki 9000 -d 32F9351A1C02B35FF97E0CA943F814F6 --key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -> Change card master key to custom from default"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "详细", "详细输出"),
        arg_lit0(NULL, "nmr", "Do not expect MAC in response"),
        arg_str1(NULL, "ki", "<hex>", "Key Index, 2 hex bytes"),
        arg_str0("k", "key",      "<hex>", "当前扇区密钥，16个十六进制字节"),
        arg_lit0("b", "typeb", "扇区密钥为密钥 B"),
        arg_str1("d",  "数据",    "<hex>", "新密钥，16个十六进制字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);
    bool nomacres = arg_get_lit(ctx, 2);

    uint8_t keyn[250] = {0};

    uint8_t ki[250] = {0};
    int kilen = 0;
    CLIGetHexWithReturn(ctx, 3, ki, &kilen);

    uint8_t key[250] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 4, key, &keylen);

    bool usekeyb = arg_get_lit(ctx, 5);
    uint8_t datain[250] = {0};
    int datainlen = 0;
    CLIGetHexWithReturn(ctx, 6, datain, &datainlen);

    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    if (!keylen) {
        memmove(key, mfp_default_key, 16);
        keylen = 16;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<key> 必须是 16 字节。实际为 %d", keylen);
        return PM3_EINVARG;
    }

    if (datainlen != 16) {
        PrintAndLogEx(ERR, "<data> 必须是 16 字节。实际为 %d", datainlen);
        return PM3_EINVARG;
    }

    mf4Session_t mf4session;

    keyn[0] = ki[0];

    if (ki[0] == 0x40) { // Only if we are working with sector keys

        if (usekeyb) {
            keyn[1] = (ki[1] % 2 == 0) ? ki[1] + 1 : ki[1]; // If we change using key B, check if KI is key A
        } else {
            keyn[1] = (ki[1] % 2 == 0) ? ki[1] : ki[1] - 1; // If we change using key A, check if KI is key A
        }

    } else {
        keyn[1] = ki[1];
    }

    if (verbose) {
        PrintAndLogEx(INFO, "--key 索引:", sprint_hex(keyn, 2));
    }

    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "认证错误: %d", res);
        return res;
    }

    mfp_data_crypt(&mf4session, &datain[0], &datain[0], false);

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    res = MFPWriteBlock(&mf4session, false, nomacres, ki[1], ki[0], datain, false, false, data, sizeof(data), &datalen, mac);
    if (res) {
        PrintAndLogEx(ERR, "写入错误: %d", res);
        DropField();
        return res;
    }

    if (datalen != 3 && (datalen != 3 + (nomacres ? 0 : 8))) {
        PrintAndLogEx(ERR, "错误返回长度：%d", datalen);
        DropField();
        return PM3_ESOFT;
    }

    if (datalen && data[0] != 0x90) {
        PrintAndLogEx(ERR, "卡片写入错误: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        DropField();
        return PM3_ESOFT;
    }

    if (memcmp(&data[1], mac, 8) && !nomacres) {
        PrintAndLogEx(WARNING, "警告：mac不相等...");
        PrintAndLogEx(WARNING, "MAC   card: %s", sprint_hex(&data[1], 8));
        PrintAndLogEx(WARNING, "MAC读取器: %s", sprint_hex(mac, 8));
    } else if (!nomacres) {
        if (verbose) {
            PrintAndLogEx(INFO, "MAC: %s", sprint_hex(&data[1], 8));
        }
    }

    DropField();
    PrintAndLogEx(INFO, "Key update ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static int CmdHFMFPChConf(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 检查配置",
                  "更改Mifare Plus标签的配置。危险！",
                  "This requires Card Master Key (9000) or Card Configuration Key (9001).\n"
                  "Configuration block info can be found below.\n"
                  "* Block B000 (00; CMK): Max amount of commands without MAC (byte 0), as well as plain mode access (unknown).\n"
                  "* Block B001 (01; CCK): Installation identifier for Virtual Card. Please consult NXP for data.\n"
                  "* Block B002 (02; CCK): ATS data.\n"
                  "* Block B003 (03; CCK): Use Random ID in SL3, decide whether proximity check is mandatory.\n  * DO NOT WRITE THIS BLOCK UNDER ANY CIRCUMSTANCES! Risk of bricking.\n"
                  "More configuration tips to follow. Check JMY600 Series IC Card Module.\n"
                  "hf mfp chconf -c 00 -d 10ffffffffffffffffffffffffffffff --key A0A1A2A3A4A5A6A7A0A1A2A3A4A5A6A7 -> Allow 16 commands without MAC in a single transaction."
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "详细", "详细输出"),
        arg_lit0(NULL, "nmr", "Do not expect MAC in response"),
        arg_int1("c", "conf", "<hex>", "配置块号，0-3"),
        arg_str0("k", "key",      "<hex>", "卡片密钥，16个十六进制字节"),
        arg_lit0(NULL, "cck", "Auth as Card Configuration key instead of Card Master Key"),
        arg_str1("d",  "数据",    "<hex>", "新配置数据，16个十六进制字节"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);
    bool nomacres = arg_get_lit(ctx, 2);

    uint8_t keyn[250] = {0};
    uint32_t blockNum = arg_get_int(ctx, 3);

    uint8_t key[250] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 4, key, &keylen);
    bool usecck = arg_get_lit(ctx, 5);

    uint8_t datain[250] = {0};
    int datainlen = 0;
    CLIGetHexWithReturn(ctx, 6, datain, &datainlen);

    CLIParserFree(ctx);

    mfpSetVerboseMode(verbose);

    if (keylen == 0) {
        memmove(key, mfp_default_key, 16);
        keylen = 16;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<key> 必须是 16 字节。实际为 %d", keylen);
        return PM3_EINVARG;
    }

    if (datainlen != 16) {
        PrintAndLogEx(ERR, "<data> 必须是 16 字节。实际为 %d", datainlen);
        return PM3_EINVARG;
    }

    if (blockNum > 3) {
        PrintAndLogEx(ERR, "<config number> 必须在 [0..3] 范围内。实际为 %d", blockNum);
        return PM3_EINVARG;
    }

    mf4Session_t mf4session;
    keyn[0] = 0x90;
    keyn[1] = usecck ? 0x01 : 0x00;

    if (verbose) {
        PrintAndLogEx(INFO, "--key 索引:", sprint_hex(keyn, 2));
    }

    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "认证错误: %d", res);
        return res;
    }

    mfp_data_crypt(&mf4session, &datain[0], &datain[0], false);

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    res = MFPWriteBlock(&mf4session, false, nomacres, blockNum & 0xff, 0xb0, datain, false, false, data, sizeof(data), &datalen, mac);
    if (res) {
        PrintAndLogEx(ERR, "写入错误: %d", res);
        DropField();
        return res;
    }

    if (datalen != 3 && (datalen != 3 + (nomacres ? 0 : 8))) {
        PrintAndLogEx(ERR, "错误返回长度：%d", datalen);
        DropField();
        return PM3_ESOFT;
    }

    if (datalen && data[0] != 0x90) {
        PrintAndLogEx(ERR, "卡片写入错误: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        DropField();
        return PM3_ESOFT;
    }

    if (memcmp(&data[1], mac, 8) && !nomacres) {
        PrintAndLogEx(WARNING, "警告：mac不相等...");
        PrintAndLogEx(WARNING, "MAC   card: %s", sprint_hex(&data[1], 8));
        PrintAndLogEx(WARNING, "MAC读取器: %s", sprint_hex(mac, 8));
    } else if (nomacres == false) {
        if (verbose) {
            PrintAndLogEx(INFO, "MAC: %s", sprint_hex(&data[1], 8));
        }
    }

    DropField();
    PrintAndLogEx(INFO, "Write config ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

// Progress indicators (non-verbose mode):
//   '.'  progress heartbeat, printed every 10 key attempts
//   '+'  key found for a sector
//   'R'  retry after transient communication error
//   'E'  exchange error, aborts the check
static int plus_key_check(uint8_t start_sector, uint8_t end_sector, uint8_t startKeyAB, uint8_t endKeyAB,
                          uint8_t *keys, size_t keycount, uint8_t foundKeys[2][64][AES_KEY_LEN + 1],
                          bool verbose, bool newline) {

    if (newline) {
        PrintAndLogEx(INFO, "." NOLF);
    }

    // sector number from 0
    for (uint8_t sector = start_sector; sector <= end_sector; sector++) {

        // 0-keyA 1-keyB
        for (uint8_t keyAB = startKeyAB; keyAB <= endKeyAB; keyAB++) {

            // skip already found keys
            if (foundKeys[keyAB][sector][0]) {
                continue;
            }

            int res;
            bool selectCard = true;

            // reset current key pointer after each loop
            uint8_t *currkey = keys;

            // main cycle with key check
            for (int i = 0; i < keycount; i++) {

                // allow client abort every iteration
                if (kbd_enter_pressed()) {
                    PrintAndLogEx(WARNING, "\\n通过键盘中止！\\n");
                    DropField();
                    return PM3_EOPABORTED;
                }

                if (i % 10 == 0) {
                    if (verbose == false) {
                        PrintAndLogEx(NORMAL, "." NOLF);
                    }
                }

                uint16_t uKeyNum = 0x4000 + sector * 2 + keyAB;
                uint8_t keyn[2] = { uKeyNum >> 8, uKeyNum & 0xff};

                // authentication loop with retries
                for (int retry = 0; retry < MFP_CHK_KEY_TRIES; retry++) {

                    res = MifareAuth4(NULL, keyn, currkey, selectCard, true, false, false, true);
                    if (res == PM3_SUCCESS || res == PM3_EWRONGANSWER) {
                        break;
                    }

                    if (verbose) {
                        PrintAndLogEx(WARNING, "\\n重试[%d]...", retry);
                    } else {
                        PrintAndLogEx(NORMAL, "R" NOLF);
                    }

                    DropField();
                    selectCard = true;
                    msleep(100);
                }

                // key for [sector,keyAB] found
                if (res == PM3_SUCCESS) {

                    if (verbose) {
                        PrintAndLogEx(INFO, "Found key for sector " _YELLOW_("%d") " key "_YELLOW_("%s") " [ " _GREEN_("%s") " ]", sector, (keyAB == 0) ? "A" : "B", sprint_hex_inrow(currkey, AES_KEY_LEN));
                    } else {
                        PrintAndLogEx(NORMAL, _GREEN_("+") NOLF);
                    }

                    foundKeys[keyAB][sector][0] = 0x01;
                    memcpy(&foundKeys[keyAB][sector][1], currkey, AES_KEY_LEN);

                    DropField();
                    selectCard = true;
//                    msleep(50);

                    // recursive test of a successful key
                    if (keycount > 1) {
                        plus_key_check(start_sector, end_sector, startKeyAB, endKeyAB, currkey, 1, foundKeys, verbose, false);
                    }

                    // break out from keylist check loop,
                    break;
                }

                if (verbose) {
                    PrintAndLogEx(WARNING, "\\n扇区 %02d 密钥 %d [%s] 结果: %d", sector, keyAB, sprint_hex_inrow(currkey, AES_KEY_LEN), res);
                }

                // RES can be:
                // PM3_ERFTRANS     -7
                // PM3_EWRONGANSWER -16
                if (res == PM3_ERFTRANS) {

                    if (verbose) {
                        PrintAndLogEx(ERR, "\\n交换错误。已中止。");
                    } else {
                        PrintAndLogEx(NORMAL, "E" NOLF);
                    }

                    DropField();
                    return PM3_ECARDEXCHANGE;
                }

                selectCard = false;

                // set pointer to next key
                currkey += AES_KEY_LEN;
            }
        }
    }

    DropField();
    return PM3_SUCCESS;
}

static void Fill2bPattern(uint8_t keyList[MAX_AES_KEYS_LIST_LEN][AES_KEY_LEN], uint32_t *n, uint32_t *startPattern) {

    uint32_t cnt = 0;
    for (uint32_t pt = *startPattern; pt < 0x10000; pt++) {

        for (uint8_t i = 0; i < AES_KEY_LEN; i += 2) {
            keyList[*n][i] = (pt >> 8) & 0xff;
            keyList[*n][i + 1] = pt & 0xff;
        }

        PrintAndLogEx(DEBUG, _YELLOW_("%4d") " - %s", *n, sprint_hex_inrow(keyList[*n], AES_KEY_LEN));

        // increase number of keys
        (*n)++;
        cnt++;

        *startPattern = pt;

        if (*n == MAX_AES_KEYS_LIST_LEN) {
            break;
        }
    }

    PrintAndLogEx(SUCCESS, "loaded " _GREEN_("%d") " pattern2 keys", cnt);

    (*startPattern)++;
}

static int CmdHFMFPChk(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 检查密钥",
                  "检查MIFARE Plus卡上的密钥",
                  "hf mfp chk -k 000102030405060708090a0b0c0d0e0f  -> check key on sector 0 as key A and B\n"
                  "hf mfp chk -s 2 -a                              -> check default key list on sector 2, only key A\n"
                  "hf mfp chk -f mfp_default_keys -s 0 -e 6        -> check keys from dictionary against sectors 0-6\n"
                  "hf mfp chk --pattern1b --dump                   -> check all 1-byte keys pattern and save found keys to file\n"
                  "hf mfp chk --pattern2b --startp2b FA00          -> check all 2-byte keys pattern. Start from key FA00FA00...FA00"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "keya",      "仅检查密钥A（默认：检查所有密钥）"),
        arg_lit0("b",  "keyb",      "仅检查密钥B（默认：检查所有密钥）"),
        arg_int0("s",  "startsec",  "<0..255>", "起始扇区号"),
        arg_int0("e",  "endsec",    "<0..255>", "结束扇区号"),
        arg_str0("k",  "key",       "<hex>", "用于检查的密钥（十六进制16字节）"),
        arg_str0("f", "file", "<fn>", "包含默认密钥的字典文件"),
        arg_lit0(NULL, "pattern1b", "Check all 1-byte combinations of key (0000...0000, 0101...0101, 0202...0202, ...)"),
        arg_lit0(NULL, "pattern2b", "Check all 2-byte combinations of key (0000...0000, 0001...0001, 0002...0002, ...)"),
        arg_str0(NULL, "startp2b",  "<pattern>", "Start key (2-byte HEX) for 2-byte search (use with `--pattern2b`)"),
        arg_lit0(NULL, "dump",      "Dump found keys to JSON file"),
        arg_lit0(NULL, "no-default",  "Skip check default keys"),
        arg_lit0("v",  "详细",   "详细输出"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keyA = arg_get_lit(ctx, 1);
    bool keyB = arg_get_lit(ctx, 2);

    uint8_t startSector = arg_get_int_def(ctx, 3, 0);
    uint8_t endSector = arg_get_int_def(ctx, 4, 0);

    uint32_t keyListLen = 0;
    uint8_t keyList[MAX_AES_KEYS_LIST_LEN][AES_KEY_LEN] = {{0}};
    uint8_t foundKeys[2][64][AES_KEY_LEN + 1] = {{{0}}};

    int vkeylen = 0;
    uint8_t vkey[AES_KEY_LEN] = {0};
    CLIGetHexWithReturn(ctx, 5, vkey, &vkeylen);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool pattern1b = arg_get_lit(ctx, 7);
    bool pattern2b = arg_get_lit(ctx, 8);

    int vpatternlen = 0;
    uint8_t vpattern[2];
    CLIGetHexWithReturn(ctx, 9, vpattern, &vpatternlen);

    bool create_dumpfile = arg_get_lit(ctx, 10);
    bool load_default = ! arg_get_lit(ctx, 11);
    bool verbose = arg_get_lit(ctx, 12);

    CLIParserFree(ctx);

    // sanity checks
    if (vkeylen && (vkeylen != AES_KEY_LEN)) {
        PrintAndLogEx(ERR, "指定的密钥必须为16字节。实际为%d", vkeylen);
        return PM3_EINVARG;
    }

    if (pattern1b && pattern2b) {
        PrintAndLogEx(ERR, "模式搜索模式必须是2字节或仅1字节");
        return PM3_EINVARG;
    }

    if (fnlen && (pattern1b || pattern2b)) {
        PrintAndLogEx(ERR, "模式搜索模式和字典模式不能在同一命令中使用");
        return PM3_EINVARG;
    }

    if (vpatternlen && pattern2b == false) {
        PrintAndLogEx(WARNING, "已输入模式，但搜索模式不是2字节搜索");
        return PM3_EINVARG;
    }

    if (vpatternlen > 2) {
        PrintAndLogEx(ERR, "模式必须是2字节。得到 %d", vpatternlen);
        return PM3_EINVARG;
    }

    uint32_t startPattern = (vpattern[0] << 8) + vpattern[1];

    // read card UID
    iso14a_card_select_t card;
    int nxptype = MTNONE;
    int res = mfp_read_card_id(&card, &nxptype);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t startKeyAB = 0;
    uint8_t endKeyAB = 1;
    if (keyA && (keyB == false)) {
        endKeyAB = 0;
    }

    if ((keyA == false) && keyB) {
        startKeyAB = 1;
    }

    if (endSector < startSector) {
        endSector = startSector;
    }

    // Print generic information
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("检查密钥") " ----------");
    PrintAndLogEx(INFO, "起始扇区... %u", startSector);
    PrintAndLogEx(INFO, "结束扇区..... %u", endSector);

    char keytypestr[6] = {0};
    if (keyA == false && keyB == false) {
        strcat(keytypestr, "AB");
    }
    if (keyA) {
        strcat(keytypestr, "A");
    }
    if (keyB) {
        strcat(keytypestr, "B");
    }
    PrintAndLogEx(INFO, "Key type....... " _YELLOW_("%s"), keytypestr);
    PrintAndLogEx(NORMAL, "");

    //
    // Key creation section
    //
    // 1-byte pattern search mode
    if (pattern1b) {

        for (int i = 0; i < 0x100; i++) {
            memset(keyList[i], i, 16);
            PrintAndLogEx(DEBUG, _YELLOW_("%3d") " - %s", i, sprint_hex_inrow(keyList[i], AES_KEY_LEN));
        }

        keyListLen = 0x100;
        PrintAndLogEx(SUCCESS, "loaded " _GREEN_("%d") " pattern1b keys", 0x100);
    }

    // 2-byte pattern search mode
    if (pattern2b) {
        Fill2bPattern(keyList, &keyListLen, &startPattern);
    }

    // dictionary mode
    uint8_t *key_block = NULL;
    uint32_t keycnt = 0;

    int ret = mfp_load_keys(&key_block, &keycnt, vkey, vkeylen, filename, fnlen, card.uid, load_default);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    PrintAndLogEx(INFO, "开始检查密钥...");

    // time
    uint64_t t1 = msclock();

    res = plus_key_check(startSector, endSector, startKeyAB, endKeyAB, key_block, keycnt, foundKeys, verbose, true);
    if (res == PM3_EOPABORTED) {
        t1 = msclock() - t1;
        PrintAndLogEx(INFO, "\ntime in checkkeys " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
        return res;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "开始检查基于模式的密钥...");
    while (keyListLen) {

        res = plus_key_check(startSector, endSector, startKeyAB, endKeyAB, (uint8_t *)keyList, keyListLen, foundKeys, verbose, true);
        if (res == PM3_EOPABORTED) {
            break;
        }

        if (pattern2b && startPattern < 0x10000) {
            keyListLen = 0;
            PrintAndLogEx(NORMAL, "");
            Fill2bPattern(keyList, &keyListLen, &startPattern);
            continue;
        }
        break;
    }

    t1 = msclock() - t1;
    PrintAndLogEx(INFO, "\ntime in checkkeys " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);

    // print result
    char strA[46 + 1] = {0};
    char strB[46 + 1] = {0};

    bool has_ndef_key = false;
    bool printedHeader = false;
    for (uint8_t s = startSector; s <= endSector; s++) {

        if ((memcmp(&foundKeys[0][s][1], g_mifarep_ndef_key, AES_KEY_LEN) == 0) ||
                (memcmp(&foundKeys[1][s][1], g_mifarep_ndef_key, AES_KEY_LEN) == 0)) {
            has_ndef_key = true;
        }

        if (printedHeader == false) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-----+----------------------------------+----------------------------------");
            PrintAndLogEx(INFO, " Sec | key A                            | key B");
            PrintAndLogEx(INFO, "-----+----------------------------------+----------------------------------");
            printedHeader = true;
        }

        if (foundKeys[0][s][0]) {
            snprintf(strA, sizeof(strA), _GREEN_("%s"), sprint_hex_inrow(&foundKeys[0][s][1], AES_KEY_LEN));
        } else {
            snprintf(strA, sizeof(strA), _RED_("%s"), "--------------------------------");
        }

        if (foundKeys[1][s][0]) {
            snprintf(strB, sizeof(strB), _GREEN_("%s"), sprint_hex_inrow(&foundKeys[1][s][1], AES_KEY_LEN));
        } else {
            snprintf(strB, sizeof(strB), _RED_("%s"), "--------------------------------");
        }

        PrintAndLogEx(INFO, " " _YELLOW_("%03d") " | %s | %s", s, strA, strB);
    }

    if (printedHeader == false) {
        PrintAndLogEx(INFO, "未找到密钥");
    } else {
        PrintAndLogEx(INFO, "-----+----------------------------------+----------------------------------");
    }
    PrintAndLogEx(NORMAL, "");

    // save keys to json
    if (create_dumpfile && printedHeader) {

        size_t keys_len = (2 * 64 * (AES_KEY_LEN + 1));

        uint8_t data[10 + 1 + 2 + 1 + 256 + keys_len];
        memset(data, 0, sizeof(data));

        memcpy(data, card.uid, card.uidlen);
        data[10] = card.sak;
        data[11] = card.atqa[1];
        data[12] = card.atqa[0];
        data[13] = card.ats_len;
        memcpy(&data[14], card.ats, card.ats_len);

        char *fptr = calloc(sizeof(char) * (strlen("hf-mfp-") + strlen("-key")) + card.uidlen * 2 + 1,  sizeof(uint8_t));
        if (fptr == NULL) {
            PrintAndLogEx(WARNING, "分配内存失败");
            return PM3_EMALLOC;
        }
        strcpy(fptr, "hf-mfp-");

        FillFileNameByUID(fptr, card.uid, "-key", card.uidlen);

        // length: UID(10b)+SAK(1b)+ATQA(2b)+ATSlen(1b)+ATS(atslen)+foundKeys[2][64][AES_KEY_LEN + 1]
        memcpy(&data[14 + card.ats_len], foundKeys, keys_len);
        // 64 here is for how many "rows" there is in the data array.  A bit confusing
        saveFileJSON(fptr, jsfMfPlusKeys, data, 64, NULL);
        free(fptr);
    }

    // MAD detection
    if ((memcmp(&foundKeys[0][0][1], g_mifarep_mad_key, AES_KEY_LEN) == 0)) {
        PrintAndLogEx(HINT, "Hint: MAD key detected. Try " _YELLOW_("`hf mfp mad`") " for more details");
    }

    // NDEF detection
    if (has_ndef_key) {
        PrintAndLogEx(HINT, "Hint: NDEF key detected. Try " _YELLOW_("`hf mfp ndefread -h`") " for more details");
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int mfp_load_keys_from_json(const char *filename, uint8_t foundKeys[2][64][AES_KEY_LEN + 1], bool verbose) {

    // loadFileJSONex handles "mfpkeys" file type.
    // Buffer layout: UID(7) + pad(3) + SAK(1) + ATQA(2) + ATSlen(1) + ATS(atslen)
    //   then flat keys: KeyA0(16) KeyB0(16) KeyA1(16) KeyB1(16) ...
    uint8_t data[14 + 256 + (2 * 64 * AES_KEY_LEN)];
    memset(data, 0, sizeof(data));
    size_t datalen = 0;

    int res = loadFileJSONex(filename, data, sizeof(data), &datalen, verbose, NULL);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t atslen = data[13];
    size_t key_offset = 14 + atslen;

    for (int i = 0; i < 64; i++) {
        size_t off = key_offset + (i * 2 * AES_KEY_LEN);
        uint8_t *ka = data + off;
        uint8_t *kb = data + off + AES_KEY_LEN;

        // check if key is non-zero (present in JSON)
        if (memcmp(ka, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", AES_KEY_LEN) != 0) {
            foundKeys[MF_KEY_A][i][0] = 1;
            memcpy(&foundKeys[MF_KEY_A][i][1], ka, AES_KEY_LEN);
        }
        if (memcmp(kb, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", AES_KEY_LEN) != 0) {
            foundKeys[MF_KEY_B][i][0] = 1;
            memcpy(&foundKeys[MF_KEY_B][i][1], kb, AES_KEY_LEN);
        }
    }

    return PM3_SUCCESS;
}

// Security level for each sector
#define MFP_SL_UNKNOWN  0
#define MFP_SL_1        1
#define MFP_SL_3        3

// Load MFC (CRYPTO1) keys from a binary key file (first half keyA, second half keyB)
static int mfp_load_mfc_keys_from_bin(const char *filename, uint8_t mfcFoundKeys[2][64][MIFARE_KEY_SIZE + 1], uint8_t numSectors, bool verbose) {

    uint8_t *keyA = NULL;
    uint8_t *keyB = NULL;
    size_t alen = 0, blen = 0;

    int res = loadFileBinaryKey(filename, "", (void **)&keyA, (void **)&keyB, &alen, &blen, verbose);
    if (res != PM3_SUCCESS) {
        return res;
    }

    for (uint8_t s = 0; s < numSectors && s * MIFARE_KEY_SIZE < alen; s++) {
        mfcFoundKeys[MF_KEY_A][s][0] = 1;
        memcpy(&mfcFoundKeys[MF_KEY_A][s][1], keyA + s * MIFARE_KEY_SIZE, MIFARE_KEY_SIZE);
    }

    for (uint8_t s = 0; s < numSectors && s * MIFARE_KEY_SIZE < blen; s++) {
        mfcFoundKeys[MF_KEY_B][s][0] = 1;
        memcpy(&mfcFoundKeys[MF_KEY_B][s][1], keyB + s * MIFARE_KEY_SIZE, MIFARE_KEY_SIZE);
    }

    free(keyA);
    free(keyB);
    return PM3_SUCCESS;
}

// Try to read a sector using SL1 (CRYPTO1) with the given 6-byte key
static int mfp_read_sector_sl1(uint8_t sectorNo, uint8_t keyType, const uint8_t *key6, uint8_t *dataout, bool verbose) {
    int res = mf_read_sector(sectorNo, keyType, key6, dataout);
    if (verbose && res != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "SL1 读取扇区 %u 密钥类型 %u 失败: %d", sectorNo, keyType, res);
    }
    return res;
}

static int CmdHFMFPDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp 转储",
                  "将MIFARE Plus标签转储到文件(bin/json)\\n"
                  "Reads sectors using keys from `hf mfp chk --dump` (AES/SL3)\n"
                  "and/or `hf mf chk` key file (CRYPTO1/SL1) for mixed-mode cards.\n"
                  "Key files are auto-detected by UID if not specified.\n"
                  "If no <name> given, UID will be used as filename",
                  "hf mfp dump\n"
                  "hf mfp dump --keys hf-mfp-01020304-key.json\n"
                  "hf mfp dump --keys hf-mfp-01020304-key.json --mfc-keys hf-mf-01020304-key.bin\n"
                  "hf mfp dump -k ffffffffffffffffffffffffffffffff\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f",  "file",     "<fn>",  "指定转储文件的文件名"),
        arg_str0(NULL, "keys",     "<fn>",  "AES key file from `hf mfp chk --dump` (JSON)"),
        arg_str0("k",  "key",      "<hex>", "所有扇区的 AES 密钥（16 个十六进制字节）"),
        arg_str0(NULL, "mfc-keys", "<fn>",  "MFC key file for SL1 sectors (.bin from `hf mf chk`)"),
        arg_lit0(NULL, "ns",           "No save to file"),
        arg_lit0("v",  "详细",      "详细输出"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int datafnlen = 0;
    char data_fn[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)data_fn, FILE_PATH_SIZE, &datafnlen);

    int keyfnlen = 0;
    char key_fn[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)key_fn, FILE_PATH_SIZE, &keyfnlen);

    int userkeylen = 0;
    uint8_t userkey[AES_KEY_LEN] = {0};
    CLIGetHexWithReturn(ctx, 3, userkey, &userkeylen);

    int mfckeyfnlen = 0;
    char mfc_key_fn[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)mfc_key_fn, FILE_PATH_SIZE, &mfckeyfnlen);

    bool nosave = arg_get_lit(ctx, 5);
    bool verbose = arg_get_lit(ctx, 6);

    CLIParserFree(ctx);

    if (userkeylen > 0 && userkeylen != AES_KEY_LEN) {
        PrintAndLogEx(ERR, "AES 密钥必须为 16 字节。实际为 %d", userkeylen);
        return PM3_EINVARG;
    }

    mfpSetVerboseMode(verbose);

    // read card info
    iso14a_card_select_t card;
    int nxptype = MTNONE;
    int res = mfp_read_card_id(&card, &nxptype);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "选择卡片失败");
        return res;
    }

    // determine number of sectors from ATQA
    uint16_t ATQA = card.atqa[0] + (card.atqa[1] << 8);
    uint8_t numSectors;
    if (ATQA & 0x0002) {
        numSectors = MIFARE_4K_MAXSECTOR;  // 40 sectors (4K)
    } else {
        numSectors = MIFARE_2K_MAXSECTOR;  // 32 sectors (2K)
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(INFO, "UID......... " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
    PrintAndLogEx(INFO, "ATQA........ " _GREEN_("%02X %02X"), card.atqa[1], card.atqa[0]);
    PrintAndLogEx(INFO, "SAK......... " _GREEN_("%02X"), card.sak);
    PrintAndLogEx(INFO, "Sectors..... " _GREEN_("%u") " (%s)", numSectors, (numSectors == MIFARE_4K_MAXSECTOR) ? "4K" : "2K");
    PrintAndLogEx(NORMAL, "");

    // ========================================
    // Load keys
    // ========================================

    // AES keys: aesFoundKeys[keytype][sector][0]=found, [1..16]=key
    uint8_t aesFoundKeys[2][64][AES_KEY_LEN + 1];
    memset(aesFoundKeys, 0, sizeof(aesFoundKeys));

    // MFC keys: mfcFoundKeys[keytype][sector][0]=found, [1..6]=key
    uint8_t mfcFoundKeys[2][64][MIFARE_KEY_SIZE + 1];
    memset(mfcFoundKeys, 0, sizeof(mfcFoundKeys));

    // Auto-detect AES key file by UID if not specified
    char *aes_fptr = NULL;
    if (keyfnlen == 0) {
        aes_fptr = calloc(sizeof(char) * (strlen("hf-mfp-") + strlen("-key")) + card.uidlen * 2 + 1, sizeof(uint8_t));
        if (aes_fptr != NULL) {
            strcpy(aes_fptr, "hf-mfp-");
            FillFileNameByUID(aes_fptr, card.uid, "-key", card.uidlen);
            strncpy(key_fn, aes_fptr, FILE_PATH_SIZE - 1);
            keyfnlen = strlen(key_fn);
        }
    }

    // Load AES keys from JSON key file (from hf mfp chk --dump)
    if (keyfnlen > 0) {
        res = mfp_load_keys_from_json(key_fn, aesFoundKeys, (aes_fptr == NULL));
        if (res != PM3_SUCCESS) {
            if (aes_fptr == NULL) {
                PrintAndLogEx(WARNING, "加载 AES 密钥文件失败，继续而不加载");
            }
        } else {
            int cnt = 0;
            for (uint8_t s = 0; s < numSectors; s++) {
                if (aesFoundKeys[MF_KEY_A][s][0]) cnt++;
                if (aesFoundKeys[MF_KEY_B][s][0]) cnt++;
            }
            PrintAndLogEx(SUCCESS, "Loaded " _GREEN_("%d") " AES keys from key file", cnt);
        }
    }
    free(aes_fptr);

    // Apply user-supplied AES key to all slots that don't have one yet
    if (userkeylen == AES_KEY_LEN) {
        int applied = 0;
        for (uint8_t s = 0; s < numSectors; s++) {
            for (uint8_t kt = MF_KEY_A; kt <= MF_KEY_B; kt++) {
                if (aesFoundKeys[kt][s][0] == 0) {
                    aesFoundKeys[kt][s][0] = 1;
                    memcpy(&aesFoundKeys[kt][s][1], userkey, AES_KEY_LEN);
                    applied++;
                }
            }
        }
        PrintAndLogEx(SUCCESS, "Applied user AES key to " _GREEN_("%d") " key slots", applied);
    }

    // Auto-detect MFC key file by UID if not specified
    char *mfc_fptr = NULL;
    if (mfckeyfnlen == 0) {
        mfc_fptr = calloc(sizeof(char) * (strlen("hf-mf-") + strlen("-key.bin")) + card.uidlen * 2 + 1, sizeof(uint8_t));
        if (mfc_fptr != NULL) {
            strcpy(mfc_fptr, "hf-mf-");
            FillFileNameByUID(mfc_fptr, card.uid, "-key.bin", card.uidlen);
            strncpy(mfc_key_fn, mfc_fptr, FILE_PATH_SIZE - 1);
            mfckeyfnlen = strlen(mfc_key_fn);
        }
    }

    // Load MFC keys from binary key file (from hf mf chk)
    if (mfckeyfnlen > 0) {
        res = mfp_load_mfc_keys_from_bin(mfc_key_fn, mfcFoundKeys, numSectors, (mfc_fptr == NULL));
        if (res != PM3_SUCCESS) {
            if (mfc_fptr == NULL) {
                PrintAndLogEx(WARNING, "加载 MFC 密钥文件失败，继续而不加载");
            }
        } else {
            int cnt = 0;
            for (uint8_t s = 0; s < numSectors; s++) {
                if (mfcFoundKeys[MF_KEY_A][s][0]) cnt++;
                if (mfcFoundKeys[MF_KEY_B][s][0]) cnt++;
            }
            PrintAndLogEx(SUCCESS, "Loaded " _GREEN_("%d") " MFC (CRYPTO1) keys from key file", cnt);
        }
    }
    free(mfc_fptr);

    // Check that we have at least some keys to work with
    bool have_keys = (userkeylen == AES_KEY_LEN);
    if (!have_keys) {
        for (uint8_t s = 0; s < numSectors; s++) {
            if (aesFoundKeys[MF_KEY_A][s][0] || aesFoundKeys[MF_KEY_B][s][0] ||
                    mfcFoundKeys[MF_KEY_A][s][0] || mfcFoundKeys[MF_KEY_B][s][0]) {
                have_keys = true;
                break;
            }
        }
    }
    if (!have_keys) {
        PrintAndLogEx(ERR, "No keys available. Run " _YELLOW_("`hf mfp chk --dump`") " and/or " _YELLOW_("`hf mf chk --dump`") " first");
        return PM3_ENODATA;
    }

    // ========================================
    // Read sectors with loaded keys
    // ========================================

    // Determine SL for each sector based on which keys are available
    uint8_t sectorSL[64];
    memset(sectorSL, MFP_SL_UNKNOWN, sizeof(sectorSL));
    for (uint8_t s = 0; s < numSectors; s++) {
        if (aesFoundKeys[MF_KEY_A][s][0] || aesFoundKeys[MF_KEY_B][s][0]) {
            sectorSL[s] = MFP_SL_3;
        }
        if (mfcFoundKeys[MF_KEY_A][s][0] || mfcFoundKeys[MF_KEY_B][s][0]) {
            sectorSL[s] = MFP_SL_1;
        }
    }

    uint16_t totalBlocks = 0;
    for (uint8_t s = 0; s < numSectors; s++) {
        totalBlocks += mfNumBlocksPerSector(s);
    }

    uint8_t *carddata = calloc(totalBlocks * MFBLOCK_SIZE, sizeof(uint8_t));
    if (carddata == NULL) {
        PrintAndLogEx(ERR, "分配内存失败");

        return PM3_EMALLOC;
    }

    uint8_t sectorRead[64];
    memset(sectorRead, 0, sizeof(sectorRead));

    PrintAndLogEx(INFO, "读取卡片数据...");

    int sectorsRead = 0;
    int sl3Count = 0;
    int sl1Count = 0;

    for (uint8_t s = 0; s < numSectors; s++) {

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\\n通过键盘中止");
            break;
        }

        bool readOK = false;
        uint16_t blockOffset = mfFirstBlockOfSector(s);
        uint8_t blocksInSector = mfNumBlocksPerSector(s);

        if (sectorSL[s] == MFP_SL_3) {
            // --- Try SL3 (AES) ---
            for (uint8_t kt = MF_KEY_A; kt <= MF_KEY_B && !readOK; kt++) {
                if (aesFoundKeys[kt][s][0] == 0) {
                    continue;
                }

                uint8_t sector_data[16 * 16] = {0};
                res = mfpReadSector(s, kt, &aesFoundKeys[kt][s][1], sector_data, verbose);
                if (res == PM3_SUCCESS) {
                    memcpy(carddata + (blockOffset * MFBLOCK_SIZE), sector_data, blocksInSector * MFBLOCK_SIZE);
                    sectorRead[s] = 1;
                    readOK = true;
                    sectorsRead++;
                    sl3Count++;
                } else if (verbose) {
                    PrintAndLogEx(DEBUG, "扇区 %u SL3 密钥%s 失败: %d", s, (kt == MF_KEY_A) ? "A" : "B", res);
                }
            }
        } else if (sectorSL[s] == MFP_SL_1) {
            // --- Try SL1 (CRYPTO1) ---
            DropField();
            for (uint8_t kt = MF_KEY_A; kt <= MF_KEY_B && !readOK; kt++) {
                if (mfcFoundKeys[kt][s][0] == 0) {
                    continue;
                }

                uint8_t sector_data[16 * 16] = {0};
                res = mfp_read_sector_sl1(s, kt, &mfcFoundKeys[kt][s][1], sector_data, verbose);
                if (res == PM3_SUCCESS) {
                    memcpy(carddata + (blockOffset * MFBLOCK_SIZE), sector_data, blocksInSector * MFBLOCK_SIZE);
                    sectorRead[s] = 1;
                    readOK = true;
                    sectorsRead++;
                    sl1Count++;
                } else if (verbose) {
                    PrintAndLogEx(DEBUG, "扇区 %u SL1 密钥%s 失败: %d", s, (kt == MF_KEY_A) ? "A" : "B", res);
                }
            }
        }

        if (readOK) {
            PrintAndLogEx(INPLACE, "Reading sector %3d / %3d ( " _GREEN_("ok, %s") " )",
                          s, numSectors - 1,
                          (sectorSL[s] == MFP_SL_3) ? "SL3" : "SL1");
        } else {
            PrintAndLogEx(INPLACE, "Reading sector %3d / %3d ( " _RED_("fail") " )", s, numSectors - 1);
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Successfully read " _GREEN_("%d") " / %d sectors  (SL3: %d, SL1: %d)", sectorsRead, numSectors, sl3Count, sl1Count);
    PrintAndLogEx(NORMAL, "");

    // ========================================
    // Print sector summary
    // ========================================
    PrintAndLogEx(INFO, "-----+----+----------------------------------+----------------------------------");
    PrintAndLogEx(INFO, " Sec | SL | key A                            | key B");
    PrintAndLogEx(INFO, "-----+----+----------------------------------+----------------------------------");

    for (uint8_t s = 0; s < numSectors; s++) {
        char strA[46 + 1] = {0};
        char strB[46 + 1] = {0};
        const char *slStr;

        switch (sectorSL[s]) {
            case MFP_SL_3:
                slStr = _GREEN_("3 ");
                if (aesFoundKeys[MF_KEY_A][s][0]) {
                    snprintf(strA, sizeof(strA), _GREEN_("%s"), sprint_hex_inrow(&aesFoundKeys[MF_KEY_A][s][1], AES_KEY_LEN));
                } else {
                    snprintf(strA, sizeof(strA), _RED_("%s"), "--------------------------------");
                }
                if (aesFoundKeys[MF_KEY_B][s][0]) {
                    snprintf(strB, sizeof(strB), _GREEN_("%s"), sprint_hex_inrow(&aesFoundKeys[MF_KEY_B][s][1], AES_KEY_LEN));
                } else {
                    snprintf(strB, sizeof(strB), _RED_("%s"), "--------------------------------");
                }
                break;
            case MFP_SL_1:
                slStr = _YELLOW_("1 ");
                if (mfcFoundKeys[MF_KEY_A][s][0]) {
                    snprintf(strA, sizeof(strA), _GREEN_("%s") "                  ", sprint_hex_inrow(&mfcFoundKeys[MF_KEY_A][s][1], MIFARE_KEY_SIZE));
                } else {
                    snprintf(strA, sizeof(strA), _RED_("%s"), "--------------------------------");
                }
                if (mfcFoundKeys[MF_KEY_B][s][0]) {
                    snprintf(strB, sizeof(strB), _GREEN_("%s") "                  ", sprint_hex_inrow(&mfcFoundKeys[MF_KEY_B][s][1], MIFARE_KEY_SIZE));
                } else {
                    snprintf(strB, sizeof(strB), _RED_("%s"), "--------------------------------");
                }
                break;
            default:
                slStr = _RED_("? ");
                snprintf(strA, sizeof(strA), _RED_("%s"), "--------------------------------");
                snprintf(strB, sizeof(strB), _RED_("%s"), "--------------------------------");
                break;
        }

        PrintAndLogEx(INFO, " " _YELLOW_("%03d") " | %s | %s | %s", s, slStr, strA, strB);
    }
    PrintAndLogEx(INFO, "-----+----+----------------------------------+----------------------------------");
    PrintAndLogEx(NORMAL, "");

    // ========================================
    // Display block data
    // ========================================
    for (uint8_t s = 0; s < numSectors; s++) {
        if (sectorRead[s] == 0) {
            continue;
        }

        mf_print_sector_hdr(s);
        uint16_t blockOffset = mfFirstBlockOfSector(s);
        for (uint8_t b = 0; b < mfNumBlocksPerSector(s); b++) {
            mf_print_block_one(blockOffset + b, carddata + ((blockOffset + b) * MFBLOCK_SIZE), verbose);
        }
    }
    PrintAndLogEx(NORMAL, "");

    if (nosave) {
        PrintAndLogEx(INFO, "调用时使用 no-save 选项");
        free(carddata);

        return PM3_SUCCESS;
    }

    // ========================================
    // Save dump
    // ========================================
    size_t dumpsize = totalBlocks * MFBLOCK_SIZE;

    // generate filename from UID if not provided
    if (datafnlen < 1) {
        char *fptr = calloc(sizeof(char) * (strlen("hf-mfp-") + strlen("-dump")) + card.uidlen * 2 + 1, sizeof(uint8_t));
        if (fptr == NULL) {
            PrintAndLogEx(ERR, "分配内存失败");
            free(carddata);

            return PM3_EMALLOC;
        }
        strcpy(fptr, "hf-mfp-");
        FillFileNameByUID(fptr, card.uid, "-dump", card.uidlen);
        strcpy(data_fn, fptr);
        free(fptr);
    }

    pm3_save_mf_dump(data_fn, carddata, dumpsize, jsfCardMemory);

    if (sectorsRead != numSectors) {
        PrintAndLogEx(HINT, "部分转储：已读取 %d/%d 个扇区", sectorsRead, numSectors);
        PrintAndLogEx(HINT, "Hint: use " _YELLOW_("`hf mfp chk --dump`") " and/or " _YELLOW_("`hf mf chk`") " to find more keys");
    }

    free(carddata);
    return PM3_SUCCESS;
}

static int CmdHFMFPMAD(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp MAD",
                  "检查并打印MIFARE应用目录（MAD）",
                  "hf mfp mad\n"
                  "hf mfp mad --aid e103 -k d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7  -> read and print NDEF data from MAD aid"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "详细",  "详细输出"),
        arg_str0(NULL, "aid",      "<hex>", "Print all sectors with aid"),
        arg_str0("k",  "key",      "<hex>", "用于打印扇区的密钥"),
        arg_lit0("b",  "keyb",     "使用密钥 B 访问打印扇区（默认：密钥 A）"),
        arg_lit0(NULL, "be",       "(optional: BigEndian)"),
        arg_lit0(NULL, "dch",      "Decode Card Holder information"),
        arg_lit0(NULL, "override", "override failed crc check"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);
    uint8_t key[16] = {0};
    int keylen;
    CLIGetHexWithReturn(ctx, 3, key, &keylen);
    bool keyB = arg_get_lit(ctx, 4);
    bool swapmad = arg_get_lit(ctx, 5);
    bool decodeholder = arg_get_lit(ctx, 6);
    bool override = arg_get_lit(ctx, 7);

    CLIParserFree(ctx);

    if (aidlen != 2 && !decodeholder && keylen > 0) {
        PrintAndLogEx(WARNING, "改用默认 MAD 密钥");
    }

    uint8_t sector0[16 * 4] = {0};
    uint8_t sector16[16 * 4] = {0};

    if (mfpReadSector(MF_MAD1_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector0, verbose)) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(ERR, "错误，读取扇区 0。卡片没有 MAD 或默认密钥上没有 MAD");
        return PM3_ESOFT;
    }

    MADPrintHeader();

    if (verbose) {
        PrintAndLogEx(SUCCESS, "原始:");
        for (int i = 0; i < 4; i ++)
            PrintAndLogEx(INFO, "[%d] %s", i, sprint_hex(&sector0[i * 16], 16));
    }

    bool haveMAD2 = false;
    MAD1DecodeAndPrint(sector0, swapmad, verbose, &haveMAD2);

    if (haveMAD2) {
        if (mfpReadSector(MF_MAD2_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector16, verbose)) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(ERR, "error, read sector " _YELLOW_("0x10") ". Card doesn't have MAD or doesn't have MAD on default keys");
            return PM3_ESOFT;
        }

        MAD2DecodeAndPrint(sector16, swapmad, verbose);
    }

    if (aidlen == 2 || decodeholder) {
        uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
        size_t madlen = 0;
        if (MADDecode(sector0, sector16, mad, &madlen, swapmad, override)) {
            PrintAndLogEx(ERR, "无法解码 MAD");
            return PM3_EWRONGANSWER;
        }

        // copy default NDEF key
        uint8_t akey[16] = {0};
        memcpy(akey, g_mifarep_ndef_key, 16);

        // user specified key
        if (keylen == 16) {
            memcpy(akey, key, 16);
        }

        uint16_t aaid = 0x0004;
        if (aidlen == 2) {
            aaid = (aid[0] << 8) + aid[1];
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-------------- " _CYAN_("AID 0x%04x") " ---------------", aaid);

            for (int i = 0; i < madlen; i++) {
                if (aaid == mad[i]) {
                    uint8_t vsector[16 * 4] = {0};
                    if (mfpReadSector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, akey, vsector, false)) {
                        PrintAndLogEx(NORMAL, "");
                        PrintAndLogEx(ERR, "错误，读取扇区 %d 出错", i + 1);
                        return PM3_ESOFT;
                    }

                    for (int j = 0; j < (verbose ? 4 : 3); j ++)
                        PrintAndLogEx(NORMAL, " [%03d] %s", (i + 1) * 4 + j, sprint_hex(&vsector[j * 16], 16));
                }
            }
        }

        if (decodeholder) {

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-------- " _CYAN_("Card Holder Info 0x%04x") " --------", aaid);

            uint8_t data[4096] = {0};
            int datalen = 0;

            for (int i = 0; i < madlen; i++) {
                if (aaid == mad[i]) {

                    uint8_t vsector[16 * 4] = {0};
                    if (mf_read_sector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, akey, vsector)) {
                        PrintAndLogEx(NORMAL, "");
                        PrintAndLogEx(ERR, "错误，读取扇区 %d", i + 1);
                        return PM3_ESOFT;
                    }

                    memcpy(&data[datalen], vsector, 16 * 3);
                    datalen += 16 * 3;
                }
            }

            if (!datalen) {
                PrintAndLogEx(WARNING, "无持卡人信息数据");
                return PM3_SUCCESS;
            }
            MADCardHolderInfoDecode(data, datalen, verbose);
        }
    }
    return PM3_SUCCESS;
}

static int CmdHFMFPNDEFFormat(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp NDEF 格式化",
                  "将 MIFARE Plus 标签格式化为具有数据交换格式 (NDEF) 的 NFC 标签\\n"
                  "If no <name> given, UID will be used as filename. \n"
                  "It will try default keys and MAD keys to detect if tag is already formatted in order to write.\n"
                  "\n"
                  "If not, it will try finding a key file based on your UID.  ie, if you ran autopwn before",
                  "hf mfp ndefformat\n"
                  "hf mfp ndefformat --keys hf-mf-01020304-key.bin -->  with keys from specified file\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "keys", "<fn>", "密钥文件名"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int keyfnlen = 0;
    char keyFilename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)keyFilename, FILE_PATH_SIZE, &keyfnlen);

    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "尚未实现。欢迎贡献代码！");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

int CmdHFMFPNDEFRead(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp NDEF 读取",
                  "打印 NFC 数据交换格式 (NDEF)",
                  "hf mfp ndefread \n"
                  "hf mfp ndefread -vv                                            -> shows NDEF parsed and raw data\n"
                  "hf mfp ndefread -f myfilename                                  -> save raw NDEF to file\n"
                  "hf mfp ndefread --aid e103 -k d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7 -> shows NDEF data with custom AID and key\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_litn("v",  "详细",  0, 2, "详细输出"),
        arg_str0(NULL, "aid",      "<aid>", "replace default aid for NDEF"),
        arg_str0("k",  "key",      "<key>", "替换NDEF的默认密钥"),
        arg_lit0("b",  "keyb",     "使用密钥B访问扇区（默认：密钥A）"),
        arg_str0("f",  "file", "<fn>", "保存原始NDEF到文件"),
        arg_lit0(NULL, "override", "override failed crc check"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool verbose2 = arg_get_lit(ctx, 1) > 1;
    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);
    uint8_t key[16] = {0};
    int keylen;
    CLIGetHexWithReturn(ctx, 3, key, &keylen);
    bool keyB = arg_get_lit(ctx, 4);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool override = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    uint16_t ndefAID = 0xe103;
    if (aidlen == 2)
        ndefAID = (aid[0] << 8) + aid[1];

    uint8_t ndefkey[16] = {0};
    memcpy(ndefkey, g_mifarep_ndef_key, 16);
    if (keylen == 16) {
        memcpy(ndefkey, key, 16);
    }

    uint8_t sector0[MIFARE_1K_MAXBLOCK] = {0};
    uint8_t sector16[MIFARE_1K_MAXBLOCK] = {0};
    uint8_t data[MIFARE_4K_MAX_BYTES] = {0};
    int datalen = 0;

    if (verbose)
        PrintAndLogEx(INFO, "正在读取 MAD v1 扇区");

    if (mfpReadSector(MF_MAD1_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector0, verbose)) {
        PrintAndLogEx(ERR, "错误，读取扇区 0。卡片没有 MAD 或默认密钥上没有 MAD");
        PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`hf mfp ndefread -k `") " with your custom key");
        return PM3_ESOFT;
    }

    bool haveMAD2 = false;
    int res = MADCheck(sector0, NULL, verbose, &haveMAD2);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "MAD错误 %d", res);
        if (override)
            PrintAndLogEx(INFO, "覆盖CRC检查");
        else
            return res;
    }

    if (haveMAD2) {

        if (verbose)
            PrintAndLogEx(INFO, "正在读取 MAD v2 扇区");

        if (mfpReadSector(MF_MAD2_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector16, verbose)) {
            PrintAndLogEx(ERR, "错误，读取扇区 0x10。卡片没有 MAD 或默认密钥上没有 MAD");
            PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`hf mfp ndefread -k `") " with your custom key");
            return PM3_ESOFT;
        }
    }

    uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
    size_t madlen = 0;
    res = MADDecode(sector0, (haveMAD2 ? sector16 : NULL), mad, &madlen, false, override);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "无法解码 MAD");
        return res;
    }

    PrintAndLogEx(INFO, "从标签读取数据");
    for (int i = 0; i < madlen; i++) {
        if (ndefAID == mad[i]) {
            uint8_t vsector[MIFARE_1K_MAXBLOCK] = {0};
            if (mfpReadSector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, ndefkey, vsector, false)) {
                PrintAndLogEx(ERR, "错误，正在读取扇区 %d", i + 1);
                return PM3_ESOFT;
            }

            memcpy(&data[datalen], vsector, 16 * 3);
            datalen += 16 * 3;

            PrintAndLogEx(INPLACE, "%d", i);
        }
    }
    PrintAndLogEx(NORMAL, "");

    if (datalen == 0) {
        PrintAndLogEx(ERR, "无 NDEF 数据");
        return PM3_SUCCESS;
    }

    if (verbose2) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("MF Plus NDEF raw") " ----------------");
        print_buffer(data, datalen, 1);
    }

    res = NDEFDecodeAndPrint(data, datalen, verbose);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(INFO, "尝试解析无NDEF头的NDEF记录");
        res = NDEFRecordsDecodeAndPrint(data, datalen, verbose);
    }

    // get total NDEF length before save. If fails, we save it all
    size_t n = 0;
    if (NDEFGetTotalLength(data, datalen, &n) != PM3_SUCCESS)
        n = datalen;

    pm3_save_dump(filename, data, n, jsfNDEF);

    if (verbose == false) {
        PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`hf mfp ndefread -v`") " for more details");
    } else {
        if (verbose2 == false) {
            PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`hf mfp ndefread -vv`") " for more details");
        }
    }
    return PM3_SUCCESS;
}

static int CmdHFMFPNDEFWrite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfp NDEF 写入",
                  "将原始NDEF十六进制字节写入标签。此命令假设标签已进行NFC/NDEF格式化。\\n",
                  "hf mfp ndefwrite -d 0300FE      -> write empty record to tag\n"
                  "hf mfp ndefwrite -f myfilename\n"
                  "hf mfp ndefwrite -d 033fd1023a53709101195405656e2d55534963656d616e2054776974746572206c696e6b5101195502747769747465722e636f6d2f686572726d616e6e31303031\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", NULL, "<hex>", "raw NDEF hex bytes"),
        arg_str0("f", "file", "<fn>", "将原始NDEF文件写入标签"),
        arg_lit0("p", NULL, "fix NDEF record headers / terminator block if missing"),
        arg_lit0("v", "详细", "详细输出"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t raw[4096] = {0};
    int rawlen;
    CLIGetHexWithReturn(ctx, 1, raw, &rawlen);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool fix_msg = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (fix_msg) {
        PrintAndLogEx(NORMAL, "调用时带有固定 NDEF 消息参数");
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, "");
    }
    PrintAndLogEx(SUCCESS, "尚未实现。欢迎贡献代码！");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFMFPList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf mfp", "mfp -c");
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,                 AlwaysAvailable, "此帮助"},
    {"list",        CmdHFMFPList,            AlwaysAvailable, "列出 MIFARE Plus 历史"},
    {"-----------", CmdHelp,                 IfPm3Iso14443a,  "------------------- " _CYAN_("operations") " ---------------------"},
    {"acl",         CmdHFMFPAcl,             AlwaysAvailable, "解码Mifare Plus的ACL值"},
    {"auth",        CmdHFMFPAuth,            IfPm3Iso14443a,  "认证"},
    {"chk",         CmdHFMFPChk,             IfPm3Iso14443a,  "检查密钥"},
    {"dump",        CmdHFMFPDump,            IfPm3Iso14443a,  "将MIFARE Plus标签转储到文件"},
    {"info",        CmdHFMFPInfo,            IfPm3Iso14443a,  "标签信息"},
    {"mad",         CmdHFMFPMAD,             IfPm3Iso14443a,  "检查并打印MAD"},
    {"rdbl",        CmdHFMFPRdbl,            IfPm3Iso14443a,  "从卡片读取多个块"},
    {"rdsc",        CmdHFMFPRdsc,            IfPm3Iso14443a,  "从卡片读取多个扇区"},
    {"wrbl",        CmdHFMFPWrbl,            IfPm3Iso14443a,  "将块写入卡片"},
    {"chkey",       CmdHFMFPChKey,           IfPm3Iso14443a,  "更改卡上的密钥"},
    {"chconf",      CmdHFMFPChConf,          IfPm3Iso14443a,  "更改卡片配置"},
    {"-----------", CmdHelp,                 IfPm3Iso14443a,  "---------------- " _CYAN_("personalization") " -------------------"},
    {"commitp",     CmdHFMFPCommitPerso,     IfPm3Iso14443a,  "配置安全层（SL1/SL3模式）"},
    {"initp",       CmdHFMFPInitPerso,       IfPm3Iso14443a,  "在SL0模式下填充卡片所有密钥"},
    {"wrp",         CmdHFMFPWritePerso,      IfPm3Iso14443a,  "写入个性化命令"},
    {"-----------", CmdHelp,                 IfPm3Iso14443a,  "---------------------- " _CYAN_("ndef") " ------------------------"},
    {"ndefformat",  CmdHFMFPNDEFFormat,      IfPm3Iso14443a,  "将MIFARE Plus标签格式化为NFC标签"},
    {"ndefread",    CmdHFMFPNDEFRead,        IfPm3Iso14443a,  "读取并打印卡片中的NDEF记录"},
    {"ndefwrite",   CmdHFMFPNDEFWrite,       IfPm3Iso14443a,  "将NDEF记录写入卡片"},
    {NULL, NULL, 0, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFMFP(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
