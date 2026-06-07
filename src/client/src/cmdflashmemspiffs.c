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
// Proxmark3 RDV40 Flash memory commands
//-----------------------------------------------------------------------------
#include "cmdflashmemspiffs.h"
#include "cmdtrace.h"
#include <ctype.h>
#include "cmdparser.h"  // command_t
#include "pmflash.h"
#include "fileutils.h"  //saveFile
#include "comms.h"      //getfromdevice
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

int flashmem_spiffs_load(const char *destfn, const uint8_t *data, size_t datalen) {

    int ret_val = PM3_SUCCESS;

    // We want to mount before multiple operation so the lazy writes/append will not
    // trigger a mount + umount each loop iteration (lazy ops device side)
    SendCommandNG(CMD_SPIFFS_MOUNT, NULL, 0);

    // Send to device
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = datalen;

    // fast push mode
    g_conn.block_after_ACK = true;

    while (bytes_remaining > 0) {

        uint32_t bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);

        flashmem_write_t *payload = calloc(1, sizeof(flashmem_write_t) + bytes_in_packet);
        if (payload == NULL) {
            PrintAndLogEx(WARNING, "分配内存失败");
            ret_val = PM3_EMALLOC;
            goto out;
        }

        payload->append = (bytes_sent > 0);

        uint8_t fnlen = MIN(sizeof(payload->fn), strlen(destfn));

        payload->fnlen = fnlen;
        memcpy(payload->fn, destfn, fnlen);

        payload->bytes_in_packet = bytes_in_packet;
        memset(payload->data, 0, bytes_in_packet);
        memcpy(payload->data, data + bytes_sent, bytes_in_packet);

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_SPIFFS_WRITE, (uint8_t *)payload, sizeof(flashmem_write_t) + bytes_in_packet);

        free(payload);

        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;

        uint8_t retry = 3;
        while (WaitForResponseTimeout(CMD_SPIFFS_WRITE, &resp, 2000) == false) {
            PrintAndLogEx(WARNING, "等待回复超时");
            retry--;
            if (retry == 0) {
                ret_val = PM3_ETIMEOUT;
                goto out;
            }
        }
    }

out:
    clearCommandBuffer();

    // turn off fast push mode
    g_conn.block_after_ACK = false;

    // We want to unmount after these to set things back to normal but more than this
    // unmouting ensure that SPIFFS CACHES are all flushed so our file is actually written on memory
    SendCommandNG(CMD_SPIFFS_UNMOUNT, NULL, 0);
    return ret_val;
}

int flashmem_spiffs_download(char *fn, uint8_t fnlen, void **pdest, size_t *destlen) {
    // get size from spiffs itself !
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_STAT, (uint8_t *)fn, fnlen);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SPIFFS_STAT, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "等待回复超时");
        return PM3_ETIMEOUT;
    }

    uint32_t len = resp.data.asDwords[0];
    if (len == 0) {
        PrintAndLogEx(ERR, "错误，无法获取 SPIFFSS 上的文件状态");
        return PM3_EFAILED;
    }

    *pdest = calloc(len, sizeof(uint8_t));
    if (*pdest == false) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    uint32_t start_index = 0;
    PrintAndLogEx(INFO, "downloading "_YELLOW_("%u") " bytes from `" _YELLOW_("%s") "` (spiffs)", len, fn);

    if (GetFromDevice(SPIFFS, *pdest, len, start_index, (uint8_t *)fn, fnlen, NULL, -1, true) == 0) {
        PrintAndLogEx(FAILED, "错误，从spiffs下载");
        free(*pdest);
        return PM3_EFLASH;
    }

    *destlen = len;
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSMount(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS挂载",
                  "挂载SPIFFS文件系统（如果尚未挂载）",
                  "SPIFFS挂载");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_MOUNT, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSUnmount(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS卸载",
                  "卸载SPIFFS文件系统",
                  "SPIFFS卸载");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_UNMOUNT, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS测试",
                  "测试 SPIFFS 操作，需要擦除页面 0 和 1",
                  "SPIFFS测试");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_TEST, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSCheck(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS检查",
                  "检查/尝试整理损坏/碎片化的SPIFFS文件系统",
                  "SPIFFS检查");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_CHECK, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSTree(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS树",
                  "打印闪存文件系统树",
                  "SPIFFS树");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "--- " _CYAN_("Flash Memory tree (SPIFFS)") " -----------------");
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_PRINT_TREE, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS信息",
                  "打印文件系统信息和使用统计",
                  "SPIFFS信息");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "--- " _CYAN_("Flash Memory info (SPIFFS)") " -----------------");
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_PRINT_FSINFO, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSRemove(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS删除",
                  "从SPIFFS文件系统中删除文件",
                  "mem spiffs remove -f lasttag.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "要删除的文件"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, 32, &fnlen);
    CLIParserFree(ctx);

    PrintAndLogEx(DEBUG, "正在移除 `" _YELLOW_("%s") "`", filename);
    struct {
        uint8_t len;
        uint8_t fn[32];
    } PACKED payload;
    payload.len = fnlen;
    memcpy(payload.fn, filename, fnlen);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_REMOVE, (uint8_t *)&payload, sizeof(payload));
    WaitForResponse(CMD_SPIFFS_REMOVE, &resp);
    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "完成！");
    }
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSRename(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS重命名",
                  "重命名/移动SPIFFS文件系统中的文件。",
                  "mem spiffs rename -s aaa.bin -d bbb.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("s", "src", "<fn>", "源文件名"),
        arg_str1("d", "dest", "<fn>", "目标文件名"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int slen = 0;
    char src[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)src, 32, &slen);

    int dlen = 0;
    char dest[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)dest, 32, &dlen);
    CLIParserFree(ctx);

    PrintAndLogEx(DEBUG, "重命名自 `" _YELLOW_("%s") "` -> `" _YELLOW_("%s") "`", src, dest);

    struct {
        uint8_t slen;
        uint8_t src[32];
        uint8_t dlen;
        uint8_t dest[32];
    } PACKED payload;
    payload.slen = slen;
    payload.dlen = dlen;

    memcpy(payload.src, src, slen);
    memcpy(payload.dest, dest, dlen);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_RENAME, (uint8_t *)&payload, sizeof(payload));
    WaitForResponse(CMD_SPIFFS_RENAME, &resp);
    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "完成！");
    }

    PrintAndLogEx(HINT, "提示：尝试 `" _YELLOW_("SPIFFS树") "` to verify");
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSCopy(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS复制",
                  "在SPIFFS文件系统中复制文件到另一个（破坏性）",
                  "mem spiffs copy -s aaa.bin -d aaa_cpy.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("s", "src", "<fn>", "源文件名"),
        arg_str1("d", "dest", "<fn>", "目标文件名"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int slen = 0;
    char src[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)src, 32, &slen);

    int dlen = 0;
    char dest[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)dest, 32, &dlen);
    CLIParserFree(ctx);

    struct {
        uint8_t slen;
        uint8_t src[32];
        uint8_t dlen;
        uint8_t dest[32];
    } PACKED payload;
    payload.slen = slen;
    payload.dlen = dlen;

    memcpy(payload.src, src, slen);
    memcpy(payload.dest, dest, dlen);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_COPY, (uint8_t *)&payload, sizeof(payload));
    WaitForResponse(CMD_SPIFFS_COPY, &resp);
    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "完成！");
    }

    PrintAndLogEx(HINT, "提示：尝试 `" _YELLOW_("SPIFFS树") "` to verify");
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS转储",
                  "将设备 SPIFFS 文件转储到本地文件\\n"
                  "Size is handled by first sending a STAT command against file to verify existence",
                  "mem spiffs dump -s tag.bin           --> download binary file from device, saved as `tag.bin`\n"
                  "mem spiffs dump -s tag.bin -d a001   --> download tag.bin, save as `a001.bin`\n"
                  "mem spiffs dump -s tag.bin -t        --> download tag.bin into trace buffer"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("s", "src", "<fn>", "要保存的 SPIFFS 文件"),
        arg_str0("d", "dest", "<fn>", "保存到的文件名（不含.bin）"),
        arg_lit0("t", "trace", "下载到跟踪缓冲区"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int slen = 0;
    char src[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)src, 32, &slen);

    int dlen = 0;
    char dest[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)dest, FILE_PATH_SIZE, &dlen);

    bool to_trace = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    // get size from spiffs itself !
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_STAT, (uint8_t *)src, slen);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SPIFFS_STAT, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "等待回复超时");
        return PM3_ETIMEOUT;
    }

    uint32_t len = resp.data.asDwords[0];
    uint8_t *dump = calloc(len, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "分配内存失败");
        return PM3_EMALLOC;
    }

    // download from device
    uint32_t start_index = 0;
    PrintAndLogEx(INFO, "downloading "_YELLOW_("%u") " bytes from `" _YELLOW_("%s") "` (spiffs)", len, src);
    if (GetFromDevice(SPIFFS, dump, len, start_index, (uint8_t *)src, slen, NULL, -1, true) == false) {
        PrintAndLogEx(FAILED, "错误，从spiffs下载");
        free(dump);
        return PM3_EFLASH;
    }

    if (to_trace) {
        // copy to client trace buffer
        if (ImportTraceBuffer(dump, len) == false) {
            PrintAndLogEx(FAILED, "错误，复制到跟踪缓冲区");
            free(dump);
            return PM3_EMALLOC;
        }
        PrintAndLogEx(HINT, "提示：使用 'trace list -1 -t ...' 查看，'trace save -f ...' 保存");
    }


    if (dlen || slen) {

        // save to file
        char fn[FILE_PATH_SIZE] = {0};

        // prefer dest name
        // else source name
        if (dlen) {
            strncpy(fn, dest, dlen);
        } else {
            strncpy(fn, src, slen);
        }

        // set file extension
        const char *suffix = strchr(fn, '.');
        if (suffix) {
            saveFile(fn, suffix, dump, len);
        } else {
            saveFile(fn, ".bin", dump, len);
        }
    }
    free(dump);
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSWipe(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mem spiffs wipe",
                  _RED_("* * *  Warning  * * *") " \n"
                  _CYAN_("This command wipes all files on the device SPIFFS file system"),
           "mem spiffs wipe");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "正在擦除 SPIFFS 文件系统中的所有文件");
    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_SPIFFS_WIPE, NULL, 0);
    WaitForResponse(CMD_SPIFFS_WIPE, &resp);
    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "完成！");
    }

    PrintAndLogEx(HINT, "提示：尝试 `" _YELLOW_("SPIFFS树") "` to verify");
    return PM3_SUCCESS;
}

static int CmdFlashMemSpiFFSUpload(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS上传",
                  "以二进制方式上传文件到设备文件系统\\n"
                  "Warning: mem area to be written must have been wiped first.\n"
                  "This is already taken care when loading dictionaries.\n"
                  "File names can only be 32 bytes long on device SPIFFS",
                  "mem spiffs upload -s local.bin -d dest.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("s", "src", "<fn>", "源文件名"),
        arg_str1("d", "dest", "<fn>", "目标文件名"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int slen = 0;
    char src[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)src, FILE_PATH_SIZE, &slen);

    int dlen = 0;
    char dest[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)dest, 32, &dlen);
    CLIParserFree(ctx);

    PrintAndLogEx(DEBUG, "上传 `" _YELLOW_("%s") "` -> `" _YELLOW_("%s") "`", src, dest);

    size_t datalen = 0;
    uint8_t *data = NULL;

    int res = loadFile_safe(src, "", (void **)&data, &datalen);
    if (res != PM3_SUCCESS) {
        free(data);
        return PM3_EFILE;
    }

    res = flashmem_spiffs_load(dest, data, datalen);
    free(data);

    if (res == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Wrote "_GREEN_("%zu") " bytes to file "_GREEN_("%s"), datalen, dest);

    PrintAndLogEx(HINT, "提示：尝试 `" _YELLOW_("SPIFFS树") "` to verify");
    return res;
}

static int CmdFlashMemSpiFFSView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "SPIFFS查看",
                  "在控制台中查看设备闪存上的文件",
                  "mem spiffs view -f tag.bin"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "要查看的 SPIFFS 文件"),
        arg_int0("c", "cols", "<dec>", "列分隔（默认16）"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char fn[32] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)fn, 32, &fnlen);

    int breaks = arg_get_int_def(ctx, 2, 16);
    CLIParserFree(ctx);

    uint8_t *dump = NULL;
    size_t dumplen = 0;
    int res = flashmem_spiffs_download(fn, fnlen, (void **)&dump, &dumplen);
    if (res != PM3_SUCCESS) {
        return res;
    }

    PrintAndLogEx(NORMAL, "");
    print_hex_break(dump, dumplen, breaks);
    PrintAndLogEx(NORMAL, "");
    free(dump);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,                  AlwaysAvailable, "此帮助"},
    {"-----------", CmdHelp,                  IfPm3Flash,      "------------------- " _CYAN_("操作") " -------------------"},
    {"copy",    CmdFlashMemSpiFFSCopy,    IfPm3Flash, "在SPIFFS文件系统中复制文件到另一个（破坏性）"},
    {"check",   CmdFlashMemSpiFFSCheck,   IfPm3Flash, "检查/尝试整理损坏/碎片化的文件系统"},
    {"dump",    CmdFlashMemSpiFFSDump,    IfPm3Flash, "从SPIFFS文件系统转储文件"},
    {"info",        CmdFlashMemSpiFFSInfo,    IfPm3Flash,      "文件系统信息和使用统计"},
    {"mount",   CmdFlashMemSpiFFSMount,   IfPm3Flash, "挂载SPIFFS文件系统（如果尚未挂载）"},
    {"remove",  CmdFlashMemSpiFFSRemove,  IfPm3Flash, "从SPIFFS文件系统中删除文件"},
    {"rename",  CmdFlashMemSpiFFSRename,  IfPm3Flash, "在SPIFFS文件系统中重命名/移动文件"},
    {"test",    CmdFlashMemSpiFFSTest,    IfPm3Flash, "测试 SPIFFS 操作"},
    {"tree",    CmdFlashMemSpiFFSTree,    IfPm3Flash, "打印闪存文件系统树"},
    {"unmount", CmdFlashMemSpiFFSUnmount, IfPm3Flash, "卸载SPIFFS文件系统"},
    {"upload",  CmdFlashMemSpiFFSUpload,  IfPm3Flash, "上传文件到SPIFFS文件系统"},
    {"view",    CmdFlashMemSpiFFSView,    IfPm3Flash, "查看SPIFFS文件系统上的文件"},
    {"wipe",    CmdFlashMemSpiFFSWipe,    IfPm3Flash, "Wipe all files from SPIFFS file system   * " _RED_("dangerous") " *" },
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdFlashMemSpiFFS(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
