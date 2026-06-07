# GitHub Release 发布指南

## 1. 创建 GitHub 仓库

```bash
# 方式 A: 用 gh CLI
gh repo create proxmark3-fullcn --public -d "Proxmark3 全中文版客户端 v4.21611"

# 方式 B: 手动在 https://github.com/new 创建
# 仓库名: proxmark3-fullcn
# 描述: Proxmark3 全中文版客户端 — 基于 Iceman v4.21611
```

## 2. 推送代码

```powershell
cd C:\Users\Samso\OneDrive\Desktop\Projects\promark3\proxmark3-fullcn-4.21611-v01

git init
git remote add origin git@github.com:Samsongzhilin/proxmark3-fullcn.git

# 添加 .gitignore (排除大文件/编译产物)
@"
*.o
*.d
*.elf
*.bin
*.zip
build/
"@ | Out-File -LiteralPath .gitignore -Encoding utf8

git add -A
git commit -m "v01: Proxmark3 全中文版客户端 v4.21611

- 10,527 条翻译覆盖全部命令描述/参数说明/运行时消息
- DeepSeek API 翻译管线 (extract → translate → apply → build)
- 硬件调校 (hw tune) 输出完整中文化
- 附完整中文教程 (10章+附录)
- Windows WSL2 启动脚本 (pm3.bat/pm3.ps1)"

git push -u origin main
```

## 3. 创建 Release

```bash
# gh CLI 创建 release
gh release create v01 \
  --title "Proxmark3 全中文版 v4.21611 v01" \
  --notes-file RELEASE_NOTES.md \
  ./client/proxmark3_cn2 \
  ./zh_trans_cn2.py \
  ./extract_all.py \
  ./apply_all.py \
  ./translate_async.py \
  ./pm3.bat \
  ./pm3.ps1 \
  ./Proxmark3-Complete-Tutorial.md
```

或手动操作:
1. 进入仓库 → Releases → Draft a new release
2. Tag: `v01`
3. Title: `Proxmark3 全中文版 v4.21611 v01`
4. 粘贴下方 Release Notes
5. 上传附件: `client/proxmark3_cn2`, `zh_trans_cn2.py`, 等

## 4. Release Notes 模板

```markdown
# Proxmark3 全中文版客户端 v4.21611 v01

基于 [Iceman/RfidResearchGroup proxmark3 v4.21611](https://github.com/RfidResearchGroup/proxmark3) 的全中文定制版客户端。

## 翻译覆盖

| 类别 | 数量 |
|------|------|
| 命令描述 (command_t) | 818 |
| CLIParserInit 提示 | 797 |
| arg_* 参数帮助 | 686 |
| PrintAndLogEx 运行时消息 | 7,420 |
| snprintf 动态字符串 | 102 |
| **总计** | **10,527** |

## 安装

1. 解压所有文件到 Proxmark3 项目目录
2. 将 `proxmark3_cn2` 放到 `client/` 子目录
3. 将 `zh_trans_cn2.py` 放到项目根目录
4. 将 `pm3.bat` / `pm3.ps1` 放到任意 PATH 目录

## 使用

```powershell
pm3 -cn2                       # 交互模式
pm3 -cn2 -c "hw version"       # 单条命令
pm3 -cn2 -c "hf mf help"       # MIFARE 命令帮助
```

## 截图

```
[usb] pm3 --> hw version

Proxmark3 RFID 检测器
-----------------------------
 客户端....... Iceman/master/v4.21611
 型号....... PM3GENERIC
 硬件....... PM3EASY
 uC......... AT91SAM7S512 Rev A
 启动闪存.... Iceman/master/v4.21611
 闪存....... 512 kB (73% 已用)
```

## 重新编译

```bash
python3 apply_all.py ~/pm3_cn2/client/src/ zh_trans_cn2.py build
```

## 文件列表

| 文件 | 大小 | 说明 |
|------|------|------|
| `client/proxmark3_cn2` | 5.9 MB | 中文客户端二进制 |
| `zh_trans_cn2.py` | 754 KB | 翻译字典 |
| `extract_all.py` | 6.8 KB | 字符串提取脚本 |
| `apply_all.py` | 6.5 KB | 翻译应用+编译脚本 |
| `translate_async.py` | 5.3 KB | DeepSeek API 翻译脚本 |
| `pm3.bat` | 60 B | Windows 启动封装 |
| `pm3.ps1` | 1 KB | PowerShell 启动脚本 |
| `Proxmark3-Complete-Tutorial.md` | 39 KB | 完整中文教程 |
| `README.md` | — | 使用说明 |
| `LICENSE.txt` | 35 KB | GPLv3 |

## 已知限制

- 固件 (ARM) 端字符串暂未翻译（`ChkKeys_fast: Can't select card` 等）
- `_CYAN_()` 短标签可能被过滤（极少数）
- 需 WSL2 环境运行

## 致谢

- [Iceman](https://github.com/RfidResearchGroup/proxmark3) — 固件/客户端
- DeepSeek API — 批量翻译引擎
- Sam (宋志林) — 翻译编译 & 教程
```

## 5. 发布检查清单

- [ ] GitHub 仓库已创建
- [ ] 所有文件已推送 (含 LICENSE)
- [ ] Tag v01 已打
- [ ] Release binary 已上传 (`proxmark3_cn2`)
- [ ] Release Notes 已填写
- [ ] 教程文件可独立下载
- [ ] 翻译字典 (`zh_trans_cn2.py`) 已作为 artifact 上传

## 6. 可选: 打包为 zip

```powershell
Compress-Archive -LiteralPath "C:\Users\Samso\OneDrive\Desktop\Projects\promark3\proxmark3-fullcn-4.21611-v01\*" -DestinationPath "C:\Users\Samso\OneDrive\Desktop\Projects\promark3\proxmark3-fullcn-4.21611-v01.zip" -Force
```

然后上传 zip 到 GitHub Release 作为额外下载选项。
