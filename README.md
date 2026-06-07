# Proxmark3 全中文版 v4.21611

基于 [RfidResearchGroup/proxmark3](https://github.com/RfidResearchGroup/proxmark3) v4.21611 (Iceman) 的全中文定制版客户端。

覆盖命令描述、参数说明、运行时消息、报错信息等全部用户可见字符串。自带完整源码 + 一键安装脚本，开箱即用。

## 特性

- 全部 `command_t` 描述已翻译（MIFARE / LF / HF / 硬件等）
- `PrintAndLogEx` 运行时消息全部中文化
- `_CYAN_()` 章节标题已翻译（操作 / 硬件 / 模拟 / 恢复）
- `hw tune` 输出完全中文化
- 专业名词保留英文：ATR / UID / NTAG / DESFire / T55xx
- `src/` 包含已应用翻译的完整 Proxmark3 源码树 (2030+ 文件)
- Windows / Linux 一键安装脚本

## 快速开始

**前置条件**：WSL2 (Ubuntu) + usbipd-win（Windows 用户）

### Windows

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File Windowsinstaller\install.ps1
pm3                           # 交互模式
pm3 -c "hw version"           # 单条命令
```

### Linux

```bash
bash Linuxinstaller/install.sh
pm3                           # 交互模式
pm3 -c "hw version"           # 单条命令
```

### 驱动安装

Windows 插上 PM3 通常自动识别。如未识别，参考 [driver/DRIVER_GUIDE.md](driver/DRIVER_GUIDE.md)。Linux 安装脚本会自动处理 udev 规则。

## 文件结构

| 文件/目录 | 说明 |
|-----------|------|
| `src/` | 完整源码树（已应用中文翻译） |
| `client/proxmark3_cn2` | 预编译中文二进制 (5.9 MB) |
| `driver/` | 驱动文件 + 安装指南 |
| `Windowsinstaller/install.ps1` | Windows 一键安装 |
| `Linuxinstaller/install.sh` | Linux 一键安装 |
| `pm3.bat` / `pm3.ps1` | Windows 启动封装 |
| `zh_trans_cn2.py` | 翻译字典 (10,527 条) |
| `extract_all.py` | 字符串提取脚本 |
| `apply_all.py` | 翻译应用 + 编译脚本 |
| `translate_async.py` | API 批量翻译脚本 |
| `Proxmark3-Complete-Tutorial.md` | 完整中文教程 |

## 重新编译

```bash
cd ~/pm3_cn2
make -j$(nproc) client
```

## 修改翻译

```bash
export OPENAI_API_KEY="your-key"
export OPENAI_API_BASE="https://api.deepseek.com"

python3 extract_all.py ~/pm3_cn2/client/src/
python3 translate_async.py
python3 apply_all.py ~/pm3_cn2/client/src/ zh_trans_cn2.py build
```

## 翻译统计

| 指标 | 数量 |
|------|------|
| 翻译字典条目 | 10,527 |
| 源码替换 | 11,562 |
| 覆盖源文件 | 153 |
| 完整源码文件 | 2,030 |
| 翻译引擎 | OpenAI 兼容 API (DeepSeek / Qwen / GLM 等) |

## 环境变量

| 变量 | 说明 |
|------|------|
| `QT_QPA_PLATFORM=offscreen` | 无头运行 |
| `QT_LOGGING_RULES='*=false'` | 屏蔽 Qt 警告 |
| `OPENAI_API_KEY` | API 翻译密钥（可选） |
| `OPENAI_API_BASE` | API 端点（可选） |

## 上游同步

跟随 [RfidResearchGroup/proxmark3](https://github.com/RfidResearchGroup/proxmark3) 官方更新。新版本发布后：

```bash
git remote add upstream https://github.com/RfidResearchGroup/proxmark3.git
git fetch upstream
git merge upstream/master
python3 apply_all.py src/client/src/ zh_trans_cn2.py build
```

## 联系

- **Bilibili**: [一摩尔的锂](https://space.bilibili.com/1532965701)（可私信）
- **GitHub Issues**: 本仓库提交问题 / 建议

## 协议

GPLv3 · [RfidResearchGroup/proxmark3](https://github.com/RfidResearchGroup/proxmark3) v4.21611
