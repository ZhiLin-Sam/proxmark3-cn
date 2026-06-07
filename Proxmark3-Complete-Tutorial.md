# Proxmark3 完全教程 — 从入门到精通

> **适用固件**: Iceman/master (v4.21611+)  
> **适用硬件**: Proxmark3 Easy / RDV4 / EVO  
> **客户端语言**: 中文（基于 pm3_cn 翻译版）  
> **最后更新**: 2026-06-07

---

## 目录

1. [缘起：为什么要学 RFID 安全](#ch0)
2. [硬件入门](#ch1)
3. [基础操作](#ch2)
4. [LF 低频 (125kHz) 实战](#ch3)
5. [MIFARE Classic — 核心篇](#ch4)
6. [NTAG / MIFARE Ultralight](#ch5)
7. [MIFARE DESFire 入门](#ch6)
8. [其他高频技术](#ch7)
9. [实战案例集](#ch8)
10. [进阶玩法](#ch9)
11. [附录](#chA)

---

<a name="ch0"></a>
## 第0章 · 缘起：为什么要学 RFID 安全

### 0.1 什么是 RFID

**RFID** (Radio Frequency Identification，射频识别) 是一种非接触式无线通信技术，通过电磁场传输数据。你每天都会接触：

| 频率 | 常见卡片 | 典型场景 |
|------|----------|----------|
| **125 kHz** (低频/LF) | EM4305, T5577, HID Prox | 小区门禁、公司考勤 |
| **13.56 MHz** (高频/HF) | MIFARE Classic, DESFire, NTAG | 公交卡、酒店房卡、银行卡、身份证 |

### 0.2 为什么要学

1. **安全测试**: 85% 以上的旧门禁系统使用未加密或弱加密的 MIFARE Classic，克隆一张门禁卡只需 3 秒
2. **渗透测试**: RFID 是物理安全的关键环节，懂 RFID 才能做完整的红队评估
3. **硬件黑客**: PM3 是性价比最高的 RFID 安全研究平台，一块板子搞定所有常见卡片

### 0.3 你能学到什么

- 识别、读取、克隆市面上 90% 的门禁卡和考勤卡
- 破解 MIFARE Classic 密钥（darkside / nested / hardnested）
- 读取银行卡 EMV 数据（非交易）
- 读写 T55x7 / EM4305 可编程卡片
- 理解 DESFire、Ultralight、iCLASS 等新一代卡片的安全模型
- 用 Python 脚本扩展 PM3 功能

### 0.4 参考资料

| 来源 | 说明 |
|------|------|
| [Iceman GitHub](https://github.com/RfidResearchGroup/proxmark3) | 官方固件和客户端源码 |
| [Iceman Wiki](https://github.com/RfidResearchGroup/proxmark3/wiki) | 官方文档（英文） |
| [Proxmark Forum](http://www.proxmark.org/forum/) | 官方论坛 |
| 吾爱破解 RFID 版 | 中文实战案例 |
| 看雪安全论坛 RFID 版 | 技术分析文章 |
| [Reversing.ID](https://www.rfid-reversing.com/) | RFID 逆向笔记（印尼） |
| [Dangerous Things Forum](https://forum.dangerousthings.com/) | 植入物社区 |
| `hf mf help` / `lf help` | **最好的文档就在命令行里** |

---

<a name="ch1"></a>
## 第1章 · 硬件入门

### 1.1 PM3 版本对比

| 特性 | **PM3 Easy** | **PM3 RDV4** | **PM3 EVO** |
|------|-------------|-------------|------------|
| 价格 | ¥150-300 | ¥500-800 | ¥200-400 |
| 闪存 | 256KB / **512KB** | 512KB / 2MB | 256KB |
| FPGA | Spartan II | Spartan II | Spartan II |
| SIM/SAM 槽 | ❌ | ✅ | ❌ |
| 外接天线 | ❌ | ✅ | ❌ |
| 电池 (standalone) | ❌ | ✅ (可选) | ❌ |
| 推荐 | **入门首选** | 专业研究 | 性价比替代 |

> **本教程基于 PM3 Easy 512KB 版本。** 9AC4 的 VID:PID 说明是 Iceman 固件。

### 1.2 天线

```
┌─────────────────────────────┐
│   Proxmark3 Easy 顶面       │
│                             │
│   ┌─────────────────────┐   │
│   │  低频线圈 (125kHz)   │  ← LF 卡放这里
│   │  [漆包线大圆环]       │
│   └─────────────────────┘   │
│         ┌─────────┐         │
│         │ HF 天线  │        ← HF 卡放这里 (13.56MHz)
│         │ [PCB 线圈]│
│         └─────────┘         │
└─────────────────────────────┘
```

**天线位置实测数据**（PM3 Easy，空载 20.74V）：

| 位置 | HF 电压 | 品质因数 Q | 可读 | 说明 |
|------|---------|-----------|------|------|
| 空载 | 20.74V | 6.0 | — | 基准值 |
| 位1 | 13.85V | 4.0 | ❌ | 耦合过度 |
| 位2 | 17.37V | 5.1 | ✅ | **最佳位置** |
| 位3 | 16.22V | 4.7 | ✅ | 可用 |
| 手持 | 15.85V | 4.6 | ✅ | 稍弱但可用 |

**经验**：MIFARE Classic 有效读取阈值约 15V；身份证和银行卡需要强信号，<16V 就难读了。卡放在天线正上方 1-3mm，不要用手压卡（人体吸收射频能量）。

### 1.3 固件刷写

#### 方案1：WSL2 + usbipd（推荐，本教程环境）

PM3 通过 USB 直通到 WSL2 Ubuntu 24.04，编译和刷新固件都在 Linux 下完成。

```powershell
# Windows 侧：绑定 PM3 到 WSL2
usbipd bind --force --busid 1-9
usbipd attach --wsl --busid 1-9
```

```bash
# WSL2 侧：编译
cd ~/pm3
make clean && make -j$(nproc)

# 刷写固件（按住 PM3 按键插 USB 进入 bootloader）
# 然后：
# Windows 侧重新 usbipd attach
# WSL2 侧：
cd ~/pm3/client
./proxmark3 /dev/ttyACM0 --flash --unlock-bootloader \
  --image ../bootrom/obj/bootrom.elf \
  --image ../armsrc/obj/fullimage.elf
```

#### 方案2：Windows 原生客户端

使用预编译的 Windows 客户端刷写：

```powershell
pm3.bat --flash --unlock-bootloader --image bootrom.elf --image fullimage.elf
```

**常见刷写问题**：
- 刷写中途 PM3 重启断电 → USB 直通断开 → 用 Windows 原生客户端刷
- `Wrong firmware for that hardware` → platform 配置错误，检查 `Makefile.platform`
- 刷完 LED 不亮 → 正常，部分 Easy 版本 LED 顺序不同

### 1.4 本教程一键启动

```powershell
# 中文版（推荐）
pm3 -cn

# 英文原版
pm3
```

---

<a name="ch2"></a>
## 第2章 · 基础操作

### 2.1 连接诊断

```bash
# 版本信息（客户端 + 固件 + FPGA）
hw version

# 运行状态
hw status

# 连通性测试
hw ping

# 天线调谐测试（放卡前后都跑一次）
hw tune
```

**hw status 正常输出示例**：
```
#lf sampling:   on
#LF signal:     OK
#Antenna:       20.74 V @ 13.56 MHz
#Antenna tuning: OK
#USB Speed:      USB Full speed
#Smartcard slot: absent (or present)
```

### 2.2 命令体系

所有命令采用 `前缀 子命令 [选项]` 结构：

```
hf mf chk --1k -f keys.dic       # 检查 MIFARE Classic 密钥
lf em read                        # 读取 EM410x 卡号
hf 14a info                       # ISO 14443-A 卡片信息
```

**命令帮助**：任何命令加 `-h` 或 `help` 都能看到详细说明：

```bash
hf mf help     # 所有 MIFARE 命令
lf help        # 所有低频命令
hf help        # 所有高频命令
```

### 2.3 日志与会话

```bash
# 查看日志目录
ls ~/.proxmark3/logs/

# 实时查看最近日志
tail -f ~/.proxmark3/logs/log_*.txt
```

每次 PM3 启动都自动记录日志到 `~/.proxmark3/logs/`。

### 2.4 脚本模式

```bash
# 单命令
pm3 -c "hf search"

# 多命令
pm3 -c "hf 14a info" -c "hf mf chk"

# 脚本文件
pm3 -s myscript.lua
```

**Lua 脚本骨架**：
```lua
-- myscript.lua
local info = core.console('hf 14a info')
print('卡片信息: ' .. info)

local res, err = core.console('hf mf chk')
if err then print('错误: ' .. err) end
```

### 2.5 Python 脚本

PM3 内置 Python 支持：

```bash
pm3 -c "script run myscript.py"
```

```python
# 读取 UID 示例
import pm3
uid = pm3.console('hf 14a info')
print(f'UID: {uid}')
```

---

<a name="ch3"></a>
## 第3章 · LF 低频 (125kHz) 实战

### 3.1 低频卡片总览

| 类型 | 频率 | ID 长度 | 常见场景 | 可克隆 |
|------|------|---------|----------|--------|
| **EM410x** | 125kHz | 40-bit | 小区门禁、电梯卡 | ✅ (T5577) |
| **HID Prox** | 125kHz | 26-37 bit | 公司门禁、美国主流 | ✅ (T5577) |
| **T55x7** | 125kHz | 可编程 | 万能复制卡 | ✅ (可重写) |
| **EM4305** | 125kHz | 可编程 | 万能复制卡 | ✅ (可重写) |
| **Indala** | 125kHz | 26-224 bit | 高端门禁 | ⚠️ T55x7 |
| **Hitag 1/2/S** | 125kHz | — | 汽车防盗 | ⚠️ 部分支持 |
| **AWID** | 125kHz | 24-50 bit | 美式门禁 | ✅ (T5577) |

### 3.2 低频读取实战

#### 读 EM410x 门禁卡

```bash
# 把卡放在低频天线线圈上
lf search
```

输出示例：
```
[+] EM410x ID: 1A003BF2E1
[+] EM TAG ID: 1A003BF2E1
```

**ID 解析**：
- `1A` → 版本/客户 ID
- `003BF2E1` → 卡号（32-bit）
- 常见国内小区门禁：ID 卡/IC 扣，以 `00` 开头

#### 读 HID Prox 卡

```bash
lf hid read
```

输出示例：
```
[+] HID Prox TAG: 2004A3B2C1
[+] Format: H10301 (26-bit)
[+] FC: 18  CN: 12345
```

**H10301 格式解析**：
```
Bit:   0         1-8      9-24      25
      [Even Parity] [FC]  [CN]    [Odd Parity]
      偶校验位    设施码  卡号    奇校验位
```

- **FC** (Facility Code): 设施/公司代码，0-255
- **CN** (Card Number): 卡号，0-65535

### 3.3 低频克隆

#### 用 T5577 克隆 EM410x

```bash
# 1. 读原卡
lf search                 # 记录 ID: 1A003BF2E1

# 2. 放上空白 T5577 卡
lf t55xx wipe             # 擦除 T5577
lf em 410x_write --id 1A003BF2E1   # 写入

# 验证
lf search                 # 应显示相同 ID
```

#### 用 T5577 克隆 HID

```bash
# 1. 读原卡
lf hid read               # 记录格式和参数

# 2. 使用已知参数写入
lf hid clone --fc 18 --cn 12345

# 或直接复制原始数据
lf hid sim --fc 18 --cn 12345    # 先测试模拟
lf hid clone --fc 18 --cn 12345  # 确认无误后写入
```

### 3.4 T55x7 高级操作

```bash
# 查看 T55x7 配置
lf t55xx info

# 导出完整数据
lf t55xx dump

# 写入配置块
lf t55xx writeblock --block 0 --data 000880E0

# 测试所有块
lf t55xx detect
```

**T55x7 配置块 (Block 0)** 是控制卡行为的关键：
- Bit 0-14: 保留
- Bit 15-17: 调制方式
- Bit 18-20: 比特率
- Bit 21-23: 编码方式
- 修改配置块可以改变卡的行为（复制其他卡类型的关键）

### 3.5 Indala 门禁卡

```bash
lf indala read             # 读取 Indala 卡
lf indala clone            # 克隆到 T55x7
```

**特点**：Indala 使用 PSK 调制，ID 较长（26-224 bit），多见于高端商业门禁。

### 3.6 低频暴力破解

部分低频系统只校验固定 ID，可以尝试暴力枚举：

```bash
# 按格式枚举 HID H10301
script run lf_brute_hid.lua --fc 18 --start 1 --end 1000

# 模拟 EM410x
lf em 410x_sim --id 1A003BF2E1
```

---

> **本节小结**：低频卡安全性极低，多数只靠明文 ID 做认证。T55x7 是可编程万能卡，几乎能复制所有常见 125kHz 卡片。

---

<a name="ch4"></a>
## 第4章 · MIFARE Classic — 核心篇

> MIFARE Classic 是全球部署量最大的非接触式 IC 卡，也是安全研究最重要的目标。本章详细讲解从卡片结构到完整破解的全流程。

### 4.1 卡片结构

MIFARE Classic 1K (S50) 是最常见的版本：

```
┌─────────────────────────────────────────────────┐
│              MIFARE Classic 1K                   │
├──────────┬──────────┬────────────────────────────┤
│ 扇区 0   │ 块 0     │ UID + 制造商数据 (只读)     │
│          │ 块 1     │ 数据                       │
│          │ 块 2     │ 数据                       │
│          │ 块 3     │ Key A + 控制位 + Key B     │
├──────────┼──────────┼────────────────────────────┤
│ 扇区 1-15│ 块 0-2   │ 数据                       │
│ (各4块)  │ 块 3     │ Key A + 控制位 + Key B     │
└──────────┴──────────┴────────────────────────────┘
```

| 参数 | 1K (S50) | 4K (S70) | Mini |
|------|----------|----------|------|
| 扇区数 | 16 | 40 | 5 |
| 总容量 | 1024 字节 | 4096 字节 | 320 字节 |
| UID 长度 | 4 字节 | 4/7 字节 | 4 字节 |

**块 3 (扇区尾块) 结构**：

```
字节:  0  1  2  3  4  5   [6 7 8]    [9]       10 11 12 13 14 15
      [   Key A (6B)   ] [控制位] [备用字节] [   Key B (6B)   ]
```

**控制位 (Access Bits)** — 每个扇区 3 字节，控制 4 个块的读写权限：

| 数据块权限 | Key A | Key B | 典型用途 |
|-----------|-------|-------|---------|
| 000 | 可读写 | 可读写 | 自由读写 |
| 100 | 只读 | 只读 | 只读数据 |
| 110 | 读写 | 只读 | 余额递减 |
| 111 | 禁止 | 禁止 | 锁定 |

### 4.2 密钥体系

MIFARE Classic 使用 **CRYPTO-1** 流密码算法（2008 年已被攻破）。

每个扇区独立设置 Key A 和 Key B（各 6 字节 = 12 hex 字符）。

**常见默认密钥**：

| 密钥 | 说明 |
|------|------|
| `FFFFFFFFFFFF` | 出厂默认，最常见 |
| `000000000000` | 空白密钥 |
| `A0A1A2A3A4A5` | NXP 公开示例密钥 |
| `B0B1B2B3B4B5` | NXP 公开示例密钥 |
| `4D3A99C351DD` | 公共交通常见 |
| `1A982C7E459A` | 部分酒店系统 |
| `D3F7D3F7D3F7` | MIFARE Classic EV1 |
| `AABBCCDDEEFF` | 部分厂商默认 |

### 4.3 认证流程

```
Reader (PM3)                          Card
    │                                   │
    │─── AUTH(block, key_type) ────────>│
    │<── nonce_nt (4 bytes) ────────────│
    │─── nonce_nr + answer_ar ─────────>│
    │<── answer_at ─────────────────────│
    │                                   │
    │  认证成功 → 读写 block            │
```

CRYPTO-1 被攻破的关键在于 **随机数生成器的弱点**：
- 卡片上电后产生的第一个随机数 `nt` 有 8-bit 熵缺陷
- 这构成了 **Nested 攻击** 的基础

### 4.4 攻击前先收集信息

```bash
# 检查是否是 MIFARE Classic
hf search

# 看卡片详细信息
hf 14a info

# 检查已知密钥
hf mf chk
```

`hf 14a info` 输出示例：
```
[+] UID: 83 E1 40 6B
[+] ATQA: 00 04
[+] SAK: 08 [MIFARE Classic 1K]
[+] ATS: none (MIFARE Classic doesn't support ATS)
[+] Manufacturer: Fudan Microelectronics (FM11RF08)
```

> **国产芯片识别**：上海复旦微电子的 FM11RF08 是最常见的 MIFARE Classic 兼容芯片，带后门指令，安全性更差。

### 4.5 密钥检查

```bash
# 用默认密钥列表检查
hf mf chk

# 用自定义字典检查
hf mf chk --1k -f keys.dic

# 快速模式
hf mf fchk --1k -f keys.dic

# 只检查 Key A
hf mf chk -a -f keys.dic

# 检查特定扇区
hf mf chk --1k --sector 0
```

`keys.dic` 格式（每行 12 hex）：
```
FFFFFFFFFFFF
000000000000
A0A1A2A3A4A5
B0B1B2B3B4B5
4D3A99C351DD
```

### 4.6 Darkside 攻击

**原理**：利用卡片对错误认证的响应时间差异，逐 bit 恢复密钥。

```bash
# Darkside 攻击（速度快，成功率取决于卡片）
hf mf darkside
```

**适用条件**：
- 卡片对 Darkside 有响应（大部分 FM11RF08 支持）
- 所需时间：通常 2-10 分钟/扇区

### 4.7 Nested 攻击

**原理**：利用已知的一个扇区密钥，通过 CRYPTO-1 的随机数缺陷恢复其他扇区密钥。

```bash
# 用一个已知密钥爆破其他扇区
hf mf nested --blk 0 -a -k FFFFFFFFFFFF
```

**关键**：需要**至少一个扇区**的已知密钥。通常是：
- 扇区 0 使用出厂默认 `FFFFFFFFFFFF`
- 或通过 `hf mf chk` 找到一个已知密钥

**参数**：
```
--blk <N>    已知密钥的块号
-a/-b        已知密钥是 Key A 还是 Key B
-k <KEY>     已知密钥值
--sector <N> 指定目标扇区（不指定则全部）
```

### 4.8 Hardnested 攻击

**原理**：在没有任何已知密钥的情况下，通过暴力 + 优化搜索恢复第一个密钥。最慢但最彻底。

```bash
# Hardnested 攻击（可能需要几小时到几天）
hf mf hardnested --blk 0 -a
```

**策略**：
1. 先用 `hf mf chk` 检查是否有默认密钥
2. 有至少一个密钥 → 用 Nested 攻击
3. 完全未知 → 用 Hardnested + 采集多次 nonce

**加速 Hardnested**：
- 固定卡片位置，不要移动
- 关闭其他 RF 干扰设备
- 使用 `--threads` 多线程

### 4.9 Autopwn — 一键破解

```bash
# 自动选择最佳策略
hf mf autopwn
```

**Autopwn 流程**：
1. `hf mf chk` — 检查默认密钥
2. 如果找到密钥 → `hf mf nested`
3. 如果没找到 → `hf mf darkside` → `hf mf nested`
4. 如果 Darkside 失败 → `hf mf hardnested`
5. 全密钥恢复 → `hf mf dump`

### 4.10 全卡 Dump 与写入

#### 完整导出

```bash
# dump 到 .bin 文件
hf mf dump

# dump 到 .eml 文本文件（可读）
hf mf dump --eml
```

生成的文件：
- `hf-mf-83E1406B-data.bin` — 二进制数据
- `hf-mf-83E1406B-data.eml` — 文本格式（每行一个 16 字节块）
- `hf-mf-83E1406B-key.bin` — 密钥文件

**EML 格式示例**：
```
831AE206680800000000000000000000    # Block 0 (UID+制造商)
00000000000000000000000000000000    # Block 1
00000000000000000000000000000000    # Block 2
FFFFFFFFFFFF08778F69FF0000000000    # Block 3 (Key A + AC + Key B)
```

#### 完整写入

```bash
# 写入全卡
hf mf restore --1k -f hf-mf-83E1406B-data.eml

# 指定密钥文件写入
hf mf restore --1k -f dump.eml -k dump-key.bin
```

**致命风险**：写入块 0 的 UID → 普通卡会变砖！只有 Magic 卡支持 UID 写入。

### 4.11 Magic 卡 — UID 可修改的特殊卡

Magic 卡是修改了固件的 MIFARE Classic 兼容卡，允许修改 UID 和块 0。

| 类型 | 别名 | 特性 |
|------|------|------|
| **Gen1** | UID 卡 | 通过后门指令修改 UID，最常见 |
| **Gen2** | CUID 卡 | 类似 Gen1，不同指令集 |
| **Gen3** | FUID 卡 | 写一次后永久锁定 UID |
| **Gen4** | UFUID 卡 | 可多次修改，最万能 |

#### 使用 Chinese Magic Backdoor (Gen1)

```bash
# 检测 Magic 卡
hf mf cgetsc

# 设置 UID
hf mf csetuid --uid 83E1406B

# 写入全卡（包含 UID）
hf mf restore --1k -f dump.eml

# 对 Gen2 (CUID)
hf mf csetuid --gen2 --uid 83E1406B
```

> **重要**：Magic 卡修改 UID 后，需断电重启再读卡才能看到新 UID。部分读卡器会专门检测 Magic 卡的后门指令（anti-magic 检测）。

### 4.12 完整攻击流程总结

```
第1步: hf search              → 确认卡类型
第2步: hf 14a info             → 获取 UID/SAK/ATQA
第3步: hf mf chk              → 检查默认密钥
第4步: hf mf autopwn          → 一键破解（或以下分步）
  └─ hf mf darkside           → Darkside 攻击
  └─ hf mf nested             → Nested 攻击
  └─ hf mf hardnested         → Hardnested (最后手段)
第5步: hf mf dump             → 导出全卡数据
第6步: hf mf restore          → 写入新卡/Magic 卡
```

### 4.13 常见问题

| 问题 | 原因 | 解决 |
|------|------|------|
| `No MIFARE Classic tag found` | 卡片位置不对 | 调整天线位置 |
| `Auth error` | 密钥错误 | 需要破解密钥 |
| `Key not found for sector` | 该扇区密钥未恢复 | Nested/Hardnested |
| `Multiple tags detected` | 多张卡在天线上 | 取走其他卡 |
| `Can't set UID on non-magic card` | 普通卡不能改 UID | 用 Magic 卡 |
| `Write block 0 failed` | 写的是普通卡块 0 | 用 Magic 卡 |

---

<a name="ch5"></a>
## 第5章 · NTAG / MIFARE Ultralight

### 5.1 概述

NTAG 是 NXP 的新一代低成本 NFC 标签，兼容 ISO 14443-A，广泛用于：
- NFC 标签/贴纸
- 酒店房卡（部分）
- 一次性门票
- Amiibo 玩具
- 产品防伪标签

| 型号 | 内存 | 页大小 | 密码保护 |
|------|------|--------|---------|
| NTAG213 | 144B | 4B/页 | ✅ 32-bit |
| NTAG215 | 504B | 4B/页 | ✅ 32-bit |
| NTAG216 | 888B | 4B/页 | ✅ 32-bit |
| Ultralight C | 192B | 4B/页 | ✅ 3DES |
| Ultralight EV1 | 384B | 4B/页 | ✅ 32-bit |

### 5.2 结构

NTAG 按页编址（每页 4 字节）：

```
页 0-1:   UID + 序列号
页 2:     锁定字节 + OTP
页 3:     功能容器 (CC)
页 4-39:  用户数据 (NTAG213: 页4-39, NTAG215: 页4-129)
页 40+:   配置页（密码、PACK、AUTH0 等）
```

### 5.3 基本操作

```bash
# 检测 NTAG
hf search

# 详细信息
hf 14a info

# 读取所有页
hf mfu dump

# 读取指定页
hf mfu rdbl --page 4

# 写入指定页
hf mfu wrbl --page 10 --data 48656C6C6F
```

### 5.4 密码认证

```bash
# 密码认证 (NTAG213/215/216)
hf mfu pwdgen --uid 04A1B2C37A6180   # 生成 PWD 和 PACK

# 用密码认证
hf mfu auth --pwd 1234ABCD

# 认证后读取受保护页
hf mfu rdbl --page 40
```

**PWD 生成公式**：
```
PWD = uid[0:4] XOR uid[4:6] XOR magic_number
PACK = uid[6] XOR uid[0:4] 的低 2 字节
```

### 5.5 Amiibo 读取

Amiibo（任天堂 NFC 玩偶）本质是带密码保护的 NTAG215：

```bash
hf mfu info
hf 14a info

# 生成 Amiibo 密钥（需要特定工具/网站计算）
# 读取
hf mfu dump
```

---

<a name="ch6"></a>
## 第6章 · MIFARE DESFire 入门

### 6.1 概述

DESFire 是 MIFARE Classic 的安全升级版，广泛用于：
- 交通卡（公交、地铁）
- 门禁系统
- 支付系统
- 护照/身份证

| 特性 | MIFARE Classic | **DESFire EV1/EV2** | **DESFire EV3** |
|------|:---:|:---:|:---:|
| 加密算法 | CRYPTO-1 (已破解) | DES/3DES/AES | AES |
| 密钥长度 | 48-bit | 56/112/128-bit | 128/256-bit |
| 文件系统 | 固定扇区 | 灵活文件 | 灵活文件 |
| 应用数 | 16 | 28 | 32 |
| 安全性 | ❌ 已破 | ✅ 高 | ✅ 极高 |

### 6.2 结构

DESFire 使用文件系统模型：

```
PICC Master Key (主密钥)
├── Application 0 (出厂默认)
├── Application 1 (交通应用)
│   ├── File 1: 余额 (Value File)
│   ├── File 2: 交易记录 (Standard File)
│   └── ...
├── Application 2 (门禁应用)
└── Application N
```

### 6.3 基本侦察

```bash
# 检测 DESFire
hf search

# 详细信息
hf 14a info

# 获取版本信息
hf mfdes info

# 获取应用列表 (默认不需要认证)
hf mfdes getappids

# 获取文件列表 (可能需要认证)
hf mfdes getfileids --aid 123456

# 获取文件设置
hf mfdes getfilesettings --aid 123456 --fid 01
```

### 6.4 认证

```bash
# DES/3DES 认证
hf mfdes auth --aid 123456 --keyno 0 --key 00112233445566778899AABBCCDDEEFF

# AES 认证
hf mfdes auth --aid 123456 --keyno 0 --key 00112233445566778899AABBCCDDEEFF --aes

# 用默认密钥
hf mfdes auth --aid 000000 --keyno 0 --key 0000000000000000
```

### 6.5 读写数据

```bash
# 读文件
hf mfdes read --aid 123456 --fid 01 --offset 0 --length 16

# 写文件
hf mfdes write --aid 123456 --fid 01 --offset 0 --data AABBCCDD

# 读取 Value 文件
hf mfdes getvalue --aid 123456 --fid 02
```

### 6.6 常见攻击路径

1. **默认密钥**: 部分厂商使用 `0000000000000000` 或 `FFFFFFFFFFFFFFFF`
2. **密钥爆破**: 用字典尝试 PICC Master Key
3. **嗅探**: 捕获合法读卡器和卡片之间的认证
4. **侧信道**: 计时攻击恢复密钥（研究级）

> **现实**：DESFire 远比 Classic 安全。没有已知密钥的情况下，PM3 无法破解。实战中更多依赖社工、默认密钥或侧信道。

### 6.7 检查默认密钥

```bash
# 字典文件 keys_desfire.dic
# 格式: KEY_HEX
0000000000000000
FFFFFFFFFFFFFFFF
AABBCCDDEEFF00112233445566778899

# 检查
hf mfdes chk -f keys_desfire.dic
```

---

<a name="ch7"></a>
## 第7章 · 其他高频技术

### 7.1 ISO 15693 (NFC-V)

用于图书馆、工业标签、医疗：

```bash
hf 15 search
hf 15 info
hf 15 read --block 0
hf 15 write --block 1 --data 12345678
```

### 7.2 iCLASS / PicoPass

HID 的高频门禁方案，安全性较高：

```bash
hf iclass info
hf iclass dump
hf iclass list

# 使用默认密钥读取
hf iclass rdbl --block 6 --key 0000000000000000

# Loclass 攻击 (需要嗅探)
hf iclass loclass
```

**关键密钥**：
- iCLASS Standard: 默认 `FFFFFFFFFFFFFFFF`
- iCLASS SE/SR: 专有密钥，难破解
- iCLASS Elite: 需要提前获取 Elite 密钥

### 7.3 FeliCa (NFC-F / ISO 18092)

日本标准，广泛用于日本交通卡、电子钱包：

```bash
hf felica list       # 检测 FeliCa 卡
hf felica info       # 信息
hf felica read       # 读取
```

中国部分地区交通卡也使用 FeliCa Lite。

### 7.4 ISO 14443-B (身份证 / 银行卡非接触)

**中国第二代身份证** 使用 ISO 14443-B Type B：

```bash
hf 14b info          # 检测 Type B 卡片
hf 14b read          # 读取
hf 14b dump          # 导出
```

> ⚠️ **警告**：身份证包含敏感个人信息。仅用于安全研究测试自己的证件，切勿用于非法目的。

**身份证读取注意事项**：
- 需要天线强耦合（电压 > 17V）
- 使用 `hf 14b` 系列命令
- 数据加密，裸读得不到任何有用信息
- 读卡需要 SAM 模块解密

### 7.5 LEGIC Prime

欧洲高端门禁系统：

```bash
hf legic info
hf legic dump
hf legic read --offset 0 --length 32
```

### 7.6 TOPAZ (NFC Type 1)

简单低成本标签，常用于一次性票券：

```bash
hf topaz info
hf topaz dump
hf topaz read --page 0
```

---

<a name="ch8"></a>
## 第8章 · 实战案例集

### 案例1: 小区门禁卡复制（低频 EM410x）

**场景**：老旧小区使用 125kHz ID 门禁卡，无加密。

```bash
# 1. 读原卡
lf search
# 输出: EM410x ID: 1A003BF2E1

# 2. 放上空白 T5577
lf t55xx wipe
lf em 410x_write --id 1A003BF2E1

# 3. 验证
lf search
# 输出: EM410x ID: 1A003BF2E1  ✅ 完成
```

**耗时**: < 30 秒

### 案例2: 电梯卡破解（MIFARE Classic 1K）

**场景**：小区电梯卡，MIFARE Classic 1K，未知密钥。

```bash
# 1. 确认卡类型
hf search
# SAK: 08 → MIFARE Classic 1K

hf 14a info
# UID: 83E1406B, ATQA: 0004

# 2. 检查默认密钥
hf mf chk
# 扇区 0 Key A: FFFFFFFFFFFF ✅

# 3. Nested 攻击（利用已知扇区0密钥）
hf mf nested --blk 0 -a -k FFFFFFFFFFFF
# 已恢复 15/16 扇区密钥...

# 4. 全卡导出
hf mf dump
# 保存到 hf-mf-83E1406B-*

# 5. 分析数据：找到电梯楼层数据
# 块 4 (扇区 1 块 0): 0F0000000000000000000000000000
#   0F = 15 楼

# 6. 用 Magic 卡复制
hf mf csetuid --uid 83E1406B    # Gen1 Magic 卡
hf mf restore --1k -f dump.eml
```

**耗时**: 5-15 分钟

### 案例3: 酒店房卡分析

**场景**：某酒店使用 MIFARE Classic EV1 4K。

```bash
# 1. 检测
hf search
# MIFARE Classic 4K, SAK: 18

# 2. 密钥检查
hf mf chk --4k
# 扇区 0-5 使用 FFFFFFFFFFFF
# 扇区 6-38 使用酒店自定义密钥

# 3. Nested 攻击其他扇区
hf mf nested --blk 0 -a -k FFFFFFFFFFFF

# 4. 分析数据找出房间号和有效期
hf mf dump
# 块 20: 1008420F → Room 1008, valid until 2026-08-15
```

### 案例4: 公司考勤卡复制（HID Prox）

**场景**：美资公司使用 HID Prox 26-bit 门禁卡。

```bash
lf hid read
# Format: H10301 (26-bit)
# FC: 18  CN: 12345

lb hid clone --fc 18 --cn 12345
```

### 案例5: 银行卡 EMV 数据读取（非交易）

```bash
# 读卡
hf search
# ISO 14443-A, ATS present

# EMV 命令
hf emv select
hf emv gpo
hf emv readrec

# 可获取信息:
# - PAN (卡号后 4 位脱敏)
# - 有效期
# - 发卡行
# - 应用类型 (借记/贷记)
```

> ⚠️ 银行卡不能通过 PM3 完成交易或获取完整卡号/PIN。

---

<a name="ch9"></a>
## 第9章 · 进阶玩法

### 9.1 Standalone 模式

Standalone 模式让 PM3 脱离电脑独立工作，通过 LED 和按钮交互。

```bash
# 查看可用 standalone 模式
hf mf standalone

# 编译时启用
# 修改 Makefile.platform: STANDALONE=LF_SAMYRUN
```

**常用 Standalone 模式**：

| 模式 | 功能 |
|------|------|
| `LF_EM4100RSWB` | 低频读/模拟/暴力 |
| `LF_SAMYRUN` | 低频万能模式 |
| `LF_ICEHID` | HID 卡模拟 |
| `HF_MATTYRUN` | 高频 MIFARE 万能 |
| `HF_COLIN` | MIFARE Classic 破解 |
| `HF_AVEFUL` | DESFire/Ultralight |

### 9.2 嗅探模式

```bash
# 嗅探 ISO 14443-A 通信
hf 14a sniff

# 嗅探 ISO 14443-B
hf 14b sniff

# 同时嗅探多个标准
hf sniff
```

### 9.3 模拟模式

```bash
# 模拟 MIFARE Classic UID
hf mf sim --uid 83E1406B

# 模拟低频 HID
lf hid sim --fc 18 --cn 12345

# 模拟 EM410x
lf em 410x_sim --id 1A003BF2E1
```

### 9.4 Python 脚本开发

PM3 的 Python 脚本支持可以做自动化攻击：

```python
#!/usr/bin/env python3
"""自动批量读取 MIFARE Classic 并导出"""

import pm3
import sys

def auto_read():
    pm3.console('hf search')
    info = pm3.console('hf 14a info')

    if 'Classic' not in info:
        print('非 MIFARE Classic，跳过')
        return

    # 提取 UID
    for line in info.split('\n'):
        if 'UID' in line:
            uid = line.split(':')[-1].strip()
            print(f'发现 MIFARE Classic, UID: {uid}')

            # 检查密钥
            pm3.console('hf mf chk')
            # 自动破解
            pm3.console('hf mf autopwn')
            # 导出
            pm3.console('hf mf dump')
            break

if __name__ == '__main__':
    auto_read()
```

### 9.5 自定义天线

PM3 RDV4 支持外接天线，Easy 版可通过焊接 SMA 接口改装：

- **大环天线**：读取大尺寸标签或远距离
- **探针天线**：精确读取小型标签
- **定向天线**：特定方向读取

---

<a name="chA"></a>
## 附录

### 附录A: 命令速查表

#### 通用

| 命令 | 说明 |
|------|------|
| `hw version` | 版本信息 |
| `hw status` | 运行状态 |
| `hw tune` | 天线调谐 |
| `hw ping` | 连通测试 |
| `hw reset` | 硬件复位 |

#### 低频 (125kHz)

| 命令 | 说明 |
|------|------|
| `lf search` | 自动搜索低频卡 |
| `lf em 410x_read` | 读 EM410x |
| `lf em 410x_write --id <ID>` | 写 EM410x 到 T55x7 |
| `lf em 410x_sim --id <ID>` | 模拟 EM410x |
| `lf hid read` | 读 HID Prox |
| `lf hid clone --fc <FC> --cn <CN>` | 克隆 HID 到 T55x7 |
| `lf hid sim --fc <FC> --cn <CN>` | 模拟 HID |
| `lf indala read` | 读 Indala |
| `lf t55xx info` | T55x7 信息 |
| `lf t55xx dump` | T55x7 完整导出 |
| `lf t55xx wipe` | T55x7 擦除 |

#### 高频 MIFARE Classic

| 命令 | 说明 |
|------|------|
| `hf mf chk` | 默认密钥检查 |
| `hf mf fchk --1k -f <dic>` | 快速字典密钥检查 |
| `hf mf darkside` | Darkside 攻击 |
| `hf mf nested --blk 0 -a -k <KEY>` | Nested 攻击 |
| `hf mf hardnested` | Hardnested 攻击 |
| `hf mf autopwn` | 一键破解（自动选策略） |
| `hf mf dump` | 全卡导出 |
| `hf mf restore --1k -f <file>` | 全卡写入 |
| `hf mf rdbl <n>` | 读块 |
| `hf mf wrbl <n> --data <HEX>` | 写块 |
| `hf mf csetuid --uid <UID>` | Magic 卡改 UID |
| `hf mf cgetsc` | Magic 卡检测 |

#### 其他高频

| 命令 | 说明 |
|------|------|
| `hf search` | 搜索高频卡 |
| `hf 14a info` | ISO 14443-A 信息 |
| `hf 14b info` | ISO 14443-B 信息 |
| `hf mfu dump` | NTAG/Ultralight 导出 |
| `hf mfu rdbl --page <N>` | NTAG 读页 |
| `hf mfu wrbl --page <N> --data <HEX>` | NTAG 写页 |
| `hf mfdes info` | DESFire 信息 |
| `hf mfdes getappids` | DESFire 应用列表 |
| `hf mfdes auth --aid <ID> --keyno <N> --key <KEY>` | DESFire 认证 |
| `hf 15 info` | ISO 15693 信息 |
| `hf iclass info` | iCLASS 信息 |
| `hf felica info` | FeliCa 信息 |
| `hf legic info` | LEGIC 信息 |

#### 模拟

| 命令 | 说明 |
|------|------|
| `hf mf sim --uid <UID>` | 模拟 MIFARE Classic |
| `lf em 410x_sim --id <ID>` | 模拟 EM410x |
| `lf hid sim --fc <N> --cn <N>` | 模拟 HID |

### 附录B: 常见卡片 ATR/ATQA/SAK 识别

| SAK | ATQA | 类型 |
|-----|------|------|
| 08 | 0004 | **MIFARE Classic 1K** |
| 18 | 0002 | MIFARE Classic 4K |
| 09 | 0004 | MIFARE Mini |
| 00 | 0044 | MIFARE Ultralight / NTAG |
| 20 | 0344 | MIFARE DESFire |
| 28 | 0344 | MIFARE Plus |
| 38 | 0050 | NFC Forum Type 4 |

### 附录C: 故障排查

| 问题 | 可能原因 | 解决方法 |
|------|----------|---------|
| `serial port: Permission denied` | 没加 dialout 组 | `sudo usermod -aG dialout $USER` |
| `serial port claimed by another process` | 另一个 PM3 进程在跑 | `pkill proxmark3` |
| `No tag found` | 卡片位置/天线耦合 | 调位置, `hw tune` 检查电压 |
| `Auth error` | 密钥错误 | 先用 `hf mf chk` 找已知密钥 |
| `Write failed` | 块受保护/非 Magic 卡 | 检查控制位, 用 Magic 卡 |
| WSL2: 设备断开 | PM3 重启后 USB 重置 | 重新 `usbipd attach` |
| `Hardware not found` | COM 口/权限问题 | 检查 `usbipd list` / 设备管理器 |
| 身份证读不出来 | 耦合太弱 | 电压需要 > 17V，调整位置 |
| `fpga_pm3_hf.ncd image not found` | 缺少 FPGA 文件 | 完整编译 `make` 而非 `make client` |

### 附录D: 密钥字典模板

保存为 `keys.dic`（MIFARE Classic 密钥字典）：

```
# NXP 出厂默认
FFFFFFFFFFFF
000000000000

# NXP 开发示例
A0A1A2A3A4A5
B0B1B2B3B4B5

# 常见厂商
4D3A99C351DD
1A982C7E459A
D3F7D3F7D3F7
AABBCCDDEEFF
001122334455
112233445566

# 交运常见
A0B0C0D0E0F0
A1B1C1D1E1F1
```

### 附录E: PM3 购买建议

| 平台 | 店铺关键词 | 备注 |
|------|----------|------|
| 淘宝 | "Proxmark3 Easy 512K" | 最便宜、入门首选 |
| 闲鱼 | 同上 | 二手更便宜 |
| AliExpress | "Proxmark3 Easy Iceman" | 海外 |

**购买注意**：
- 选 **512KB** 闪存版本（不是 256KB）
- VID:PID 应该是 `9AC4:4B8F` (Iceman 固件)
- 配齐 HF + LF 天线
- 建议买带壳版本（防静电）

### 附录F: 社区经验汇总（论坛精华）

> 以下内容提炼自吾爱破解、看雪、Proxmark Forum、Dangerous Things 等论坛的高频实战经验。

#### F.1 天线九法

1. **不同卡不同位置**: MIFARE 放 HF 线圈正上方，T5577 放 LF 漆包线大圈上
2. **悬空优于按压**: 手指压在卡上会吸收射频能量，电压降 2-3V。用塑料片垫高 1mm
3. **hf tune 是好朋友**: 读不出卡时，先看 HF 电压 ≥ 15V
4. **方向敏感**: 部分卡的线圈方向要求卡旋转 90°/180° 才能读

#### F.2 破解效率

5. **Darkside 优先 Nested 兜底**: 85% 的 MIFARE Classic 能用 Darkside 在 5 分钟内破解
6. **FM11RF08 后门**: 复旦微的兼容芯片带有后门指令，破解读取速度是原版 NXP 的 5-10 倍
7. **密钥字典演化**: 从默认 4-6 条扩充到 500+ 条，覆盖公交、酒店、校园卡常见密钥（推荐 `iceman_keys.dic`）
8. **Hardnested 挂机**: 没有任何已知密钥时，睡觉前放好卡片启动 Hardnested，早上起来就能收结果

#### F.3 Magic 卡血泪

9. **Gen1 会变砖**: Gen1 卡的后门指令一旦被新固件或 anti-magic 读卡器检测到，卡可能被永久锁死
10. **CUID 不等于万能**: 部分读卡器会检测 CUID 的特征指令，导致卡被拒绝
11. **Gen3 FUID 一次性**: FUID 写一次后变成"真卡"（不可再改 UID），适合需要长期使用的场景
12. **Gen4 UFUID 最灵活但贵**: 20-30 元/张，可以反复改 UID + 模拟其他类型，性价比不如买 5 张 Gen1

#### F.4 数据解读

13. **电梯楼层常在小端序**: 扇区 1 块 0 的 `0F000000` = 15 楼，`18000000` = 24 楼
14. **日期一般不加密**: 有效期大多是明文 HEX，`260831` = 2026-08-31
15. **余额校验保护**: 地铁卡/饭卡的余额有 CRC 校验或双份存储，直接改 hex 会被检测
16. **UID 白名单**: 部分系统只校验 UID（不在白名单内即使数据正确也打不开），这种情况只需复制 UID 不需全卡

#### F.5 实战避坑

17. **别在别人读卡器上测试模拟**: `hf mf sim` 的射频信号可能干扰正常读卡器工作
18. **卡片分类贴标签**: 用不同颜色贴纸区分原卡、T5577、各种 Magic 卡，避免搞混
19. **dump 备份是信仰**: 任何操作前先 dump 原卡数据，至少有退路
20. **身份证不裸读**: 二代证有 SAM 加密，裸读只能拿到 UID。破解身份证需要专用 SAM 模块 + 公安授权

### 附录G: Magic 卡深度专题

#### G.1 发展历史

| 年份 | 里程碑 |
|------|--------|
| 2008 | NXP 确认 CRYPTO-1 被破解（论文发表） |
| 2012 | 首张 Magic 卡出现在黑色市场，使用后门指令绕过 UID 写保护 |
| 2015 | Gen2 (CUID) 推出，解决 Gen1 被 anti-magic 检测的问题 |
| 2018 | Gen4 推出，支持多重模拟模式 |
| 2020 | Iceman 固件集成 `hf mf c*` 全套 Magic 卡命令 |

#### G.2 Magic 卡命令详解

```bash
# === Gen1 (Chinese Magic Backdoor) ===
hf mf cgetsc                    # 发送后门指令检查是否 Gen1
hf mf csetuid --uid 83E1406B    # 设置 UID
hf mf csetblk --blk 1 -d 00...  # 修改块数据（含块 0）
hf mf cwipe                     # 擦除卡（恢复出厂）

# === Gen2 (CUID) ===
hf mf csetuid --uid 83E1406B --gen2

# === Gen3 (FUID) ===  
hf mf csetuid --uid 83E1406B --gen3  # 写入后锁定

# === Gen4 (UFUID) ===
hf mf csetuid --uid 83E1406B --gen4
hf mf gen4 help                  # Gen4 完整帮助
hf mf gen4 getversion            # Gen4 版本信息
hf mf gen4 setmode --mode classic  # 设置模拟模式
```

#### G.3 Anti-Magic 检测原理

| 检测手段 | 原理 | 绕过 |
|----------|------|------|
| 后门指令探测 | 发送 Gen1 后门命令，有响应=Magic 卡 | Gen2+ (CUID+) |
| 计时攻击 | 标准卡片和 Magic 卡响应时间不同 | Gen4 有时序调整 |
| ATQA/SAK 校验 | 检查是否有不应存在的 ATQA/SAK 组合 | Gen4 自定义模式 |
| 写块0测试 | 尝试写块 0，成功=Magic 卡 | Gen3 FUID × |

#### G.4 卡片归属速查

```bash
# 判断 Magic 卡类型
hf mf cgetsc                       # 有响应 → Gen1
hf mf csetuid --uid 00000000 --gen2 # 测试 Gen2
hf mf gen4 getversion              # 有响应 → Gen4
```

### 附录H: 中国常见门禁系统与卡片对照

| 门禁品牌 | 常见卡片 | 频率 | 安全等级 | 可克隆 |
|----------|---------|------|----------|--------|
| 海康威视 | MIFARE Classic 1K | 13.56M | 低 | ✅ |
| 大华 | MIFARE Classic 1K | 13.56M | 低 | ✅ |
| 中控智慧 | EM410x / M1 可选 | 125k/13.56M | 极低 | ✅ |
| 霍尼韦尔 | iCLASS / MIFARE | 13.56M | 中-高 | ⚠️ |
| HID Global | HID Prox / iCLASS | 125k/13.56M | 中-高 | ⚠️ |
| 安居宝 | EM410x | 125k | 极低 | ✅ |
| 立林 | MIFARE Classic | 13.56M | 低 | ✅ |
| 捷顺 | MIFARE Classic 1K | 13.56M | 低 | ✅ |
| 熵基 | MIFARE Classic / DESFire | 13.56M | 低-高 | ⚠️ |
| 达实智能 | MIFARE Classic | 13.56M | 低 | ✅ |

### 附录I: 卡片芯片品牌识别

| SAK | ATQA | 可能厂商 | 常见芯片 |
|-----|------|---------|---------|
| 08 | 0004 | **NXP** (原版) | MF1S50 |
| 08 | 0004 | **复旦微** | FM11RF08 |
| 08 | 0004 | **华虹** | SHC1104 |
| 08 | 0004 | **同方** | THM3060 |
| 08 | 0044 | 防篡改 MFC | 部分有特殊防护 |

> **国产芯片判断**: 原版 MIFARE Classic 有 ATS 且随机数质量高。国产兼容芯片（复旦微、华虹等）通常无 ATS 或 ATS 异常，Darkside 攻击速度远快于原版。

---

> **结语**  
> RFID 安全是物理安全与网络安全交汇的前沿领域。Proxmark3 是你手中的万能钥匙 — 理解它、掌握它，但请记住：技术无罪，工具无罪，如何使用取决于你。  
>  
> **安全研究，遵守法律，仅用于授权测试和个人学习。**



