# Proxmark3 驱动安装指南

Proxmark3 使用 USB CDC ACM 协议与主机通信。不同操作系统的驱动安装方式如下。

## Windows

### 方法 A: 自动安装（Windows 10/11 推荐）

Windows 10/11 内置 `usbser.sys` 驱动，插入 PM3 后通常自动识别为串口设备。

1. 插入 Proxmark3
2. 打开 **设备管理器** (`devmgmt.msc`)
3. 查看 **端口 (COM 和 LPT)** 下是否出现 `Proxmark3` 或 `USB 串行设备`
4. 如果自动安装成功，记下 COM 端口号（如 `COM24`）

### 方法 B: 手动安装 INF 驱动

如果自动安装失败（设备显示为 "未知设备"）：

1. 打开 **设备管理器** → 找到带黄色感叹号的 PM3 设备
2. 右键 → **更新驱动程序** → **浏览我的电脑以查找驱动程序**
3. **让我从计算机上的可用驱动程序列表中选取**
4. **从磁盘安装** → 浏览选择 `driver\proxmark3.inf`
5. 选择 `Proxmark3` → 下一步
6. **忽略 "未签名驱动" 警告** → 继续安装

### 方法 C: Zadig (WinUSB 模式)

如果串口驱动安装后仍然无法通信，可以试用 Zadig 安装通用 WinUSB 驱动：

1. 安装 [Proxmark3 Windows 客户端](https://github.com/RfidResearchGroup/proxmark3/releases)（含 Zadig）
2. 运行 `proxmark3\client\tools\zadig.exe`
3. Options → List All Devices
4. 选择 `Proxmark3` → Driver: **WinUSB** → Replace Driver

> **注意**: WSL2 下使用 `usbipd-win` 连接 PM3 时，**不需要**安装 WinUSB/Zadig 驱动。PM3 保持为 COM 端口设备即可，usbipd-win 会直接转发 USB 设备到 WSL2。

### 验证

```powershell
# 检查 COM 端口
Get-CimInstance -ClassName Win32_SerialPort | Where-Object { $_.PNPDeviceID -like '*VID_9AC4*' }

# 使用 WSL2 客户端测试
wsl -d Ubuntu bash -c "cd ~/pm3_cn2/client && ./proxmark3 /dev/ttyACM0 -c 'hw version'"
```

## Linux

### udev 规则（防止 ModemManager 抢占）

PM3 的 USB CDC ACM 接口可能被 ModemManager 误识别为调制解调器，导致串口无法正常使用。

**自动安装（安装脚本自动执行）**：

```bash
# 复制 udev 规则并重载
sudo cp driver/77-pm3-usb-device-blacklist-*.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

**手动安装**：

| 文件 | 作用 |
|------|------|
| `77-pm3-usb-device-blacklist-dialout.rules` | 将 `dialout` 组用户排除在 ModemManager 之外 |
| `77-pm3-usb-device-blacklist-uucp.rules` | 将 `uucp` 组用户排除在 ModemManager 之外 |

如果 PM3 串口仍有问题：
```bash
# 临时禁用 ModemManager
sudo systemctl stop ModemManager
sudo systemctl disable ModemManager

# 或彻底卸载
sudo apt remove modemmanager
```

### 串口权限

```bash
# 将当前用户加入 dialout 组
sudo usermod -a -G dialout $USER
# 注销后重新登录生效
```

### 验证

```bash
ls -la /dev/ttyACM*
# 预期: crw-rw---- 1 root dialout ... /dev/ttyACM0

~/pm3_cn2/client/proxmark3 /dev/ttyACM0 -c "hw version"
```

## macOS

macOS 自带 CDC ACM 驱动，无需手动安装。

```bash
ls -la /dev/cu.usbmodem*
# 预期: /dev/cu.usbmodemXXX

~/pm3_cn2/client/proxmark3 /dev/cu.usbmodemXXX -c "hw version"
```

## 故障排查

| 症状 | 可能原因 | 解决方法 |
|------|----------|----------|
| 设备管理器无 PM3 | USB 线缆/供电问题 | 更换数据线，直接插主板 USB 口 |
| COM 口有黄色感叹号 | 驱动未安装/签名验证阻止 | 使用 INF 手动安装或禁用驱动签名 |
| WSL2 `ttyACM0` 不存在 | usbipd 未连接 | `usbipd list` → `usbipd bind --busid X-Y` → `usbipd attach --wsl --busid X-Y` |
| Linux `ttyACM0` 断开重连 | ModemManager 抢占 | 安装 udev 规则或禁用 ModemManager |
| `permission denied` | 串口权限不足 | `sudo usermod -a -G dialout $USER` |

## 相关 VID/PID

Proxmark3 各型号的 USB 标识：

| 型号 | VID:PID |
|------|---------|
| Proxmark3 (Iceman) | `9AC4:4B8F` |
| Proxmark3 (old bootloader) | `2D2D:504D` |
| Proxmark3 Easy | `502D:502D` |
| RDV4 | `9AC4:4B8F` |
