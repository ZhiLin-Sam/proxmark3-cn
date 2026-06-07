# Proxmark3 FullCN v4.21611 - Windows 一键安装脚本
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
#
# 前置条件: WSL2 Ubuntu 已安装 + usbipd-win 已安装
# 如果未满足，脚本会尝试自动安装

param(
    [switch]$SkipWSL2Check,  # 跳过 WSL2 安装检查（如果已确认正常）
    [switch]$SkipUSBIPD,     # 跳过 usbipd-win 安装
    [switch]$SkipBuild,      # 跳过编译（仅使用预编译二进制）
    [switch]$DryRun          # 仅检查环境，不执行安装
)

$ErrorActionPreference = "Stop"
$PACKAGE_ROOT = Split-Path -Parent $PSScriptRoot
$WSL_DISTRO = "Ubuntu"

Write-Host @"

============================================
 Proxmark3 FullCN v4.21611 安装程序
============================================
 包目录: $PACKAGE_ROOT

"@

# === 1. 检查 WSL2 ===
Write-Host "[1/6] 检查 WSL2..."
$wslOk = $true
try {
    $wslVersion = wsl --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "WSL not installed" }
    $distroOk = wsl -l -q 2>&1 | Select-String -Quiet $WSL_DISTRO
    if (-not $distroOk) {
        Write-Host "  [!] Ubuntu 发行版未安装，正在安装..."
        if ($DryRun) { Write-Host "  [DRY-RUN] wsl --install -d Ubuntu" }
        else { wsl --install -d Ubuntu }
        Write-Host "  [!] 请重启后重新运行此脚本"
        exit 0
    }
} catch {
    Write-Host "  [!] WSL2 未安装，正在安装..."
    if ($DryRun) { Write-Host "  [DRY-RUN] wsl --install" }
    else {
        wsl --install
        Write-Host "  [!] 请重启后重新运行此脚本"
        exit 0
    }
}
Write-Host "  [OK] WSL2 + Ubuntu 就绪"

# === 2. 检查 usbipd-win ===
Write-Host "[2/6] 检查 usbipd-win..."
$usbipdExe = "C:\Program Files\usbipd-win\usbipd.exe"
if (-not (Test-Path $usbipdExe) -and -not $SkipUSBIPD) {
    Write-Host "  [!] usbipd-win 未安装，正在通过 winget 安装..."
    if (-not $DryRun) {
        winget install --id dorssel.usbipd-win --accept-source-agreements --accept-package-agreements
    } else { Write-Host "  [DRY-RUN] winget install dorssel.usbipd-win" }
}
if (Test-Path $usbipdExe) {
    Write-Host "  [OK] usbipd-win 已安装"
} else {
    Write-Host "  [WARN] usbipd-win 未安装，Proxmark3 USB 连接需要它"
    Write-Host "         手动安装: https://github.com/dorssel/usbipd-win/releases"
}

# === 3. 安装启动脚本 ===
Write-Host "[3/6] 安装启动脚本..."
$localBin = "$env:USERPROFILE\.local\bin"
if (-not (Test-Path $localBin)) { New-Item -ItemType Directory -Force -Path $localBin | Out-Null }

Copy-Item -LiteralPath "$PACKAGE_ROOT\pm3.bat" -Destination "$localBin\pm3.bat" -Force
Copy-Item -LiteralPath "$PACKAGE_ROOT\pm3.ps1" -Destination "$localBin\pm3.ps1" -Force

# 检查 PATH
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$localBin*") {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$localBin", "User")
    $env:PATH = "$env:PATH;$localBin"
    Write-Host "  [OK] $localBin 已添加到用户 PATH"
} else {
    Write-Host "  [OK] $localBin 已在 PATH 中"
}

# === 4. 复制源码到 WSL2 ===
Write-Host "[4/6] 复制源码到 WSL2..."
if (-not $SkipBuild) {
    $srcDir = Join-Path $PACKAGE_ROOT "src"
    if (-not (Test-Path $srcDir)) {
        Write-Host "  [ERR] src/ 目录不存在！请确保完整解压发布包"
        exit 1
    }
    if (-not $DryRun) {
        # 将 src/ 打包并通过 WSL tar 解压到 ~/pm3_cn2/
        wsl -d $WSL_DISTRO bash -l -c "rm -rf ~/pm3_cn2 && mkdir -p ~/pm3_cn2"
        # 使用 WSL 内部的 tar 通过 /mnt 路径直接读取
        wsl -d $WSL_DISTRO bash -l -c "cd '$($srcDir -replace '\\','/' -replace 'C:','/mnt/c')/..' && tar czf /tmp/pm3_src.tar.gz src/ 2>/dev/null" 
        wsl -d $WSL_DISTRO bash -l -c "cd ~/pm3_cn2 && tar xzf /tmp/pm3_src.tar.gz --strip-components=1 && rm /tmp/pm3_src.tar.gz && echo 'source copied OK' && find . -maxdepth 1 -type d | wc -l"
    } else {
        Write-Host "  [DRY-RUN] Would copy src/ to ~/pm3_cn2/"
    }
} else {
    Write-Host "  [SKIP] --SkipBuild 已设置"
}

# === 5. 安装编译依赖 + 编译 ===
Write-Host "[5/6] 安装编译依赖并编译客户端..."
if (-not $SkipBuild) {
    $buildScript = @'
#!/bin/bash
set -e
echo "  -> 更新 apt 源..."
sudo apt-get update -qq
echo "  -> 安装编译依赖..."
sudo apt-get install -y -qq git build-essential pkg-config libreadline-dev \
    gcc-arm-none-eabi libnewlib-dev qtbase5-dev libbz2-dev liblz4-dev \
    libbluetooth-dev libpython3-dev libssl-dev 2>&1 | tail -1
echo "  -> 编译客户端..."
cd ~/pm3_cn2
make -j$(nproc) client 2>&1 | tail -3
echo "  -> 编译完成"
ls -lh client/proxmark3
'@
    if (-not $DryRun) {
        $buildScript | wsl -d $WSL_DISTRO bash -l
    } else {
        Write-Host "  [DRY-RUN] Would install deps + build client in WSL2"
    }
} else {
    Write-Host "  [SKIP] 使用预编译二进制"
}

# === 6. 安装预编译二进制 ===
Write-Host "[6/6] 安装预编译中文二进制..."
if (-not $DryRun) {
    $cn2bin = Join-Path $PACKAGE_ROOT "client\proxmark3_cn2"
    if (Test-Path $cn2bin) {
        wsl -d $WSL_DISTRO bash -l -c "cp -f '$($cn2bin -replace '\\','/' -replace 'C:','/mnt/c')' ~/pm3_cn2/client/proxmark3"
        Write-Host "  [OK] 中文二进制已安装到 ~/pm3_cn2/client/proxmark3"
    } else {
        Write-Host "  [WARN] client/proxmark3_cn2 不存在，将使用编译产物"
    }
} else {
    Write-Host "  [DRY-RUN] Would copy proxmark3_cn2 to WSL"
}

Write-Host @"

============================================
 安装完成！
============================================

使用方法:
  pm3                    # 英文原版交互模式
  pm3 -cn2               # 全中文版交互模式
  pm3 -cn2 -c "命令"      # 单条中文命令

  # 重新编译（修改源码后）
  wsl -d Ubuntu bash -lc "cd ~/pm3_cn2 && make -j4 client"

  # 重新翻译（修改翻译字典后）
  wsl -d Ubuntu bash -lc "cd ~/pm3_cn2 && python3 apply_all.py ~/pm3_cn2/client/src/ zh_trans_cn2.py build"

文档:
  Proxmark3-Complete-Tutorial.md  # 完整中文教程

"@
