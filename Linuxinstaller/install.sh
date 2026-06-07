#!/usr/bin/env bash
# Proxmark3 FullCN v4.21611 - Linux 一键安装脚本
# 用法: bash install.sh [--skip-build]

set -euo pipefail

SKIP_BUILD=false
DRY_RUN=false

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --dry-run) DRY_RUN=true ;;
        -h|--help)
            echo "用法: bash install.sh [--skip-build] [--dry-run]"
            echo "  --skip-build  跳过编译，仅使用预编译二进制"
            echo "  --dry-run     检查环境但不实际执行"
            exit 0
            ;;
    esac
done

PACKAGE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PM3_DIR="$HOME/pm3_cn2"

echo ""
echo "============================================"
echo " Proxmark3 FullCN v4.21611 安装程序 (Linux)"
echo "============================================"
echo " 包目录: $PACKAGE_ROOT"
echo " 安装目标: $PM3_DIR"
echo ""

run() {
    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY-RUN] $*"
    else
        eval "$@"
    fi
}

# === 1. 检测发行版并安装依赖 ===
echo "[1/5] 检测发行版并安装编译依赖..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
else
    echo "  [ERR] 无法检测发行版"
    exit 1
fi

case "$DISTRO" in
    ubuntu|debian|linuxmint|pop)
        echo "  检测到: $DISTRO (apt)"
        if [ "$SKIP_BUILD" = false ]; then
            run "sudo apt-get update -qq"
            run "sudo apt-get install -y -qq git build-essential pkg-config libreadline-dev \
                gcc-arm-none-eabi libnewlib-dev qtbase5-dev libbz2-dev liblz4-dev \
                libbluetooth-dev libpython3-dev libssl-dev"
        fi
        ;;
    fedora|rhel|centos|rocky)
        echo "  检测到: $DISTRO (dnf/yum)"
        if [ "$SKIP_BUILD" = false ]; then
            run "sudo dnf install -y git make gcc gcc-c++ readline-devel \
                arm-none-eabi-gcc-cs newlib-devel qt5-qtbase-devel bzip2-devel \
                lz4-devel bluez-libs-devel python3-devel openssl-devel"
        fi
        ;;
    arch|manjaro)
        echo "  检测到: $DISTRO (pacman)"
        if [ "$SKIP_BUILD" = false ]; then
            run "sudo pacman -S --noconfirm git base-devel readline \
                arm-none-eabi-gcc arm-none-eabi-newlib qt5-base bzip2 lz4 \
                bluez-libs python openssl"
        fi
        ;;
    *)
        echo "  [WARN] 未知发行版: $DISTRO"
        echo "  请手动安装以下依赖后带 --skip-build 重新运行:"
        echo "    git, gcc, make, readline-dev, qt5-dev, bzip2, lz4, python3-dev, openssl-dev"
        echo "    ARM 交叉编译器 (arm-none-eabi-gcc) 可选 — 不编译固件可省略"
        ;;
esac
echo "  [OK] 依赖安装完成"

# === 2. 安装 udev 规则 ===
echo "[2/6] 安装 udev 规则..."
if [ -d "$PACKAGE_ROOT/driver" ]; then
    run "sudo cp '$PACKAGE_ROOT/driver/'77-pm3-*.rules /etc/udev/rules.d/"
    run "sudo udevadm control --reload-rules"
    run "sudo udevadm trigger"
    # 禁用 ModemManager (可选)
    if systemctl is-active --quiet ModemManager 2>/dev/null; then
        echo "  检测到 ModemManager 在运行，正在禁用..."
        run "sudo systemctl stop ModemManager"
        run "sudo systemctl disable ModemManager"
    fi
    echo "  [OK] udev 规则已安装"
else
    echo "  [WARN] driver/ 目录不存在，跳过 udev 配置"
fi

# === 3. 复制源码 ===
echo "[3/6] 复制源码..."
if [ -d "$PACKAGE_ROOT/src" ]; then
    run "rm -rf $PM3_DIR"
    run "mkdir -p $PM3_DIR"
    run "cp -r '$PACKAGE_ROOT/src/'* $PM3_DIR/"
    echo "  [OK] 源码已复制到 $PM3_DIR"
else
    echo "  [ERR] src/ 目录不存在！请确保完整解压发布包"
    exit 1
fi

# === 4. 编译客户端 ===
echo "[4/6] 编译客户端..."
if [ "$SKIP_BUILD" = false ]; then
    run "cd $PM3_DIR && make -j\$(nproc) client"
    if [ -f "$PM3_DIR/client/proxmark3" ]; then
        echo "  [OK] 编译完成: $(ls -lh $PM3_DIR/client/proxmark3 | awk '{print $5}')"
    else
        echo "  [ERR] 编译失败，查看上方日志"
        exit 1
    fi
else
    echo "  [SKIP] --skip-build 已设置"
fi

# === 5. 安装预编译中文二进制 ===
echo "[5/6] 安装中文二进制..."
CN2_BIN="$PACKAGE_ROOT/client/proxmark3_cn2"
if [ -f "$CN2_BIN" ]; then
    run "cp -f '$CN2_BIN' $PM3_DIR/client/proxmark3"
    run "chmod +x $PM3_DIR/client/proxmark3"
    echo "  [OK] 中文二进制已安装"
else
    echo "  [WARN] client/proxmark3_cn2 不存在，将使用编译产物"
fi

# === 6. 安装 pm3 启动脚本 ===
echo "[6/6] 安装 pm3 命令..."
PM3_WRAPPER="$HOME/.local/bin/pm3"
run "mkdir -p $HOME/.local/bin"

cat > /tmp/pm3_wrapper << 'PM3EOF'
#!/usr/bin/env bash
# Proxmark3 FullCN 启动包装器
# 用法: pm3 [-cn2] [-c "命令"]
#
# 自动检测 USB 设备 (/dev/ttyACM*)

CLIENT="$HOME/pm3_cn2/client/proxmark3"
CN2_CLIENT="$HOME/pm3_cn2/client/proxmark3"  # CN2 客户端（同一二进制）
# 如需区分，可设置 CN2_CLIENT 为不同路径

TTY=""
for dev in /dev/ttyACM*; do
    if [ -e "$dev" ]; then TTY="$dev"; break; fi
done
if [ -z "$TTY" ]; then
    echo "[!] 未找到 Proxmark3 (/dev/ttyACM*)"
    echo "    请检查 USB 连接"
    exit 1
fi

export QT_QPA_PLATFORM=offscreen
export QT_LOGGING_RULES='*=false'

if [ "$1" = "-cn2" ]; then
    shift
    CLIENT="$CN2_CLIENT"
fi

if [ "$1" = "-c" ] && [ -n "$2" ]; then
    exec "$CLIENT" "$TTY" -c "$2"
else
    exec "$CLIENT" "$TTY" "$@"
fi
PM3EOF

run "cp /tmp/pm3_wrapper $HOME/.local/bin/pm3"
run "chmod +x $HOME/.local/bin/pm3"

# 检查 PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    echo "  [OK] ~/.local/bin 已添加到 PATH（新终端生效）"
else
    echo "  [OK] ~/.local/bin 已在 PATH 中"
fi

echo ""
echo "============================================"
echo " 安装完成！"
echo "============================================"
echo ""
echo " 使用方法:"
echo "   pm3                    英文交互模式"
echo "   pm3 -cn2               全中文交互模式"
echo "   pm3 -c \"hw version\"    单条命令"
echo ""
echo " 重新编译:"
echo "   cd ~/pm3_cn2 && make -j\$(nproc) client"
echo ""
echo " 重新翻译:"
echo "   cd ~/pm3_cn2 && python3 apply_all.py client/src/ zh_trans_cn2.py build"
echo ""

run "rm -f /tmp/pm3_wrapper"
