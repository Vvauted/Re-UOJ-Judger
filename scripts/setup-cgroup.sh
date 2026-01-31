#!/bin/bash
#
# UOJ Judger cgroup 设置脚本
#
# 用途：
# 1. 在有 systemd 的系统上安装 uoj.slice
# 2. 在无 systemd 的系统上手动创建 cgroup 结构
#
# 使用方法：sudo ./setup-cgroup.sh

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then
    error "请使用 root 权限运行此脚本"
fi

# 检查 cgroup v2
if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
    error "系统未使用 cgroup v2。请确保内核支持并启用 cgroup v2。"
fi

info "检测到 cgroup v2 环境"

# 检查是否有 systemd
if [ -d /run/systemd/system ]; then
    info "检测到 systemd，安装 uoj.slice..."
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SLICE_SRC="$SCRIPT_DIR/../systemd/uoj.slice"
    
    if [ -f "$SLICE_SRC" ]; then
        cp "$SLICE_SRC" /etc/systemd/system/uoj.slice
        systemctl daemon-reload
        systemctl enable uoj.slice
        info "uoj.slice 已安装并启用"
    else
        warn "找不到 uoj.slice 文件: $SLICE_SRC"
        warn "请手动创建 /etc/systemd/system/uoj.slice"
    fi
    
    info ""
    info "使用方法："
    info "  judge_client 会自动使用 systemd-run --slice=uoj 启动评测机"
    info "  查看状态：systemctl status uoj.slice"
    info "  查看 cgroup：systemd-cgls /uoj.slice"
    
else
    info "未检测到 systemd，手动创建 cgroup 结构..."
    
    # 创建 uoj cgroup
    CGROUP_PATH="/sys/fs/cgroup/uoj"
    
    if [ -d "$CGROUP_PATH" ]; then
        warn "cgroup 路径已存在: $CGROUP_PATH"
    else
        mkdir -p "$CGROUP_PATH"
        info "创建 cgroup: $CGROUP_PATH"
    fi
    
    # 启用控制器
    echo "+memory +cpu +pids +io" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
    
    # 创建子 cgroup
    mkdir -p "$CGROUP_PATH/judger"
    mkdir -p "$CGROUP_PATH/sandbox"
    
    # 启用 sandbox 的子控制器
    echo "+memory +cpu +pids +io" > "$CGROUP_PATH/cgroup.subtree_control" 2>/dev/null || true
    echo "+memory +cpu +pids +io" > "$CGROUP_PATH/sandbox/cgroup.subtree_control" 2>/dev/null || true
    
    info "cgroup 结构已创建："
    info "  $CGROUP_PATH/"
    info "  ├── judger/    (main_judger 进程)"
    info "  └── sandbox/   (沙箱进程)"
    
    info ""
    info "注意：在无 systemd 环境中，main_judger 会自动检测并使用此结构"
    info "      或在 /proc/self/cgroup 指向的路径下创建子 cgroup"
fi

info ""
info "cgroup 设置完成！"

