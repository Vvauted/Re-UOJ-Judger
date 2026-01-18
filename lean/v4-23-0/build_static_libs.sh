#!/bin/bash
# 构建 Lean 依赖库的静态库（用于快速链接）
# 在 Dockerfile 构建阶段运行一次

set -e

LEAN_ENV="/usr/lean/v4-23-0"
cd "$LEAN_ENV"

echo "=== 构建 Lean 依赖静态库 (含 Mathlib) ==="

# 收集所有 .o 文件，排除：
# - Answer（用户代码占位）
# - Cache/Main（有 main 函数）
# - Cache/Lean（重复符号）
find .lake -name "*.c.o.export" \
    | grep -v "/build/ir/Answer" \
    | grep -v "Cache/Main" \
    | grep -v "Cache/Lean" > /tmp/lean_objs.txt

echo "共 $(wc -l < /tmp/lean_objs.txt) 个对象文件"

ar rcs libLeanDeps.a $(cat /tmp/lean_objs.txt)
ls -lh libLeanDeps.a

echo "=== 完成 ==="
