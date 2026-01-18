#!/bin/bash
set -e

WORK_PATH="${1:-.}"
LEAN_ENV="/usr/lean/v4-23-0"
TOOLCHAIN="/usr/local/elan/toolchains/leanprover--lean4---v4.23.0"

export LEAN_PATH="$(cat $LEAN_ENV/lean_path.txt 2>/dev/null || echo "")"
export ELAN_HOME="/usr/local/elan"
export PATH="/usr/local/elan/bin:/usr/bin:/bin"
export HOME="/tmp"
export LD_LIBRARY_PATH="$TOOLCHAIN/lib/lean:$TOOLCHAIN/lib:$LD_LIBRARY_PATH"

cd "$WORK_PATH"
rm -f answer answer.c answer.o answer.olean answer.ilean

# 1. 编译 Lean -> C
$TOOLCHAIN/bin/lean answer.code -c answer.c

# 2. 编译 C -> O
$TOOLCHAIN/bin/clang -c -o answer.o answer.c \
    -I $TOOLCHAIN/include \
    -fstack-clash-protection -fwrapv -fPIC -fvisibility=hidden \
    -Wno-unused-command-line-argument \
    --sysroot $TOOLCHAIN \
    -nostdinc -isystem $TOOLCHAIN/include/clang \
    -O3 -DNDEBUG -DLEAN_EXPORTING

# 3. 链接（使用预编译的静态库，含 Mathlib）
$TOOLCHAIN/bin/clang -o answer \
    answer.o \
    -L $LEAN_ENV -lLeanDeps \
    -L $TOOLCHAIN/lib/lean --sysroot $TOOLCHAIN \
    -L $TOOLCHAIN/lib -L $TOOLCHAIN/lib/glibc \
    -lc -lc_nonshared \
    -Wl,--as-needed -l:ld.so -Wl,--no-as-needed \
    -lpthread_nonshared -Wl,--as-needed \
    -Wl,-Bstatic -lgmp -lunwind -luv -Wl,-Bdynamic \
    -Wl,--no-as-needed -fuse-ld=lld \
    -Wl,--start-group -lleancpp -lLean -Wl,--end-group \
    -lStd \
    -Wl,--start-group -lInit -lleanrt -Wl,--end-group \
    -Wl,-Bstatic -lc++ -lc++abi -Wl,-Bdynamic \
    -lLake \
    -Wl,--as-needed -lgmp -luv -lpthread -ldl -lrt -Wl,--no-as-needed \
    -lm -ldl -pthread

rm -f answer.c answer.o
