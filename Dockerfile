FROM ubuntu:20.04
MAINTAINER Baoshuo <i@baoshuo.ren>
LABEL org.opencontainers.image.source=https://github.com/UniversalOJ/UOJ-System
LABEL org.opencontainers.image.description="UOJ Judger"
LABEL org.opencontainers.image.licenses=MIT

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ARG CLONE_ADDFLAG

RUN apt-get update && \
    apt-get install -y --no-install-recommends gnupg ca-certificates apt-transport-https && \
    apt-get update && \
    for pkg in git vim ntp zip unzip curl wget build-essential fp-compiler python python3 python3-requests openjdk-8-jdk openjdk-11-jdk tzdata; do \
        cnt=10 && \
        while ! apt-get install -y "$pkg"; do \
            if [ $cnt -le 0 ]; then \
              echo "Failed to install $pkg" && \
              exit 1; \
            fi; \
            cnt=$((cnt - 1)); \
        done; \
    done

# =========================================================
# Install Elan (Lean version manager)
# =========================================================
ENV ELAN_HOME="/usr/local/elan"
ENV PATH="$ELAN_HOME/bin:$PATH"

RUN curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh -s -- -y --default-toolchain none

# =========================================================
# Setup Lean 4.23.0 + Mathlib
# =========================================================
RUN mkdir -p /usr/lean/v4-23-0
WORKDIR /usr/lean/v4-23-0

RUN echo "leanprover/lean4:v4.23.0" > lean-toolchain

RUN cat > lakefile.toml << 'EOF'
name = "v4-23-0"
packagesDir = "/usr/lean/v4-23-0/.lake/packages"
version = "0.1.0"
defaultTargets = ["answer"]

[[require]]
name = "mathlib"
scope = "leanprover-community"
rev = "v4.23.0"

[[require]]
name = "Loom"
git = "https://github.com/verse-lab/loom"
rev = "v4.23.0"

[[require]]
name = "auto"
scope = "leanprover-community"
rev = "2c088e7617d6e2018386de23b5df3b127fae4634"

[[lean_lib]]
name = "Answer"

[[lean_exe]]
name = "answer"
root = "Answer"

EOF

RUN cat > Answer.lean << 'EOF'
import Mathlib
import Loom
import Auto.Tactic

def main : IO Unit := pure ()
EOF

# 下载依赖并构建
RUN lake exe cache get
RUN lake build


# 构建预编译静态库
RUN find .lake -name "*.c.o.export" \
    | grep -v "/build/ir/Answer" \
    | grep -v "Cache/Main" \
    | grep -v "Cache/Lean" > /tmp/objs.txt && \
    ar rcs libLeanDeps.a $(cat /tmp/objs.txt)

# 复制 Lean 编译脚本
COPY lean/v4-23-0/compile_lean.sh /usr/lean/v4-23-0/
COPY lean/v4-23-0/build_static_libs.sh /usr/lean/v4-23-0/
RUN chmod +x /usr/lean/v4-23-0/*.sh

# 生成 lean_path.txt（编译时需要）
RUN LEAN_PATH="" && \
    for pkg in /usr/lean/v4-23-0/.lake/packages/*/.lake/build/lib/lean; do \
      [ -d "$pkg" ] && LEAN_PATH="${LEAN_PATH:+$LEAN_PATH:}$pkg"; \
    done && \
    LEAN_PATH="${LEAN_PATH:+$LEAN_PATH:}/usr/lean/v4-23-0/.lake/build/lib/lean" && \
    echo "$LEAN_PATH" > lean_path.txt && \
    cat lean_path.txt | head -c 200

# =========================================================
# 复制 judger 代码并编译
# =========================================================
ADD . /opt/uoj_judger
WORKDIR /opt/uoj_judger

RUN sh install.sh -p && sh install.sh -d

ENV LANG=C.UTF-8 TZ=Asia/Shanghai
EXPOSE 2333
CMD /opt/up
