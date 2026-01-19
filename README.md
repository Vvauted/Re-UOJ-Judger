# UOJ New Judger

> 警告：本项目目前处于测试与代码审查阶段，**不建议将本项目的实现投入使用！**

基于现代 Linux 安全特性的 UOJ 评测机，使用 seccomp-bpf + cgroups v2 + namespaces 替代传统 ptrace 沙箱。

## 特性

- **沙箱**
  - seccomp-bpf 系统调用过滤（内核级拦截）
  - cgroups v2 资源限制（内存、CPU、进程数）
  - pivot_root + mount namespace 文件系统隔离
  
- **多语言支持**
  - C/C++ (98, 11, 14, 17, 20, 23)
  - Java (8, 11, 17, 21)
  - Python 2/3, PyPy3
  - Pascal, Rust, Go, Kotlin, Haskell, Ruby, D
  - Lean 4.23.0 + Mathlib
  
- **YAML 配置**: 语言与运行权限配置通过 YAML 文件定义，无需改代码
- **兼容 UOJ**: 与原 UOJ 评测协议完全兼容

### 性能

相比原来的 ptrace 沙箱，现在的沙箱方案节省了每次 Syscall（比如输入输出）都要切换父进程判断的开销，而把 Syscall 限制集成到了内核态

在 $10^6$ 个整数排序，50 个测试点的测试中，新 Judger 的代码运行时间减少了 ~10%，大部分提升都集中在输入输出中

新的沙箱设计单次启动仅需要 ~1ms，对比无沙箱环境运行单个测试点只多了 8ms，完全可以当做 eps

### 安全

通过类似 [google nsjail](https://github.com/google/nsjail) 的安全系统，限制了大部分程序运行的权限和资源

尽管 UOJ 开源的镜像是基于 docker 的，题目管理员仍能通过自定义 Judger 来影响机器的安全，而我们设计了 User 系统，现在的安全系统被分层为：

+ System - 无任何限制
+ Problem - 如自定义 Judger, checker 这样的题目配置文件
+ Compiler - 编译器
+ Submission - 用户代码

你可以通过 /config/user/ 的 YAML 文件修改或添加更多 User 以配置运行权限，每种语言也可以配置单独的 Compiler 和 Submission 的权限

### 配置

在 /config 文件夹下有沙箱 User 和语言的 YAML 配置，不需要像原 Judger 一样读上千行的代码添加新语言

## 快速开始

### 下载

下载或通过 `Dockerfile` 构建自己的镜像，因为支持了 `Lean4.23.0 with Mathlib` 所以空间会占的比较大，删除掉相关的内容就可以减小一些

### 配置

编辑 `docker-compose.yml`：

```yaml
environment:
  - UOJ_PROTOCOL=http
  - UOJ_HOST=your-uoj-server.com
  - JUDGER_NAME=judger1
  - JUDGER_PASSWORD=your_password
  - SOCKET_PORT=2333
  - SOCKET_PASSWORD=your_socket_password
```

### 启动

```bash
docker compose up -d
```

## 致谢

+ vfk 开源的 [UOJ](https://github.com/vfleaking/uoj) 和 [UOJ 社区版](https://github.com/UniversalOJ/UOJ-System)  以及它们的开发者

+ Google 开源的 [Nsjail](https://github.com/google/nsjail) 为本项目实现提供宝贵参考

## 许可证

MIT License
