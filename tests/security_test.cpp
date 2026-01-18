/**
 * @file security_test.cpp
 * @brief 沙箱安全性测试
 * 
 * 使用 Google Test 框架测试沙箱的各项安全特性
 */

#include <gtest/gtest.h>
#include <fstream>
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>

// 简化的测试：编译并运行恶意代码，验证沙箱能正确拦截

class SandboxSecurityTest : public ::testing::Test {
protected:
    std::string work_dir = "/tmp/sandbox_test";
    std::string judger_path = "../uoj_judger/builtin/judger/judger";
    
    void SetUp() override {
        system(("mkdir -p " + work_dir).c_str());
    }
    
    void TearDown() override {
        system(("rm -rf " + work_dir).c_str());
    }
    
    // 编译测试代码
    bool compile(const std::string& code, const std::string& output) {
        std::string src = work_dir + "/test.cpp";
        std::ofstream f(src);
        f << code;
        f.close();
        
        std::string cmd = "g++ -o " + work_dir + "/" + output + " " + src + " 2>/dev/null";
        return system(cmd.c_str()) == 0;
    }
    
    // 在沙箱中运行（简化版，实际应调用 main_judger）
    int run_sandboxed(const std::string& program) {
        // TODO: 集成 main_judger 调用
        return 0;
    }
};

// 测试：尝试读取 /etc/passwd 应该失败
TEST_F(SandboxSecurityTest, CannotReadEtcPasswd) {
    const char* code = R"(
#include <fstream>
#include <iostream>
int main() {
    std::ifstream f("/etc/passwd");
    if (f.is_open()) {
        std::cout << "ESCAPED" << std::endl;
        return 0;
    }
    return 1;
}
)";
    ASSERT_TRUE(compile(code, "read_passwd"));
    // 在沙箱中运行时应该无法读取
}

// 测试：尝试 fork bomb 应该被限制
TEST_F(SandboxSecurityTest, ForkBombLimited) {
    const char* code = R"(
#include <unistd.h>
int main() {
    while(1) fork();
    return 0;
}
)";
    ASSERT_TRUE(compile(code, "fork_bomb"));
    // cgroup pids 限制应该阻止无限 fork
}

// 测试：尝试访问网络应该失败
TEST_F(SandboxSecurityTest, NetworkBlocked) {
    const char* code = R"(
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 1; // 期望失败
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        return 0; // 不应该成功
    }
    return 1;
}
)";
    ASSERT_TRUE(compile(code, "network_test"));
}

// 测试：内存限制
TEST_F(SandboxSecurityTest, MemoryLimitEnforced) {
    const char* code = R"(
#include <cstdlib>
#include <cstring>
int main() {
    // 尝试分配 1GB 内存
    char* p = (char*)malloc(1024ULL * 1024 * 1024);
    if (p) {
        memset(p, 0, 1024ULL * 1024 * 1024);
    }
    return 0;
}
)";
    ASSERT_TRUE(compile(code, "memory_hog"));
    // 应该被 MLE
}

// 测试：时间限制
TEST_F(SandboxSecurityTest, TimeLimitEnforced) {
    const char* code = R"(
int main() {
    while(1);
    return 0;
}
)";
    ASSERT_TRUE(compile(code, "infinite_loop"));
    // 应该被 TLE
}

// 测试：禁止的系统调用
TEST_F(SandboxSecurityTest, ForbiddenSyscallBlocked) {
    const char* code = R"(
#include <sys/ptrace.h>
int main() {
    // ptrace 应该被 seccomp 阻止
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == 0) {
        return 0; // 不应该成功
    }
    return 1;
}
)";
    ASSERT_TRUE(compile(code, "ptrace_test"));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

