INCLUDE_PATH = include
CXXFLAGS = -I./include -O2 -std=c++17

# 只包含存在源文件的 checker
EXE_CHECKER = \
	builtin/checker/acmp \
	builtin/checker/bcmp \
	builtin/checker/caseicmp \
	builtin/checker/casencmp \
	builtin/checker/casewcmp \
	builtin/checker/dcmp \
	builtin/checker/fcmp \
	builtin/checker/hcmp \
	builtin/checker/icmp \
	builtin/checker/lcmp \
	builtin/checker/ncmp \
	builtin/checker/rncmp \
	builtin/checker/uncmp \
	builtin/checker/wcmp \
	builtin/checker/yesno

# 可执行文件
EXE = main_judger builtin/judger/judger

# 默认目标
all: $(EXE) $(EXE_CHECKER)

# Checker
checker: $(EXE_CHECKER)

#==============================================================================
# 编译规则 (使用现代沙箱: seccomp-bpf + cgroups v2)
#==============================================================================

# main_judger: 入口程序，选择并调用 judger
main_judger: main_judger.cpp include/uoj_judger_new.h include/core/*.h include/sandbox/*.h
	$(CXX) $(CXXFLAGS) $< -o $@

# builtin/judger/judger: 内置评测器
builtin/judger/judger: builtin/judger/judger.cpp include/uoj_judger_new.h include/core/*.h include/sandbox/*.h
	$(CXX) $(CXXFLAGS) $< -o $@

#==============================================================================
# Checker 编译规则
#==============================================================================

$(EXE_CHECKER): include/testlib.h
	$(CXX) $(CXXFLAGS) $@.cpp -o $@

#==============================================================================
# 清理
#==============================================================================

clean:
	rm -f $(EXE) $(EXE_CHECKER)

.PHONY: all checker clean
