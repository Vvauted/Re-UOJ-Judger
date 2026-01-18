cmake_minimum_required(VERSION 3.14)
project(uoj_judger_tests)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Google Test
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

enable_testing()

# Security tests
add_executable(security_test security_test.cpp)
target_link_libraries(security_test GTest::gtest_main)
target_include_directories(security_test PRIVATE ../uoj_judger/include)

include(GoogleTest)
gtest_discover_tests(security_test)

