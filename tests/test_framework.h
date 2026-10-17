// WezCrypt Aegis - minimal self-contained test framework.
//
// Tests register themselves with TEST(Suite, Name). The runner executes all
// tests (or a --filter substring), prints a summary, and can emit a JUnit
// XML report (--junit=path) consumed by CI.
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace aegis_test {

struct TestCase {
  std::string suite;
  std::string name;
  std::function<void()> fn;
};

std::vector<TestCase>& Registry();

struct Registrar {
  Registrar(const char* suite, const char* name, std::function<void()> fn) {
    Registry().push_back({suite, name, std::move(fn)});
  }
};

// Records a failure for the currently running test.
void ReportFailure(const char* file, int line, const std::string& message);
bool CurrentTestFailed();

// Directory containing repository assets (filter lists, PSL).
std::filesystem::path SourceDir();
// Fresh, empty temporary directory unique to the current test.
std::filesystem::path TempDir();

template <typename T>
std::string ToDebugString(const T& v) {
  std::ostringstream os;
  if constexpr (std::is_same_v<T, bool>) {
    os << (v ? "true" : "false");
  } else if constexpr (std::is_enum_v<T>) {
    os << static_cast<long long>(v);
  } else if constexpr (requires(std::ostream& o, const T& x) { o << x; }) {
    os << v;
  } else {
    os << "<value>";
  }
  return os.str();
}

}  // namespace aegis_test

#define AEGIS_CONCAT2(a, b) a##b
#define AEGIS_CONCAT(a, b) AEGIS_CONCAT2(a, b)

#define TEST(suite, name)                                                         \
  static void suite##_##name##_impl();                                            \
  static ::aegis_test::Registrar AEGIS_CONCAT(reg_, AEGIS_CONCAT(suite, name))(   \
      #suite, #name, &suite##_##name##_impl);                                     \
  static void suite##_##name##_impl()

#define EXPECT_TRUE(cond)                                                         \
  do {                                                                            \
    if (!(cond)) ::aegis_test::ReportFailure(__FILE__, __LINE__, "expected true: " #cond); \
  } while (0)

#define EXPECT_FALSE(cond)                                                        \
  do {                                                                            \
    if (cond) ::aegis_test::ReportFailure(__FILE__, __LINE__, "expected false: " #cond); \
  } while (0)

#define EXPECT_EQ(a, b)                                                           \
  do {                                                                            \
    const auto _va = (a);                                                        \
    const auto _vb = (b);                                                        \
    if (!(_va == _vb))                                                            \
      ::aegis_test::ReportFailure(__FILE__, __LINE__,                             \
                                  std::string("expected " #a " == " #b ": got '") + \
                                      ::aegis_test::ToDebugString(_va) + "' vs '" + \
                                      ::aegis_test::ToDebugString(_vb) + "'");    \
  } while (0)

#define EXPECT_NE(a, b)                                                           \
  do {                                                                            \
    const auto _va = (a);                                                        \
    const auto _vb = (b);                                                        \
    if (_va == _vb)                                                               \
      ::aegis_test::ReportFailure(__FILE__, __LINE__,                             \
                                  std::string("expected " #a " != " #b ": both '") + \
                                      ::aegis_test::ToDebugString(_va) + "'");    \
  } while (0)

#define ASSERT_TRUE(cond)                                                         \
  do {                                                                            \
    if (!(cond)) {                                                                \
      ::aegis_test::ReportFailure(__FILE__, __LINE__, "assertion failed: " #cond); \
      return;                                                                     \
    }                                                                             \
  } while (0)
