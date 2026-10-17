// WezCrypt Aegis - test runner.
//
// Usage: aegis_tests [--filter=substring] [--junit=report.xml] [--list]

#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <random>
#include <string>

#include "test_framework.h"

namespace aegis_test {
namespace {

struct Result {
  std::string suite;
  std::string name;
  bool passed = true;
  double seconds = 0;
  std::vector<std::string> failures;
};

Result* g_current = nullptr;
std::filesystem::path g_temp_root;
int g_temp_counter = 0;

std::string XmlEscape(const std::string& s) {
  std::string o;
  for (char c : s) {
    switch (c) {
      case '&': o += "&amp;"; break;
      case '<': o += "&lt;"; break;
      case '>': o += "&gt;"; break;
      case '"': o += "&quot;"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20 && c != '\n' && c != '\t') o += '?';
        else o += c;
    }
  }
  return o;
}

}  // namespace

std::vector<TestCase>& Registry() {
  static std::vector<TestCase>* r = new std::vector<TestCase>();
  return *r;
}

void ReportFailure(const char* file, int line, const std::string& message) {
  std::string msg = std::string(file) + ":" + std::to_string(line) + ": " + message;
  if (g_current) {
    g_current->passed = false;
    g_current->failures.push_back(msg);
  }
  std::cerr << "    FAIL " << msg << "\n";
}

bool CurrentTestFailed() { return g_current && !g_current->passed; }

std::filesystem::path SourceDir() { return std::filesystem::path(AEGIS_SOURCE_DIR); }

std::filesystem::path TempDir() {
  std::filesystem::path p = g_temp_root / ("t" + std::to_string(++g_temp_counter));
  std::error_code ec;
  std::filesystem::remove_all(p, ec);
  std::filesystem::create_directories(p);
  return p;
}

}  // namespace aegis_test

int main(int argc, char** argv) {
  using namespace aegis_test;
  std::string filter;
  std::string junit;
  bool list = false;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a.rfind("--filter=", 0) == 0) filter = a.substr(9);
    else if (a.rfind("--junit=", 0) == 0) junit = a.substr(8);
    else if (a == "--list") list = true;
    else if (a == "--help" || a == "-h") {
      std::cout << "aegis_tests [--filter=substring] [--junit=report.xml] [--list]\n";
      return 0;
    } else {
      std::cerr << "unknown argument: " << a << "\n";
      return 2;
    }
  }

  std::random_device rd;
  g_temp_root = std::filesystem::temp_directory_path() /
                ("aegis-tests-" + std::to_string(rd()) + std::to_string(rd()));
  std::filesystem::create_directories(g_temp_root);

  std::vector<Result> results;
  auto start_all = std::chrono::steady_clock::now();
  for (const TestCase& tc : Registry()) {
    std::string full = tc.suite + "." + tc.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) continue;
    if (list) {
      std::cout << full << "\n";
      continue;
    }
    Result r;
    r.suite = tc.suite;
    r.name = tc.name;
    g_current = &r;
    std::cout << "[ RUN      ] " << full << std::endl;
    auto t0 = std::chrono::steady_clock::now();
    try {
      tc.fn();
    } catch (const std::exception& e) {
      ReportFailure(__FILE__, __LINE__, std::string("uncaught exception: ") + e.what());
    } catch (...) {
      ReportFailure(__FILE__, __LINE__, "uncaught non-standard exception");
    }
    r.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::cout << (r.passed ? "[       OK ] " : "[  FAILED  ] ") << full << " ("
              << static_cast<long>(r.seconds * 1000) << " ms)" << std::endl;
    g_current = nullptr;
    results.push_back(std::move(r));
  }
  if (list) return 0;
  double total = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_all).count();

  int failed = 0;
  for (const auto& r : results) failed += r.passed ? 0 : 1;
  std::cout << "\n" << results.size() << " tests, " << (results.size() - failed) << " passed, "
            << failed << " failed (" << static_cast<long>(total * 1000) << " ms)\n";
  for (const auto& r : results) {
    if (!r.passed) std::cout << "  FAILED: " << r.suite << "." << r.name << "\n";
  }

  if (!junit.empty()) {
    std::ofstream out(junit, std::ios::binary);
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<testsuites name=\"aegis\" tests=\"" << results.size() << "\" failures=\"" << failed
        << "\" time=\"" << total << "\">\n";
    out << "<testsuite name=\"aegis\" tests=\"" << results.size() << "\" failures=\"" << failed
        << "\">\n";
    for (const auto& r : results) {
      out << "  <testcase classname=\"" << XmlEscape(r.suite) << "\" name=\"" << XmlEscape(r.name)
          << "\" time=\"" << r.seconds << "\">";
      for (const auto& f : r.failures) {
        out << "<failure message=\"" << XmlEscape(f) << "\"/>";
      }
      out << "</testcase>\n";
    }
    out << "</testsuite>\n</testsuites>\n";
  }
  std::error_code ec;
  std::filesystem::remove_all(g_temp_root, ec);
  return failed == 0 && !results.empty() ? 0 : 1;
}
