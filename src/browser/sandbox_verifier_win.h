// WezCrypt Aegis - runtime verification of the Chromium sandbox (Windows).
//
// Starting the browser with a sandbox_info pointer only *requests* the
// sandbox. The verifier collects runtime evidence: it enumerates this
// browser's child processes, reads each one's "--type=" switch and the
// mandatory integrity level / AppContainer status of its primary token.
//
// Chromium launches sandboxed renderers with a restricted token at Low
// integrity and lowers them to Untrusted integrity once initialized. A
// renderer at Medium integrity or higher is not sandboxed; WezCrypt Aegis
// treats that as a fatal condition and fails closed.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aegis {

struct ChildProcessInfo {
  std::uint32_t pid = 0;
  std::string type;            // "renderer", "gpu-process", "utility", ...
  std::uint32_t integrity_rid = 0xFFFFFFFF;  // SECURITY_MANDATORY_*_RID
  bool token_queried = false;
  bool app_container = false;
  bool restricted_token = false;
};

struct SandboxReport {
  std::vector<ChildProcessInfo> children;
  int renderers = 0;
  int renderers_sandboxed = 0;    // integrity <= Low
  int renderers_unsandboxed = 0;  // integrity >= Medium
  int renderers_unknown = 0;      // token could not be queried
  std::string summary;
  std::string detail;
};

std::string IntegrityName(std::uint32_t rid);

// Inspects direct child processes of the current process.
SandboxReport InspectChildProcesses();

}  // namespace aegis
