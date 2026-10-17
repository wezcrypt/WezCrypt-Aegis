// WezCrypt Aegis - online update services.
//
// All fetches use CefURLRequest on the global request context: Chromium's
// certificate verification applies, no cookies or credentials are sent, and
// responses are size-capped while streaming. Nothing fetched here is ever
// executed: filter lists are data, and release manifests only inform the
// user (installers are downloaded through the normal, confirmed download
// flow and verified against the signed manifest).
#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "updates/update_verifier.h"

namespace aegis {

using FetchCallback = std::function<void(bool ok, int http_status, std::string body, std::string error)>;

// UI thread. Calls |done| on the UI thread.
void FetchHttps(const std::string& url, std::size_t max_bytes, FetchCallback done);

class UpdateService {
 public:
  // Refreshes filter lists that are stale (per their "! Expires:" header,
  // default 4 days) or all lists when |force| is true.
  static void RefreshFilterLists(bool force);

  // Checks the signed release manifest configured at build time.
  static void CheckForBrowserUpdate();

  // Verifies a completed download against the last verified manifest, if
  // its file name matches a release artifact. Returns false when it does
  // not correspond to any artifact; |matches| reports the result otherwise.
  static bool VerifyDownloadedArtifact(const std::string& file_path, const std::string& file_name,
                                       bool* matches);

  // Schedules periodic checks (UI thread).
  static void ScheduleBackgroundChecks();
};

// Parses an EasyList "Expires" value ("4 days", "12 hours") to seconds.
std::int64_t ParseExpiresSeconds(const std::string& value);

}  // namespace aegis
