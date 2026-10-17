#include "browser/scheme_handler.h"

#include <algorithm>
#include <cstring>

#include "aegis_build_info.h"
#include "browser/aegis_context.h"
#include "common/strings.h"
#include "common/utf8.h"
#include "include/base/cef_callback.h"
#include "include/cef_parser.h"
#include "include/cef_resource_handler.h"
#include "include/cef_version.h"
#include "include/wrapper/cef_closure_task.h"
#include "include/wrapper/cef_helpers.h"
#include "ui/omnibox.h"

namespace aegis {
namespace {

struct PageResult {
  int status = 200;
  std::string html;
};

std::string ChromiumVersion() {
  return std::to_string(CHROME_VERSION_MAJOR) + "." + std::to_string(CHROME_VERSION_MINOR) + "." +
         std::to_string(CHROME_VERSION_BUILD) + "." + std::to_string(CHROME_VERSION_PATCH);
}

json::Value TokenPayload(AegisContext* ctx, const std::string& query) {
  std::string payload;
  if (!ctx->ConsumeActionToken(QueryParam(query, "t"), &payload)) return json::Value();
  auto v = json::Parse(payload);
  return v ? *v : json::Value();
}

// Builds the page on the UI thread, where settings are owned.
PageResult BuildPage(const std::string& url, bool private_window) {
  CEF_REQUIRE_UI_THREAD();
  PageResult r;
  auto* ctx = AegisContext::Get();
  auto u = ParseUrl(url);
  if (!ctx || !u) {
    r.status = 404;
    r.html = pages::NotFoundPage(url);
    return r;
  }
  const std::string& host = u->host;
  const std::string& q = u->query;
  if (host == "newtab") {
    std::uint64_t blocked = 0;
    for (int i = 0; i < static_cast<int>(EventCategory::kCount); ++i) {
      if (i == static_cast<int>(EventCategory::kHttpsUpgrade)) continue;
      blocked += ctx->events().SessionCount(static_cast<EventCategory>(i));
    }
    r.html = pages::NewTabPage(ctx->settings().mode, blocked, private_window);
  } else if (host == "security") {
    r.html = pages::DashboardPage(ctx->BuildDashboard(private_window));
  } else if (host == "site-report") {
    std::string target = QueryParam(q, "url");
    if (target.empty()) target = "https://" + QueryParam(q, "site") + "/";
    r.html = pages::SiteReportPage(ctx->BuildSiteReport(target, private_window));
  } else if (host == "network") {
    auto events = ctx->events().Recent(500);
    r.html = pages::NetworkActivityPage(events, events.size());
  } else if (host == "history") {
    std::string query = QueryParam(q, "q");
    auto entries = query.empty() ? ctx->history().Recent(500) : ctx->history().Search(query, 500);
    r.html = pages::HistoryPage(entries, query, ctx->settings().save_history);
  } else if (host == "bookmarks") {
    r.html = pages::BookmarksPage(ctx->bookmarks().All());
  } else if (host == "downloads") {
    std::vector<pages::DownloadRow> rows;
    for (const auto& d : ctx->Downloads()) {
      rows.push_back({d.filename, d.url, d.state, std::string(FileRiskLabel(d.risk)), d.path, d.percent});
    }
    r.html = pages::DownloadsPage(rows, WideToUtf8(ctx->DefaultDownloadDirectory().wstring()));
  } else if (host == "blocked") {
    json::Value v = TokenPayload(ctx, q);
    if (!v.is_object()) {
      r.html = pages::BlockedNavigationPage("(unknown)", "This blocked-page link has expired.", {}, {});
    } else {
      r.html = pages::BlockedNavigationPage(v.GetString("url"), v.GetString("reason"),
                                            v.GetString("rule"), v.GetString("list"));
    }
  } else if (host == "cert-error") {
    json::Value v = TokenPayload(ctx, q);
    r.html = pages::CertificateErrorPage(v.GetString("url", "(unknown)"), v.GetString("error"),
                                         static_cast<int>(v.GetInt("code", 0)));
  } else if (host == "https-fallback") {
    json::Value v = TokenPayload(ctx, q);
    if (!v.is_object()) {
      r.html = pages::LoadErrorPage(url, "This page has expired.", 0);
    } else {
      std::string http_url = v.GetString("http_url");
      std::string continue_token = ctx->IssueActionToken(
          json::Serialize(json::Value(json::Object{{"action", "http-continue"}, {"http_url", http_url}}), -1));
      r.html = pages::HttpsFallbackPage(v.GetString("https_url"), http_url,
                                        "aegis://https-fallback/continue?t=" + continue_token,
                                        v.GetString("error"));
    }
  } else if (host == "load-error") {
    json::Value v = TokenPayload(ctx, q);
    r.html = pages::LoadErrorPage(v.GetString("url", "(unknown)"), v.GetString("error"),
                                  static_cast<int>(v.GetInt("code", 0)));
  } else if (host == "about") {
    r.html = pages::AboutPage(std::string(AEGIS_VERSION_STRING) + " (" + AEGIS_GIT_REVISION + ")",
                              CEF_VERSION, ChromiumVersion(),
                              {{"Chromium Embedded Framework", "BSD-3-Clause"},
                               {"Chromium", "BSD-3-Clause and others (see credits in CEF distribution)"},
                               {"Monocypher 4.0.2", "BSD-2-Clause or CC0-1.0"},
                               {"Public Suffix List", "MPL-2.0"},
                               {"EasyList / EasyPrivacy", "GPLv3 or CC BY-SA 3.0"}});
  } else if (host == "blocked-resource") {
    r.status = 403;
    r.html.clear();
  } else {
    r.status = 404;
    r.html = pages::NotFoundPage(url);
  }
  return r;
}

class InternalPageHandler : public CefResourceHandler {
 public:
  InternalPageHandler(std::string url, bool private_window)
      : url_(std::move(url)), private_window_(private_window) {}

  bool Open(CefRefPtr<CefRequest> request, bool& handle_request,
            CefRefPtr<CefCallback> callback) override {
    (void)request;
    handle_request = false;
    CefRefPtr<InternalPageHandler> self(this);
    CefPostTask(TID_UI, base::BindOnce(
                            [](CefRefPtr<InternalPageHandler> h, CefRefPtr<CefCallback> cb) {
                              PageResult p = BuildPage(h->url_, h->private_window_);
                              h->status_ = p.status;
                              h->data_ = std::move(p.html);
                              h->ready_ = true;
                              cb->Continue();
                            },
                            self, callback));
    return true;
  }

  void GetResponseHeaders(CefRefPtr<CefResponse> response, int64_t& response_length,
                          CefString& redirect_url) override {
    (void)redirect_url;
    response->SetStatus(ready_ ? status_ : 500);
    response->SetMimeType(status_ == 403 ? "text/plain" : "text/html");
    response->SetCharset("utf-8");
    CefResponse::HeaderMap headers;
    headers.emplace("Content-Security-Policy", std::string(pages::InternalPageCsp()));
    headers.emplace("X-Content-Type-Options", "nosniff");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Referrer-Policy", "no-referrer");
    headers.emplace("Cache-Control", "no-store");
    headers.emplace("Cross-Origin-Opener-Policy", "same-origin");
    headers.emplace("Cross-Origin-Resource-Policy", "same-origin");
    response->SetHeaderMap(headers);
    response_length = static_cast<int64_t>(data_.size());
  }

  bool Read(void* data_out, int bytes_to_read, int& bytes_read,
            CefRefPtr<CefResourceReadCallback> callback) override {
    (void)callback;
    bytes_read = 0;
    if (offset_ >= data_.size()) return false;
    std::size_t n = std::min<std::size_t>(static_cast<std::size_t>(bytes_to_read), data_.size() - offset_);
    std::memcpy(data_out, data_.data() + offset_, n);
    offset_ += n;
    bytes_read = static_cast<int>(n);
    return true;
  }

  void Cancel() override {}

 private:
  std::string url_;
  bool private_window_;
  bool ready_ = false;
  int status_ = 500;
  std::string data_;
  std::size_t offset_ = 0;
  IMPLEMENT_REFCOUNTING(InternalPageHandler);
};

class InternalSchemeFactory : public CefSchemeHandlerFactory {
 public:
  CefRefPtr<CefResourceHandler> Create(CefRefPtr<CefBrowser> browser, CefRefPtr<CefFrame> frame,
                                       const CefString& scheme_name,
                                       CefRefPtr<CefRequest> request) override {
    (void)scheme_name;
    // Internal pages render only as top-level documents of a browser.
    if (!browser || !frame || !frame->IsMain()) {
      return new InternalPageHandler(kBlockedResourceUrl, false);
    }
    bool priv = false;
    if (auto* ctx = AegisContext::Get()) {
      priv = ctx->IsPrivateContext(browser->GetHost()->GetRequestContext());
    }
    return new InternalPageHandler(request->GetURL().ToString(), priv);
  }

 private:
  IMPLEMENT_REFCOUNTING(InternalSchemeFactory);
};

}  // namespace

int InternalSchemeOptions() {
  return CEF_SCHEME_OPTION_STANDARD | CEF_SCHEME_OPTION_SECURE |
         CEF_SCHEME_OPTION_DISPLAY_ISOLATED;
}

void RegisterInternalSchemeHandler(CefRefPtr<CefRequestContext> ctx) {
  CefRefPtr<CefSchemeHandlerFactory> factory = new InternalSchemeFactory();
  if (ctx) {
    ctx->RegisterSchemeHandlerFactory(kInternalScheme, CefString(), factory);
  } else {
    CefRegisterSchemeHandlerFactory(kInternalScheme, CefString(), factory);
  }
}

}  // namespace aegis
