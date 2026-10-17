#include "ui/browser_window.h"

#include <windows.h>
#include <shellapi.h>

#include <algorithm>

#include "browser/aegis_context.h"
#include "browser/request_handlers.h"
#include "browser/update_service.h"
#include "common/idna.h"
#include "common/strings.h"
#include "common/utf8.h"
#include "filtering/filter_rule.h"
#include "include/base/cef_callback.h"
#include "include/cef_app.h"
#include "include/cef_color_ids.h"
#include "include/views/cef_box_layout.h"
#include "include/wrapper/cef_closure_task.h"
#include "include/wrapper/cef_helpers.h"
#include "storage/atomic_file.h"
#include "ui/omnibox.h"
#include "ui/prompt_window.h"
#include "ui/theme.h"

namespace aegis {
namespace {

// View IDs.
enum ViewId : int {
  kIdNewTab = 1,
  kIdBack,
  kIdForward,
  kIdReload,
  kIdHome,
  kIdSite,
  kIdAddress,
  kIdBookmark,
  kIdShield,
  kIdMode,
  kIdMenu,
  kIdFindField,
  kIdFindPrev,
  kIdFindNext,
  kIdFindClose,
  kIdTabButtonBase = 100000,
  kIdTabCloseBase = 200000,
};

// Command IDs (menus and accelerators).
enum Command : int {
  kCmdNewTab = 1000,
  kCmdCloseTab,
  kCmdReopenTab,
  kCmdNewWindow,
  kCmdNewPrivateWindow,
  kCmdFocusAddress,
  kCmdReload,
  kCmdHardReload,
  kCmdStop,
  kCmdBack,
  kCmdForward,
  kCmdHome,
  kCmdFind,
  kCmdFindNext,
  kCmdFindPrev,
  kCmdNextTab,
  kCmdPrevTab,
  kCmdZoomIn,
  kCmdZoomOut,
  kCmdZoomReset,
  kCmdBookmarkPage,
  kCmdBookmarks,
  kCmdHistory,
  kCmdDownloads,
  kCmdDashboard,
  kCmdNetwork,
  kCmdSiteReport,
  kCmdAbout,
  kCmdModeMax,
  kCmdModeStrict,
  kCmdModeCompat,
  kCmdSiteAllowJs,
  kCmdSiteAllowThirdParty,
  kCmdSiteDisableFiltering,
  kCmdSiteAllowPopups,
  kCmdSiteBlockJs,
  kCmdSiteClearPermissions,
  kCmdClearHistory,
  kCmdClearCookies,
  kCmdClearCache,
  kCmdClearSiteDataOnRestart,
  kCmdToggleHistory,
  kCmdToggleRestoreTabs,
  kCmdToggleHttpsFirst,
  kCmdToggleThirdPartyCookies,
  kCmdToggleClearOnExit,
  kCmdListBaseline,
  kCmdListEasyList,
  kCmdListEasyPrivacy,
  kCmdAddRule,
  kCmdClearRules,
  kCmdUpdateFilters,
  kCmdCheckUpdates,
  kCmdOpenDownloadsFolder,
  kCmdExit,
};

constexpr int kModeRadioGroup = 1;

std::vector<CefRefPtr<BrowserWindow>>& Windows() {
  static auto* v = new std::vector<CefRefPtr<BrowserWindow>>();
  return *v;
}

std::string TruncateTitle(const std::string& title, std::size_t max_chars) {
  std::vector<char32_t> cps;
  if (!DecodeUtf8(title, &cps)) return title.substr(0, max_chars);
  if (cps.size() <= max_chars) return title;
  cps.resize(max_chars - 1);
  cps.push_back(0x2026);
  return EncodeUtf8(cps);
}

// Address-bar rendering: hosts are shown in Unicode only when the spoof
// check accepts them; credentials are never displayed.
std::string DisplayUrl(const std::string& url) {
  if (url.empty() || StartsWith(url, "aegis://newtab")) return {};
  auto u = ParseUrl(url);
  if (!u || u->host.empty()) return url;
  auto d = idna::ForDisplay(u->host);
  std::string spec = u->Spec();
  if (d.is_idn && !d.spoof_risk) {
    std::size_t pos = spec.find(u->host);
    if (pos != std::string::npos) spec.replace(pos, u->host.size(), d.text);
  }
  return spec;
}

void StyleButton(CefRefPtr<CefLabelButton> b, cef_color_t bg, cef_color_t fg, const char* font) {
  b->SetFontList(font);
  b->SetEnabledTextColors(fg);
  b->SetTextColor(CEF_BUTTON_STATE_DISABLED, theme::kTextMuted);
  b->SetBackgroundColor(bg);
  b->SetInkDropEnabled(true);
}

CefRefPtr<CefImage> LoadIcon() {
  auto* ctx = AegisContext::Get();
  if (!ctx) return nullptr;
  auto img = CefImage::CreateImage();
  bool any = false;
  for (auto [scale, name] : {std::pair<float, const char*>{1.0f, "aegis-32.png"},
                             std::pair<float, const char*>{2.0f, "aegis-64.png"}}) {
    auto r = storage::ReadFile(ctx->assets_dir() / "branding" / name, 1 << 20);
    if (r.status == storage::ReadStatus::kOk) {
      any |= img->AddPNG(scale, r.data.data(), r.data.size());
    }
  }
  return any ? img : nullptr;
}

}  // namespace

// Theme colors for views without per-view color setters (text fields,
// menus) are applied through the window's color provider.
void ApplyThemeColors(CefRefPtr<CefWindow> window) {
  struct C { int id; cef_color_t color; };
  const C colors[] = {
      {CEF_ColorTextfieldForeground, theme::kTextPrimary},
      {CEF_ColorTextfieldBackground, theme::kFieldBackground},
      {CEF_ColorTextfieldSelectionBackground, theme::kSelection},
      {CEF_ColorTextfieldSelectionForeground, theme::kTextPrimary},
      {CEF_ColorTextfieldForegroundPlaceholder, theme::kTextMuted},
      {CEF_ColorMenuBackground, theme::kToolbarBackground},
      {CEF_ColorMenuItemForeground, theme::kTextPrimary},
      {CEF_ColorMenuItemForegroundDisabled, theme::kTextMuted},
      {CEF_ColorMenuItemForegroundSelected, theme::kTextPrimary},
      {CEF_ColorMenuItemBackgroundSelected, theme::kSelection},
      {CEF_ColorMenuSeparator, 0xFF2B3038},
      {CEF_ColorMenuBorder, 0xFF2B3038},
      {CEF_ColorMenuIcon, theme::kTextPrimary},
      {CEF_ColorPrimaryBackground, theme::kToolbarBackground},
      {CEF_ColorPrimaryForeground, theme::kTextPrimary},
      {CEF_ColorDialogBackground, theme::kToolbarBackground},
      {CEF_ColorDialogForeground, theme::kTextPrimary},
      {CEF_ColorFocusableBorderFocused, theme::kAccentCyan},
  };
  for (const auto& c : colors) window->SetThemeColor(c.id, c.color);
  window->ThemeChanged();
}

// ---------------------------------------------------------------------------
// Static helpers

void BrowserWindow::Open(bool private_window, const std::vector<std::string>& urls) {
  CEF_REQUIRE_UI_THREAD();
  CefRefPtr<BrowserWindow> w = new BrowserWindow(private_window, urls);
  Windows().push_back(w);
  CefWindow::CreateTopLevelWindow(w);
}

void BrowserWindow::CloseAll(bool force) {
  CEF_REQUIRE_UI_THREAD();
  auto copy = Windows();
  for (auto& w : copy) {
    w->closing_ = true;
    for (auto& t : w->tabs_) {
      if (auto b = t.view ? t.view->GetBrowser() : nullptr) b->GetHost()->CloseBrowser(force);
    }
    if (w->window_) w->window_->Close();
  }
}

void BrowserWindow::RecreateAllTabs() {
  CEF_REQUIRE_UI_THREAD();
  for (auto& w : Windows()) w->RecreateTabs();
}

int BrowserWindow::OpenWindowCount() { return static_cast<int>(Windows().size()); }

BrowserWindow::BrowserWindow(bool private_window, std::vector<std::string> urls)
    : private_(private_window), initial_urls_(std::move(urls)) {
  client_ = new ClientHandler(this);
  auto* ctx = AegisContext::Get();
  request_context_ = private_ ? ctx->CreatePrivateRequestContext() : ctx->normal_request_context();
}

void* BrowserWindow::NativeWindowHandle() {
  return window_ ? reinterpret_cast<void*>(window_->GetWindowHandle()) : nullptr;
}

// ---------------------------------------------------------------------------
// Window lifecycle

CefRect BrowserWindow::GetInitialBounds(CefRefPtr<CefWindow>) {
  return CefRect(0, 0, 1280, 820);
}

cef_show_state_t BrowserWindow::GetInitialShowState(CefRefPtr<CefWindow>) {
  return CEF_SHOW_STATE_NORMAL;
}

CefSize BrowserWindow::GetMinimumSize(CefRefPtr<CefView>) { return CefSize(640, 400); }

void BrowserWindow::OnThemeColorsChanged(CefRefPtr<CefWindow> window, bool chrome_theme) {
  (void)chrome_theme;
  // Keep the WezCrypt palette when the OS theme changes.
  struct C { int id; cef_color_t color; };
  const C colors[] = {
      {CEF_ColorTextfieldForeground, theme::kTextPrimary},
      {CEF_ColorTextfieldBackground, theme::kFieldBackground},
      {CEF_ColorMenuBackground, theme::kToolbarBackground},
      {CEF_ColorMenuItemForeground, theme::kTextPrimary},
  };
  for (const auto& c : colors) window->SetThemeColor(c.id, c.color);
}

void BrowserWindow::OnWindowCreated(CefRefPtr<CefWindow> window) {
  window_ = window;
  window_->SetTitle(private_ ? "WezCrypt Aegis - Private" : "WezCrypt Aegis");
  if (auto icon = LoadIcon()) {
    window_->SetWindowIcon(icon);
    window_->SetWindowAppIcon(icon);
  }
  window_->SetBackgroundColor(theme::kWindowBackground);
  ApplyThemeColors(window_);
  BuildLayout();
  InstallAccelerators();
  if (initial_urls_.empty()) {
    auto* ctx = AegisContext::Get();
    initial_urls_.push_back(private_ ? "aegis://newtab/" : ctx->settings().home_page);
  }
  for (std::size_t i = 0; i < initial_urls_.size(); ++i) AddTab(initial_urls_[i], i == 0);
  window_->CenterWindow(CefSize(1280, 820));
  window_->Show();
}

bool BrowserWindow::CanClose(CefRefPtr<CefWindow>) {
  closing_ = true;
  bool all_closed = true;
  for (auto& t : tabs_) {
    auto browser = t.view ? t.view->GetBrowser() : nullptr;
    if (browser && !browser->GetHost()->TryCloseBrowser()) all_closed = false;
  }
  return all_closed;
}

void BrowserWindow::OnWindowClosing(CefRefPtr<CefWindow>) {
  auto* ctx = AegisContext::Get();
  if (!ctx || private_) return;
  // Remember tabs only if this is the last normal window and the user
  // enabled restoration. Internal pages and web pages only.
  int normal_windows = 0;
  for (auto& w : Windows()) normal_windows += w->private_ ? 0 : 1;
  if (normal_windows > 1) return;
  std::vector<std::string> urls;
  if (ctx->settings().restore_tabs) {
    for (auto& t : tabs_) {
      auto u = ParseUrl(t.url);
      if (u && (u->IsHttpLike() || u->scheme == "aegis")) urls.push_back(u->Spec(false));
    }
  }
  ctx->UpdateSettings([&](Settings& s) { s.session_tabs = urls; });
}

void BrowserWindow::OnWindowDestroyed(CefRefPtr<CefWindow>) {
  client_->DetachHost();
  if (private_) {
    if (auto* ctx = AegisContext::Get()) ctx->ReleasePrivateRequestContext(request_context_);
  }
  window_ = nullptr;
  tabs_.clear();
  orphans_.clear();
  auto& v = Windows();
  v.erase(std::remove_if(v.begin(), v.end(), [this](const CefRefPtr<BrowserWindow>& w) { return w.get() == this; }),
          v.end());
  if (v.empty()) {
    // Last window: persist state and apply clear-on-exit, then quit. A
    // timeout guarantees exit even if an asynchronous deletion stalls.
    if (auto* ctx = AegisContext::Get()) {
      ctx->Shutdown([]() { CefQuitMessageLoop(); });
      CefPostDelayedTask(TID_UI, base::BindOnce([]() { CefQuitMessageLoop(); }), 5000);
    } else {
      CefQuitMessageLoop();
    }
  }
}

bool BrowserWindow::OnPopupBrowserViewCreated(CefRefPtr<CefBrowserView>, CefRefPtr<CefBrowserView>, bool) {
  // Popups are always cancelled in OnBeforePopup; nothing reaches here.
  return false;
}

// ---------------------------------------------------------------------------
// Layout

CefRefPtr<CefLabelButton> BrowserWindow::MakeIconButton(int id, const char* glyph, const char* tooltip) {
  auto b = CefLabelButton::CreateLabelButton(this, glyph);
  b->SetID(id);
  StyleButton(b, theme::kToolbarBackground, theme::kTextPrimary, theme::kIconFont);
  b->SetTooltipText(tooltip);
  b->SetAccessibleName(tooltip);
  b->SetMinimumSize(CefSize(34, 30));
  return b;
}

void BrowserWindow::BuildLayout() {
  CefBoxLayoutSettings vertical;
  vertical.horizontal = false;
  auto root = window_->SetToBoxLayout(vertical);

  const cef_color_t strip_bg = private_ ? 0xFF15172A : theme::kTabStripBackground;

  // Tab strip.
  tab_strip_ = CefPanel::CreatePanel(nullptr);
  tab_strip_->SetBackgroundColor(strip_bg);
  CefBoxLayoutSettings strip;
  strip.horizontal = true;
  strip.inside_border_insets = {6, 8, 0, 8};
  strip.between_child_spacing = 2;
  strip.cross_axis_alignment = CEF_AXIS_ALIGNMENT_CENTER;
  tab_strip_->SetToBoxLayout(strip);
  new_tab_button_ = CefLabelButton::CreateLabelButton(this, theme::kGlyphAdd);
  new_tab_button_->SetID(kIdNewTab);
  StyleButton(new_tab_button_, strip_bg, theme::kTextPrimary, theme::kIconFont);
  new_tab_button_->SetTooltipText("New tab (Ctrl+T)");
  new_tab_button_->SetAccessibleName("New tab");
  tab_strip_->AddChildView(new_tab_button_);
  window_->AddChildView(tab_strip_);

  // Toolbar.
  toolbar_ = CefPanel::CreatePanel(nullptr);
  toolbar_->SetBackgroundColor(theme::kToolbarBackground);
  CefBoxLayoutSettings bar;
  bar.horizontal = true;
  bar.inside_border_insets = {6, 8, 6, 8};
  bar.between_child_spacing = 4;
  bar.cross_axis_alignment = CEF_AXIS_ALIGNMENT_CENTER;
  auto bar_layout = toolbar_->SetToBoxLayout(bar);
  back_ = MakeIconButton(kIdBack, theme::kGlyphBack, "Back (Alt+Left)");
  forward_ = MakeIconButton(kIdForward, theme::kGlyphForward, "Forward (Alt+Right)");
  reload_ = MakeIconButton(kIdReload, theme::kGlyphRefresh, "Reload (Ctrl+R)");
  home_ = MakeIconButton(kIdHome, theme::kGlyphHome, "Home");
  site_button_ = CefMenuButton::CreateMenuButton(this, theme::kGlyphLock);
  site_button_->SetID(kIdSite);
  StyleButton(site_button_, theme::kFieldBackground, theme::kOk, theme::kIconFont);
  site_button_->SetTooltipText("Site security");
  site_button_->SetAccessibleName("Site security");
  address_ = CefTextfield::CreateTextfield(this);
  address_->SetID(kIdAddress);
  address_->SetFontList(theme::kAddressFont);
  address_->SetBackgroundColor(theme::kFieldBackground);
  address_->SetPlaceholderText("Search or enter address");
  address_->SetAccessibleName("Address and search bar");
  bookmark_ = MakeIconButton(kIdBookmark, theme::kGlyphStar, "Bookmark this page (Ctrl+D)");
  shield_ = CefLabelButton::CreateLabelButton(this, std::string(theme::kGlyphShield) + " 0");
  shield_->SetID(kIdShield);
  StyleButton(shield_, theme::kToolbarBackground, theme::kAccentCyan, theme::kIconFont);
  shield_->SetTooltipText("Requests blocked on this page - open the site report");
  shield_->SetAccessibleName("Blocked requests on this page");
  mode_button_ = CefMenuButton::CreateMenuButton(this, "");
  mode_button_->SetID(kIdMode);
  StyleButton(mode_button_, theme::kToolbarBackground, theme::kAccentCyan, theme::kUiFontBold);
  mode_button_->SetTooltipText("Security mode");
  mode_button_->SetAccessibleName("Security mode");
  menu_button_ = CefMenuButton::CreateMenuButton(this, theme::kGlyphMore);
  menu_button_->SetID(kIdMenu);
  StyleButton(menu_button_, theme::kToolbarBackground, theme::kTextPrimary, theme::kIconFont);
  menu_button_->SetTooltipText("Menu");
  menu_button_->SetAccessibleName("Menu");
  for (CefRefPtr<CefView> v : std::vector<CefRefPtr<CefView>>{back_, forward_, reload_, home_, site_button_,
                                                              address_, bookmark_, shield_, mode_button_,
                                                              menu_button_}) {
    toolbar_->AddChildView(v);
  }
  bar_layout->SetFlexForView(address_, 1);
  window_->AddChildView(toolbar_);

  // Find bar (hidden until Ctrl+F).
  find_bar_ = CefPanel::CreatePanel(nullptr);
  find_bar_->SetBackgroundColor(theme::kToolbarBackground);
  CefBoxLayoutSettings find;
  find.horizontal = true;
  find.inside_border_insets = {0, 8, 6, 8};
  find.between_child_spacing = 4;
  find.cross_axis_alignment = CEF_AXIS_ALIGNMENT_CENTER;
  auto find_layout = find_bar_->SetToBoxLayout(find);
  find_field_ = CefTextfield::CreateTextfield(this);
  find_field_->SetID(kIdFindField);
  find_field_->SetFontList(theme::kUiFont);
  find_field_->SetBackgroundColor(theme::kFieldBackground);
  find_field_->SetPlaceholderText("Find in page");
  find_field_->SetAccessibleName("Find in page");
  find_status_ = CefLabelButton::CreateLabelButton(this, "");
  StyleButton(find_status_, theme::kToolbarBackground, theme::kTextMuted, theme::kUiFont);
  find_status_->SetEnabled(false);
  find_status_->SetMinimumSize(CefSize(80, 24));
  find_bar_->AddChildView(find_field_);
  find_bar_->AddChildView(find_status_);
  find_bar_->AddChildView(MakeIconButton(kIdFindPrev, theme::kGlyphUp, "Previous match (Shift+F3)"));
  find_bar_->AddChildView(MakeIconButton(kIdFindNext, theme::kGlyphDown, "Next match (F3)"));
  find_bar_->AddChildView(MakeIconButton(kIdFindClose, theme::kGlyphClose, "Close find bar (Esc)"));
  find_layout->SetFlexForView(find_field_, 1);
  find_bar_->SetVisible(false);
  window_->AddChildView(find_bar_);

  // Content area: one BrowserView per tab, only the active one visible.
  content_ = CefPanel::CreatePanel(nullptr);
  content_->SetBackgroundColor(theme::kWindowBackground);
  CefBoxLayoutSettings content;
  content.horizontal = false;
  content.default_flex = 1;
  content_->SetToBoxLayout(content);
  window_->AddChildView(content_);
  root->SetFlexForView(content_, 1);

  // Status bar.
  status_bar_ = CefPanel::CreatePanel(nullptr);
  status_bar_->SetBackgroundColor(strip_bg);
  CefBoxLayoutSettings status;
  status.horizontal = true;
  status.inside_border_insets = {2, 10, 2, 10};
  status.cross_axis_alignment = CEF_AXIS_ALIGNMENT_CENTER;
  auto status_layout = status_bar_->SetToBoxLayout(status);
  status_text_ = CefLabelButton::CreateLabelButton(this, "");
  StyleButton(status_text_, strip_bg, theme::kTextMuted, theme::kUiFont);
  status_text_->SetEnabled(false);
  status_text_->SetHorizontalAlignment(CEF_HORIZONTAL_ALIGNMENT_LEFT);
  status_mode_ = CefLabelButton::CreateLabelButton(this, "");
  StyleButton(status_mode_, strip_bg, private_ ? theme::kPrivateAccent : theme::kAccentCyan, theme::kUiFontBold);
  status_mode_->SetEnabled(false);
  status_bar_->AddChildView(status_text_);
  status_bar_->AddChildView(status_mode_);
  status_layout->SetFlexForView(status_text_, 1);
  window_->AddChildView(status_bar_);

  RefreshToolbar();
}

void BrowserWindow::InstallAccelerators() {
  struct A { int cmd; int key; bool shift, ctrl, alt; };
  const A accels[] = {
      {kCmdNewTab, 'T', false, true, false},
      {kCmdCloseTab, 'W', false, true, false},
      {kCmdCloseTab, VK_F4, false, true, false},
      {kCmdReopenTab, 'T', true, true, false},
      {kCmdNewWindow, 'N', false, true, false},
      {kCmdNewPrivateWindow, 'N', true, true, false},
      {kCmdFocusAddress, 'L', false, true, false},
      {kCmdFocusAddress, VK_F6, false, false, false},
      {kCmdReload, 'R', false, true, false},
      {kCmdReload, VK_F5, false, false, false},
      {kCmdHardReload, VK_F5, false, true, false},
      {kCmdStop, VK_ESCAPE, false, false, false},
      {kCmdBack, VK_LEFT, false, false, true},
      {kCmdForward, VK_RIGHT, false, false, true},
      {kCmdHome, VK_HOME, false, false, true},
      {kCmdFind, 'F', false, true, false},
      {kCmdFindNext, VK_F3, false, false, false},
      {kCmdFindPrev, VK_F3, true, false, false},
      {kCmdNextTab, VK_TAB, false, true, false},
      {kCmdPrevTab, VK_TAB, true, true, false},
      {kCmdZoomIn, VK_OEM_PLUS, false, true, false},
      {kCmdZoomOut, VK_OEM_MINUS, false, true, false},
      {kCmdZoomReset, '0', false, true, false},
      {kCmdBookmarkPage, 'D', false, true, false},
      {kCmdBookmarks, 'B', true, true, false},
      {kCmdHistory, 'H', false, true, false},
      {kCmdDownloads, 'J', false, true, false},
      {kCmdDashboard, 'S', true, true, false},
      {kCmdNetwork, 'A', true, true, false},
  };
  for (const auto& a : accels) window_->SetAccelerator(a.cmd, a.key, a.shift, a.ctrl, a.alt, false);
}

CefBrowserSettings BrowserWindow::MakeBrowserSettings() const {
  CefBrowserSettings s;
  auto* ctx = AegisContext::Get();
  const Settings& st = ctx->settings();
  const bool max_iso = st.mode == SecurityMode::kMaximumIsolation;
  bool any_js_exception = false;
  for (const auto& [site, ex] : st.site_exceptions) any_js_exception |= ex.allow_javascript;
  // Browser-level switches complement the per-origin content settings.
  // In Maximum Isolation without JavaScript exceptions, script is disabled
  // for the whole browser instance as an additional layer.
  s.javascript = (max_iso && !any_js_exception) ? STATE_DISABLED : STATE_DEFAULT;
  s.javascript_close_windows = STATE_DISABLED;
  s.javascript_access_clipboard = STATE_DISABLED;
  s.javascript_dom_paste = STATE_DISABLED;
  // Web fonts and WebGL are parsing / GPU attack surface.
  s.remote_fonts = max_iso ? STATE_DISABLED : STATE_DEFAULT;
  s.webgl = st.mode == SecurityMode::kCompatibility ? STATE_DEFAULT : STATE_DISABLED;
  s.background_color = theme::kWindowBackground;
  return s;
}

// ---------------------------------------------------------------------------
// Tabs

int BrowserWindow::AddTab(const std::string& url, bool activate, int index) {
  Tab t;
  t.key = next_key_++;
  t.url = url;
  t.title = "New Tab";
  t.button = CefLabelButton::CreateLabelButton(this, t.title);
  t.button->SetID(kIdTabButtonBase + t.key);
  StyleButton(t.button, theme::kTabInactiveBackground, theme::kTextMuted, theme::kUiFont);
  t.button->SetMinimumSize(CefSize(120, 30));
  t.button->SetMaximumSize(CefSize(220, 30));
  t.button->SetHorizontalAlignment(CEF_HORIZONTAL_ALIGNMENT_LEFT);
  t.close = CefLabelButton::CreateLabelButton(this, theme::kGlyphClose);
  t.close->SetID(kIdTabCloseBase + t.key);
  StyleButton(t.close, theme::kTabInactiveBackground, theme::kTextMuted, "Segoe Fluent Icons, Segoe MDL2 Assets, 10px");
  t.close->SetTooltipText("Close tab (Ctrl+W)");
  t.close->SetAccessibleName("Close tab");
  // Insert before the "+" button.
  int pos = static_cast<int>(tab_strip_->GetChildViewCount()) - 1;
  if (index >= 0) pos = std::min(pos, index * 2);
  tab_strip_->AddChildViewAt(t.button, pos);
  tab_strip_->AddChildViewAt(t.close, pos + 1);

  t.view = CefBrowserView::CreateBrowserView(client_, url, MakeBrowserSettings(), nullptr,
                                             request_context_, this);
  t.view->SetPreferAccelerators(true);
  content_->AddChildView(t.view);
  t.view->SetVisible(false);
  const int key = t.key;
  if (index >= 0 && index < static_cast<int>(tabs_.size())) {
    tabs_.insert(tabs_.begin() + index, std::move(t));
  } else {
    tabs_.push_back(std::move(t));
  }
  if (activate || active_key_ < 0) ActivateTab(key);
  tab_strip_->Layout();
  return key;
}

BrowserWindow::Tab* BrowserWindow::FindTab(int key) {
  for (auto& t : tabs_) if (t.key == key) return &t;
  return nullptr;
}

BrowserWindow::Tab* BrowserWindow::FindTabByBrowser(int browser_id) {
  for (auto& t : tabs_) if (t.browser_id == browser_id) return &t;
  return nullptr;
}

BrowserWindow::Tab* BrowserWindow::ActiveTab() { return FindTab(active_key_); }

CefRefPtr<CefBrowser> BrowserWindow::ActiveBrowser() {
  Tab* t = ActiveTab();
  return (t && t->view) ? t->view->GetBrowser() : nullptr;
}

void BrowserWindow::ActivateTab(int key) {
  Tab* target = FindTab(key);
  if (!target) return;
  active_key_ = key;
  for (auto& t : tabs_) {
    const bool active = t.key == key;
    if (t.view) t.view->SetVisible(active);
    RefreshTabButton(t);
  }
  content_->Layout();
  RefreshToolbar();
  if (target->url.empty() || StartsWith(target->url, "aegis://newtab")) {
    address_->RequestFocus();
  } else if (target->view) {
    target->view->RequestFocus();
  }
}

void BrowserWindow::CloseTab(int key) {
  Tab* t = FindTab(key);
  if (!t) return;
  if (!t->url.empty() && !private_) closed_urls_.push_back(t->url);
  if (closed_urls_.size() > 25) closed_urls_.erase(closed_urls_.begin());
  if (tabs_.size() == 1) {
    window_->Close();
    return;
  }
  // Pick the neighbour to activate before removing.
  auto it = std::find_if(tabs_.begin(), tabs_.end(), [key](const Tab& x) { return x.key == key; });
  std::size_t idx = static_cast<std::size_t>(it - tabs_.begin());
  int next = (idx + 1 < tabs_.size()) ? tabs_[idx + 1].key : tabs_[idx - 1].key;
  tab_strip_->RemoveChildView(t->button);
  tab_strip_->RemoveChildView(t->close);
  if (t->view) {
    if (auto b = t->view->GetBrowser()) {
      orphans_.push_back({t->browser_id, t->view});
      b->GetHost()->CloseBrowser(false);
    }
    t->view->SetVisible(false);
  }
  tabs_.erase(it);
  tab_strip_->Layout();
  ActivateTab(next);
}

void BrowserWindow::RecreateTabs() {
  for (auto& t : tabs_) {
    std::string url = t.url.empty() ? "aegis://newtab/" : t.url;
    if (t.view) {
      if (auto b = t.view->GetBrowser()) {
        orphans_.push_back({t.browser_id, t.view});
        b->GetHost()->CloseBrowser(true);
      }
      t.view->SetVisible(false);
    }
    t.browser_id = -1;
    t.view = CefBrowserView::CreateBrowserView(client_, url, MakeBrowserSettings(), nullptr,
                                               request_context_, this);
    t.view->SetPreferAccelerators(true);
    content_->AddChildView(t.view);
    t.view->SetVisible(t.key == active_key_);
  }
  content_->Layout();
  RefreshToolbar();
}

void BrowserWindow::OnTabCreated(CefRefPtr<CefBrowser> browser) {
  auto view = CefBrowserView::GetForBrowser(browser);
  for (auto& t : tabs_) {
    if (t.view && view && t.view->IsSame(view)) {
      t.browser_id = browser->GetIdentifier();
      return;
    }
  }
}

void BrowserWindow::OnTabClosed(int browser_id) {
  for (auto it = orphans_.begin(); it != orphans_.end(); ++it) {
    if (it->browser_id == browser_id || !it->view->GetBrowser()) {
      content_->RemoveChildView(it->view);
      orphans_.erase(it);
      break;
    }
  }
  if (Tab* t = FindTabByBrowser(browser_id)) {
    // Closed by the engine (window closing).
    t->browser_id = -1;
  }
  if (closing_ && window_) {
    bool any_alive = false;
    for (auto& t : tabs_) any_alive |= t.view && t.view->GetBrowser() != nullptr;
    if (!any_alive) window_->Close();
  }
}

void BrowserWindow::OnTabAddressChanged(int browser_id, const std::string& url) {
  Tab* t = FindTabByBrowser(browser_id);
  if (!t) return;
  t->url = url;
  if (t->key == active_key_) RefreshToolbar();
}

void BrowserWindow::OnTabTitleChanged(int browser_id, const std::string& title) {
  Tab* t = FindTabByBrowser(browser_id);
  if (!t) return;
  t->title = title.empty() ? t->url : title;
  RefreshTabButton(*t);
  if (t->key == active_key_ && window_) {
    window_->SetTitle(TruncateTitle(t->title, 80) + (private_ ? " - WezCrypt Aegis Private" : " - WezCrypt Aegis"));
  }
}

void BrowserWindow::OnTabLoadingState(int browser_id, bool loading, bool can_back, bool can_forward) {
  Tab* t = FindTabByBrowser(browser_id);
  if (!t) return;
  t->loading = loading;
  t->can_back = can_back;
  t->can_forward = can_forward;
  RefreshTabButton(*t);
  if (t->key == active_key_) RefreshToolbar();
}

void BrowserWindow::OnTabStatusMessage(int browser_id, const std::string& text) {
  Tab* t = FindTabByBrowser(browser_id);
  if (t && t->key == active_key_) status_text_->SetText(SanitizeForLog(text, 200));
}

void BrowserWindow::OnTabFindResult(int browser_id, int count, int active, bool) {
  Tab* t = FindTabByBrowser(browser_id);
  if (!t || t->key != active_key_) return;
  find_status_->SetText(count == 0 ? "No matches" : std::to_string(active) + " of " + std::to_string(count));
}

void BrowserWindow::OnTabSecurityEvent(int browser_id) {
  Tab* t = FindTabByBrowser(browser_id);
  if (t && t->key == active_key_) RefreshSecurityIndicator();
}

void BrowserWindow::OpenInNewTab(const std::string& url, bool foreground) {
  // Insert next to the active tab.
  int index = -1;
  for (std::size_t i = 0; i < tabs_.size(); ++i) {
    if (tabs_[i].key == active_key_) index = static_cast<int>(i) + 1;
  }
  AddTab(url, foreground, index);
}

void BrowserWindow::RefreshTabButton(Tab& t) {
  const bool active = t.key == active_key_;
  std::string label = (t.loading ? std::string("\xe2\x80\xa2 ") : std::string()) + TruncateTitle(t.title, 22);
  t.button->SetText(label);
  t.button->SetTooltipText(t.title);
  cef_color_t bg = active ? theme::kTabActiveBackground : (private_ ? 0xFF15172A : theme::kTabInactiveBackground);
  t.button->SetBackgroundColor(bg);
  t.button->SetEnabledTextColors(active ? theme::kTextPrimary : theme::kTextMuted);
  t.close->SetBackgroundColor(bg);
}

// ---------------------------------------------------------------------------
// Toolbar state

void BrowserWindow::RefreshToolbar() {
  auto* ctx = AegisContext::Get();
  Tab* t = ActiveTab();
  back_->SetEnabled(t && t->can_back);
  forward_->SetEnabled(t && t->can_forward);
  reload_->SetText(t && t->loading ? theme::kGlyphStop : theme::kGlyphRefresh);
  reload_->SetTooltipText(t && t->loading ? "Stop (Esc)" : "Reload (Ctrl+R)");
  if (t && !address_->HasFocus()) address_->SetText(DisplayUrl(t->url));
  const bool bookmarked = t && ctx->bookmarks().Contains(t->url);
  bookmark_->SetText(bookmarked ? theme::kGlyphStarFilled : theme::kGlyphStar);
  bookmark_->SetEnabledTextColors(bookmarked ? theme::kAccentCyan : theme::kTextPrimary);
  const SecurityMode mode = ctx->settings().mode;
  mode_button_->SetText(std::string(SecurityModeShortLabel(mode)));
  mode_button_->SetEnabledTextColors(mode == SecurityMode::kCompatibility ? theme::kWarning
                                                                          : theme::kAccentCyan);
  status_mode_->SetText((private_ ? std::string("PRIVATE  |  ") : std::string()) +
                        std::string(SecurityModeDisplayName(mode)));
  RefreshSecurityIndicator();
  toolbar_->Layout();
}

void BrowserWindow::RefreshSecurityIndicator() {
  auto* ctx = AegisContext::Get();
  Tab* t = ActiveTab();
  std::uint64_t blocked = (t && t->browser_id >= 0) ? ctx->events().TabBlockedCount(t->browser_id) : 0;
  shield_->SetText(std::string(theme::kGlyphShield) + " " + std::to_string(blocked));
  auto u = t ? ParseUrl(t->url) : std::nullopt;
  if (u && u->scheme == "https") {
    auto d = idna::ForDisplay(u->host);
    site_button_->SetText(d.spoof_risk ? theme::kGlyphWarning : theme::kGlyphLock);
    site_button_->SetEnabledTextColors(d.spoof_risk ? theme::kWarning : theme::kOk);
    site_button_->SetTooltipText(d.spoof_risk ? "Encrypted connection - the address uses look-alike "
                                                "international characters"
                                              : "Encrypted connection (HTTPS)");
  } else if (u && u->scheme == "aegis") {
    site_button_->SetText(theme::kGlyphShield);
    site_button_->SetEnabledTextColors(theme::kAccentCyan);
    site_button_->SetTooltipText("WezCrypt Aegis internal page");
  } else if (u && u->scheme == "http") {
    site_button_->SetText(theme::kGlyphWarning);
    site_button_->SetEnabledTextColors(theme::kWarning);
    site_button_->SetTooltipText("Not encrypted - information sent to this site can be read by others");
  } else {
    site_button_->SetText(theme::kGlyphShield);
    site_button_->SetEnabledTextColors(theme::kTextMuted);
    site_button_->SetTooltipText("Site security");
  }
  const SandboxStatus sb = ctx->sandbox_status();
  if (sb.state == SandboxStatus::State::kFailed) {
    shield_->SetEnabledTextColors(theme::kDanger);
  } else {
    shield_->SetEnabledTextColors(ctx->update_status().warning ? theme::kWarning : theme::kAccentCyan);
  }
}

// ---------------------------------------------------------------------------
// Input

void BrowserWindow::Navigate(const std::string& input) {
  auto browser = ActiveBrowser();
  if (!browser) return;
  OmniboxResult r = ResolveOmniboxInput(input);
  // The navigation is browser-initiated (typed): internal and file:// URLs
  // are permitted only through this path.
  ExpectBrowserNavigation(browser->GetIdentifier(), r.url);
  browser->GetMainFrame()->LoadURL(r.url);
  if (auto view = ActiveTab()->view) view->RequestFocus();
}

bool BrowserWindow::OnKeyEvent(CefRefPtr<CefTextfield> textfield, const CefKeyEvent& event) {
  if (event.type != KEYEVENT_RAWKEYDOWN) return false;
  if (textfield->GetID() == kIdAddress) {
    if (event.windows_key_code == VK_RETURN) {
      Navigate(textfield->GetText().ToString());
      return true;
    }
    if (event.windows_key_code == VK_ESCAPE) {
      Tab* t = ActiveTab();
      textfield->SetText(t ? DisplayUrl(t->url) : "");
      return true;
    }
  } else if (textfield->GetID() == kIdFindField) {
    if (event.windows_key_code == VK_RETURN) {
      FindNext((event.modifiers & EVENTFLAG_SHIFT_DOWN) == 0);
      return true;
    }
    if (event.windows_key_code == VK_ESCAPE) {
      ShowFindBar(false);
      return true;
    }
  }
  return false;
}

void BrowserWindow::ShowFindBar(bool show) {
  find_bar_->SetVisible(show);
  window_->Layout();
  if (show) {
    find_field_->RequestFocus();
    find_field_->SelectAll(false);
  } else {
    if (auto b = ActiveBrowser()) b->GetHost()->StopFinding(true);
    find_status_->SetText("");
    last_find_.clear();
  }
}

void BrowserWindow::FindNext(bool forward) {
  auto b = ActiveBrowser();
  if (!b) return;
  std::string text = find_field_->GetText().ToString();
  if (text.empty()) {
    b->GetHost()->StopFinding(true);
    find_status_->SetText("");
    return;
  }
  b->GetHost()->Find(text, forward, false, text == last_find_);
  last_find_ = text;
}

void BrowserWindow::OnButtonPressed(CefRefPtr<CefButton> button) {
  const int id = button->GetID();
  if (id >= kIdTabCloseBase) {
    CloseTab(id - kIdTabCloseBase);
    return;
  }
  if (id >= kIdTabButtonBase) {
    ActivateTab(id - kIdTabButtonBase);
    return;
  }
  switch (id) {
    case kIdNewTab: AddTab("aegis://newtab/", true); break;
    case kIdBack: OnAccelerator(window_, kCmdBack); break;
    case kIdForward: OnAccelerator(window_, kCmdForward); break;
    case kIdReload: {
      Tab* t = ActiveTab();
      OnAccelerator(window_, t && t->loading ? kCmdStop : kCmdReload);
      break;
    }
    case kIdHome: OnAccelerator(window_, kCmdHome); break;
    case kIdBookmark: OnAccelerator(window_, kCmdBookmarkPage); break;
    case kIdShield: OnAccelerator(window_, kCmdSiteReport); break;
    case kIdFindPrev: FindNext(false); break;
    case kIdFindNext: FindNext(true); break;
    case kIdFindClose: ShowFindBar(false); break;
    default: break;
  }
}

void BrowserWindow::OnMenuButtonPressed(CefRefPtr<CefMenuButton> menu_button, const CefPoint& screen_point,
                                        CefRefPtr<CefMenuButtonPressedLock>) {
  switch (menu_button->GetID()) {
    case kIdMenu: ShowMainMenu(menu_button, screen_point); break;
    case kIdMode: ShowModeMenu(menu_button, screen_point); break;
    case kIdSite: ShowSiteMenu(menu_button, screen_point); break;
    default: break;
  }
}

// ---------------------------------------------------------------------------
// Menus

std::string BrowserWindow::CurrentSiteKey() {
  Tab* t = ActiveTab();
  auto* ctx = AegisContext::Get();
  if (!t || !ctx) return {};
  auto u = ParseUrl(t->url);
  if (!u || !u->IsHttpLike()) return {};
  return MakeSiteExceptionKey(ctx->psl(), t->url, false);
}

void BrowserWindow::ShowModeMenu(CefRefPtr<CefMenuButton> button, const CefPoint& pt) {
  auto* ctx = AegisContext::Get();
  auto m = CefMenuModel::CreateMenuModel(this);
  m->AddRadioItem(kCmdModeMax, "Maximum Isolation  (JavaScript off, third parties blocked)", kModeRadioGroup);
  m->AddRadioItem(kCmdModeStrict, "Strict Protection  (JavaScript per site, no JIT)", kModeRadioGroup);
  m->AddRadioItem(kCmdModeCompat, "Compatibility  (filters on, fewer restrictions)", kModeRadioGroup);
  switch (ctx->settings().mode) {
    case SecurityMode::kMaximumIsolation: m->SetChecked(kCmdModeMax, true); break;
    case SecurityMode::kStrictProtection: m->SetChecked(kCmdModeStrict, true); break;
    case SecurityMode::kCompatibility: m->SetChecked(kCmdModeCompat, true); break;
  }
  m->AddSeparator();
  m->AddItem(kCmdDashboard, "Security Control Center");
  button->ShowMenu(m, pt, CEF_MENU_ANCHOR_TOPRIGHT);
}

void BrowserWindow::ShowSiteMenu(CefRefPtr<CefMenuButton> button, const CefPoint& pt) {
  auto* ctx = AegisContext::Get();
  auto m = CefMenuModel::CreateMenuModel(this);
  const std::string key = CurrentSiteKey();
  SiteException ex;
  auto it = ctx->settings().site_exceptions.find(key);
  if (it != ctx->settings().site_exceptions.end()) ex = it->second;
  m->AddItem(kCmdSiteReport, "Site security report");
  m->AddSeparator();
  m->AddCheckItem(kCmdSiteAllowJs, "Allow JavaScript on " + (key.empty() ? std::string("this site") : key));
  m->AddCheckItem(kCmdSiteAllowThirdParty, "Allow third-party content");
  m->AddCheckItem(kCmdSiteAllowPopups, "Allow popups");
  m->AddCheckItem(kCmdSiteDisableFiltering, "Disable ad and tracker filtering");
  if (ctx->settings().mode == SecurityMode::kStrictProtection) {
    m->AddCheckItem(kCmdSiteBlockJs, "Block JavaScript on this site");
    m->SetChecked(kCmdSiteBlockJs, ctx->settings().javascript_blocked_sites.count(key) > 0);
  }
  m->AddItem(kCmdSiteClearPermissions, "Reset permissions for this site");
  m->SetChecked(kCmdSiteAllowJs, ex.allow_javascript);
  m->SetChecked(kCmdSiteAllowThirdParty, ex.allow_third_party);
  m->SetChecked(kCmdSiteAllowPopups, ex.allow_popups);
  m->SetChecked(kCmdSiteDisableFiltering, ex.disable_filtering);
  const bool usable = !key.empty();
  for (int c : {static_cast<int>(kCmdSiteAllowJs), static_cast<int>(kCmdSiteAllowThirdParty),
                static_cast<int>(kCmdSiteAllowPopups), static_cast<int>(kCmdSiteDisableFiltering),
                static_cast<int>(kCmdSiteBlockJs), static_cast<int>(kCmdSiteClearPermissions)}) {
    m->SetEnabled(c, usable);
  }
  button->ShowMenu(m, pt, CEF_MENU_ANCHOR_TOPLEFT);
}

void BrowserWindow::ShowMainMenu(CefRefPtr<CefMenuButton> button, const CefPoint& pt) {
  auto* ctx = AegisContext::Get();
  const Settings& s = ctx->settings();
  auto m = CefMenuModel::CreateMenuModel(this);
  m->AddItem(kCmdNewTab, "New tab");
  m->AddItem(kCmdNewWindow, "New window");
  m->AddItem(kCmdNewPrivateWindow, "New private window");
  m->AddSeparator();
  m->AddItem(kCmdBookmarks, "Bookmarks");
  m->AddItem(kCmdHistory, "History");
  m->AddItem(kCmdDownloads, "Downloads");
  m->AddItem(kCmdFind, "Find in page...");
  m->AddSeparator();
  m->AddItem(kCmdDashboard, "Security Control Center");
  m->AddItem(kCmdNetwork, "Network activity");
  m->AddItem(kCmdSiteReport, "Site security report");
  auto filters = m->AddSubMenu(0, "Filter lists");
  filters->AddCheckItem(kCmdListBaseline, "WezCrypt Aegis Baseline");
  filters->AddCheckItem(kCmdListEasyList, "EasyList (advertising)");
  filters->AddCheckItem(kCmdListEasyPrivacy, "EasyPrivacy (tracking)");
  for (const auto& c : ctx->filters().Configs()) {
    if (c.id == "aegis-baseline") filters->SetChecked(kCmdListBaseline, c.enabled);
    if (c.id == "easylist") filters->SetChecked(kCmdListEasyList, c.enabled);
    if (c.id == "easyprivacy") filters->SetChecked(kCmdListEasyPrivacy, c.enabled);
  }
  filters->AddSeparator();
  filters->AddItem(kCmdAddRule, "Add my own blocking rule...");
  filters->AddItem(kCmdClearRules, "Remove all my rules (" + std::to_string(s.user_rules.size()) + ")");
  filters->AddItem(kCmdUpdateFilters, "Update filter lists now");
  auto privacy = m->AddSubMenu(0, "Privacy and data");
  privacy->AddCheckItem(kCmdToggleHistory, "Save browsing history");
  privacy->SetChecked(kCmdToggleHistory, s.save_history);
  privacy->AddCheckItem(kCmdToggleThirdPartyCookies, "Block third-party cookies");
  privacy->SetChecked(kCmdToggleThirdPartyCookies, s.block_third_party_cookies);
  privacy->AddCheckItem(kCmdToggleHttpsFirst, "HTTPS-first mode");
  privacy->SetChecked(kCmdToggleHttpsFirst, s.https_first);
  privacy->AddCheckItem(kCmdToggleRestoreTabs, "Restore tabs on startup");
  privacy->SetChecked(kCmdToggleRestoreTabs, s.restore_tabs);
  privacy->AddCheckItem(kCmdToggleClearOnExit, "Clear cookies, cache and history on exit");
  privacy->SetChecked(kCmdToggleClearOnExit, s.clear_cookies_on_exit && s.clear_cache_on_exit &&
                                                 s.clear_history_on_exit);
  privacy->AddSeparator();
  privacy->AddItem(kCmdClearHistory, "Clear history now");
  privacy->AddItem(kCmdClearCookies, "Clear cookies now");
  privacy->AddItem(kCmdClearCache, "Clear cache now");
  privacy->AddItem(kCmdClearSiteDataOnRestart, "Clear all site data on next start...");
  privacy->AddItem(kCmdOpenDownloadsFolder, "Open downloads folder");
  if (private_) {
    for (int c : {static_cast<int>(kCmdClearHistory), static_cast<int>(kCmdClearCookies),
                  static_cast<int>(kCmdClearCache)}) {
      privacy->SetEnabled(c, false);
    }
  }
  m->AddItem(kCmdCheckUpdates, "Check for WezCrypt Aegis updates");
  m->AddSeparator();
  m->AddItem(kCmdAbout, "About WezCrypt Aegis");
  m->AddItem(kCmdExit, "Exit");
  button->ShowMenu(m, pt, CEF_MENU_ANCHOR_TOPRIGHT);
}

void BrowserWindow::ExecuteCommand(CefRefPtr<CefMenuModel>, int command_id, cef_event_flags_t) {
  OnAccelerator(window_, command_id);
}

// ---------------------------------------------------------------------------
// Commands

bool BrowserWindow::Confirm(const std::wstring& text, const std::wstring& title, bool warning) {
  return ::MessageBoxW(static_cast<HWND>(NativeWindowHandle()), text.c_str(), title.c_str(),
                       MB_YESNO | (warning ? MB_ICONWARNING : MB_ICONQUESTION) | MB_DEFBUTTON2) == IDYES;
}

void BrowserWindow::Inform(const std::wstring& text, const std::wstring& title) {
  ::MessageBoxW(static_cast<HWND>(NativeWindowHandle()), text.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
}

void BrowserWindow::SetMode(SecurityMode mode) {
  auto* ctx = AegisContext::Get();
  const SecurityMode current = ctx->settings().mode;
  if (mode == current) return;
  if (IsProtectionReduction(current, mode)) {
    std::wstring msg = L"Switch from " + Utf8ToWide(std::string(SecurityModeDisplayName(current))) + L" to " +
                       Utf8ToWide(std::string(SecurityModeDisplayName(mode))) +
                       L"?\n\nThis lowers protection:\n" +
                       Utf8ToWide(std::string(SecurityModeDescription(mode))) +
                       L"\n\nAll open tabs will be reloaded with the new policy.";
    if (!Confirm(msg, L"WezCrypt Aegis - Lower protection?", true)) return;
  }
  ctx->UpdateSettings([mode](Settings& s) { s.mode = mode; });
  RecreateAllTabs();
  for (auto& w : Windows()) w->RefreshToolbar();
  const bool wasm_changes = (current == SecurityMode::kMaximumIsolation) != (mode == SecurityMode::kMaximumIsolation);
  if (wasm_changes && ctx->startup_mode() != mode) {
    Inform(L"The WebAssembly setting for the new mode takes effect after WezCrypt Aegis is restarted. "
           L"All other protections changed immediately.",
           L"WezCrypt Aegis - Restart to complete");
  }
}

void BrowserWindow::ToggleSiteException(int command_id) {
  auto* ctx = AegisContext::Get();
  const std::string key = CurrentSiteKey();
  if (key.empty()) return;
  SiteException ex;
  auto it = ctx->settings().site_exceptions.find(key);
  if (it != ctx->settings().site_exceptions.end()) ex = it->second;
  bool* flag = nullptr;
  const wchar_t* what = L"";
  switch (command_id) {
    case kCmdSiteAllowJs: flag = &ex.allow_javascript; what = L"allow JavaScript"; break;
    case kCmdSiteAllowThirdParty: flag = &ex.allow_third_party; what = L"allow third-party content"; break;
    case kCmdSiteAllowPopups: flag = &ex.allow_popups; what = L"allow popups"; break;
    case kCmdSiteDisableFiltering: flag = &ex.disable_filtering; what = L"disable ad and tracker filtering"; break;
    default: return;
  }
  if (!*flag) {
    std::wstring msg = std::wstring(L"Relax protection for ") + Utf8ToWide(key) + L" and " + what +
                       L"?\n\nThis applies only to this site. Other sites keep full protection.";
    if (!Confirm(msg, L"WezCrypt Aegis - Site exception", true)) return;
  }
  *flag = !*flag;
  ctx->UpdateSettings([&](Settings& s) {
    if (ex.empty()) s.site_exceptions.erase(key);
    else s.site_exceptions[key] = ex;
  });
  if (command_id == kCmdSiteAllowJs) {
    RecreateAllTabs();  // browser-level JavaScript switch may change
  } else if (auto b = ActiveBrowser()) {
    b->Reload();
  }
  RefreshToolbar();
}

void BrowserWindow::ClearData(int command_id) {
  auto* ctx = AegisContext::Get();
  auto normal = ctx->normal_request_context();
  switch (command_id) {
    case kCmdClearHistory:
      if (Confirm(L"Delete all browsing history stored on this computer?", L"WezCrypt Aegis", false)) {
        ctx->history().Clear();
      }
      break;
    case kCmdClearCookies:
      if (Confirm(L"Delete all cookies? You will be signed out of websites.", L"WezCrypt Aegis", false) && normal) {
        if (auto cm = normal->GetCookieManager(nullptr)) cm->DeleteCookies("", "", nullptr);
      }
      break;
    case kCmdClearCache:
      if (normal) normal->ClearHttpCache(nullptr);
      Inform(L"The HTTP cache is being cleared.", L"WezCrypt Aegis");
      break;
    case kCmdClearSiteDataOnRestart:
      if (Confirm(L"All cookies, local storage, IndexedDB, service workers and cache of this profile will "
                  L"be deleted the next time WezCrypt Aegis starts. Continue?",
                  L"WezCrypt Aegis", true)) {
        storage::WriteFileAtomically(ctx->paths().profile_dir / "clear-site-data.pending", "1", false);
        Inform(L"Site data will be cleared at the next start. Restart WezCrypt Aegis to complete.",
               L"WezCrypt Aegis");
      }
      break;
    default: break;
  }
}

void BrowserWindow::PromptAddRule() {
  CefRefPtr<BrowserWindow> self(this);
  PromptWindow::Show(window_, "Add blocking rule",
                     "Enter an Adblock Plus network rule or a domain (for example ||ads.example.com^ or "
                     "tracker.example.net):",
                     [self](const std::string& text) {
                       auto* ctx = AegisContext::Get();
                       std::string rule(TrimAsciiWhitespace(text));
                       if (rule.empty() || !ctx) return;
                       // A bare domain becomes a domain-anchored host rule.
                       if (rule.find_first_of("|/^*$@") == std::string::npos && rule.find('.') != std::string::npos) {
                         rule = "||" + rule + "^";
                       }
                       ParsedLine p = ParseFilterLine(rule, 0);
                       if (p.outcome != ParseOutcome::kRule) {
                         self->Inform(L"This rule is not a supported network filter and was not added.",
                                      L"WezCrypt Aegis");
                         return;
                       }
                       ctx->UpdateSettings([&](Settings& s) { s.user_rules.push_back(rule); });
                     });
}

bool BrowserWindow::OnAccelerator(CefRefPtr<CefWindow>, int command_id) {
  auto* ctx = AegisContext::Get();
  auto browser = ActiveBrowser();
  Tab* tab = ActiveTab();
  switch (command_id) {
    case kCmdNewTab: AddTab("aegis://newtab/", true); return true;
    case kCmdCloseTab: if (tab) CloseTab(tab->key); return true;
    case kCmdReopenTab:
      if (!closed_urls_.empty()) {
        std::string u = closed_urls_.back();
        closed_urls_.pop_back();
        AddTab(u, true);
      }
      return true;
    case kCmdNewWindow: Open(false, {}); return true;
    case kCmdNewPrivateWindow: Open(true, {}); return true;
    case kCmdFocusAddress:
      address_->RequestFocus();
      address_->SelectAll(false);
      return true;
    case kCmdReload: if (browser) browser->Reload(); return true;
    case kCmdHardReload: if (browser) browser->ReloadIgnoreCache(); return true;
    case kCmdStop:
      if (find_bar_->IsVisible()) ShowFindBar(false);
      else if (browser) browser->StopLoad();
      return true;
    case kCmdBack: if (browser && browser->CanGoBack()) browser->GoBack(); return true;
    case kCmdForward: if (browser && browser->CanGoForward()) browser->GoForward(); return true;
    case kCmdHome: Navigate(private_ ? "aegis://newtab/" : ctx->settings().home_page); return true;
    case kCmdFind: ShowFindBar(true); return true;
    case kCmdFindNext: if (!find_bar_->IsVisible()) ShowFindBar(true); else FindNext(true); return true;
    case kCmdFindPrev: if (!find_bar_->IsVisible()) ShowFindBar(true); else FindNext(false); return true;
    case kCmdNextTab:
    case kCmdPrevTab: {
      if (tabs_.size() < 2 || !tab) return true;
      auto it = std::find_if(tabs_.begin(), tabs_.end(), [&](const Tab& t) { return t.key == tab->key; });
      std::size_t idx = static_cast<std::size_t>(it - tabs_.begin());
      std::size_t n = tabs_.size();
      idx = command_id == kCmdNextTab ? (idx + 1) % n : (idx + n - 1) % n;
      ActivateTab(tabs_[idx].key);
      return true;
    }
    case kCmdZoomIn: if (browser) browser->GetHost()->SetZoomLevel(std::min(browser->GetHost()->GetZoomLevel() + 0.5, 5.0)); return true;
    case kCmdZoomOut: if (browser) browser->GetHost()->SetZoomLevel(std::max(browser->GetHost()->GetZoomLevel() - 0.5, -5.0)); return true;
    case kCmdZoomReset: if (browser) browser->GetHost()->SetZoomLevel(0.0); return true;
    case kCmdBookmarkPage:
      if (tab) {
        if (ctx->bookmarks().Contains(tab->url)) ctx->bookmarks().Remove(tab->url);
        else ctx->bookmarks().Add(tab->url, tab->title, NowUnixMs());
        ctx->bookmarks().Save();
        RefreshToolbar();
      }
      return true;
    case kCmdBookmarks: OpenInNewTab("aegis://bookmarks/", true); return true;
    case kCmdHistory: OpenInNewTab("aegis://history/", true); return true;
    case kCmdDownloads: OpenInNewTab("aegis://downloads/", true); return true;
    case kCmdDashboard: OpenInNewTab("aegis://security/", true); return true;
    case kCmdNetwork: OpenInNewTab("aegis://network/", true); return true;
    case kCmdSiteReport:
      if (tab) OpenInNewTab("aegis://site-report/?url=" + UrlEncodeComponent(tab->url), true);
      return true;
    case kCmdAbout: OpenInNewTab("aegis://about/", true); return true;
    case kCmdModeMax: SetMode(SecurityMode::kMaximumIsolation); return true;
    case kCmdModeStrict: SetMode(SecurityMode::kStrictProtection); return true;
    case kCmdModeCompat: SetMode(SecurityMode::kCompatibility); return true;
    case kCmdSiteAllowJs:
    case kCmdSiteAllowThirdParty:
    case kCmdSiteAllowPopups:
    case kCmdSiteDisableFiltering:
      ToggleSiteException(command_id);
      return true;
    case kCmdSiteBlockJs: {
      std::string key = CurrentSiteKey();
      if (key.empty()) return true;
      ctx->UpdateSettings([&](Settings& s) {
        if (!s.javascript_blocked_sites.erase(key)) s.javascript_blocked_sites.insert(key);
      });
      if (browser) browser->Reload();
      return true;
    }
    case kCmdSiteClearPermissions: {
      auto u = tab ? ParseUrl(tab->url) : std::nullopt;
      if (u) ctx->UpdateSettings([&](Settings& s) { s.permission_grants.erase(u->Origin()); });
      return true;
    }
    case kCmdClearHistory:
    case kCmdClearCookies:
    case kCmdClearCache:
    case kCmdClearSiteDataOnRestart:
      ClearData(command_id);
      return true;
    case kCmdToggleHistory:
      ctx->UpdateSettings([](Settings& s) { s.save_history = !s.save_history; });
      return true;
    case kCmdToggleRestoreTabs:
      ctx->UpdateSettings([](Settings& s) { s.restore_tabs = !s.restore_tabs; });
      return true;
    case kCmdToggleHttpsFirst:
      if (ctx->settings().https_first &&
          !Confirm(L"Turn off HTTPS-first? Pages will load over unencrypted HTTP when a site links to it.",
                   L"WezCrypt Aegis - Lower protection?", true)) {
        return true;
      }
      ctx->UpdateSettings([](Settings& s) { s.https_first = !s.https_first; });
      return true;
    case kCmdToggleThirdPartyCookies:
      if (ctx->settings().block_third_party_cookies &&
          !Confirm(L"Allow third-party cookies? Trackers embedded in pages will be able to recognize you "
                   L"across sites.",
                   L"WezCrypt Aegis - Lower protection?", true)) {
        return true;
      }
      ctx->UpdateSettings([](Settings& s) { s.block_third_party_cookies = !s.block_third_party_cookies; });
      return true;
    case kCmdToggleClearOnExit: {
      const Settings& s0 = ctx->settings();
      bool on = !(s0.clear_cookies_on_exit && s0.clear_cache_on_exit && s0.clear_history_on_exit);
      ctx->UpdateSettings([on](Settings& s) {
        s.clear_cookies_on_exit = on;
        s.clear_cache_on_exit = on;
        s.clear_history_on_exit = on;
      });
      return true;
    }
    case kCmdListBaseline:
    case kCmdListEasyList:
    case kCmdListEasyPrivacy: {
      std::string id = command_id == kCmdListBaseline ? "aegis-baseline"
                       : command_id == kCmdListEasyList ? "easylist" : "easyprivacy";
      bool enabled = true;
      for (const auto& c : ctx->filters().Configs()) if (c.id == id) enabled = c.enabled;
      if (enabled && !Confirm(L"Disable this filter list? Requests it blocks will reach the network again.",
                              L"WezCrypt Aegis - Lower protection?", true)) {
        return true;
      }
      ctx->UpdateSettings([&](Settings& s) { s.filter_lists_enabled[id] = !enabled; });
      return true;
    }
    case kCmdAddRule: PromptAddRule(); return true;
    case kCmdClearRules:
      if (!ctx->settings().user_rules.empty() &&
          Confirm(L"Remove all of your own blocking rules?", L"WezCrypt Aegis", false)) {
        ctx->UpdateSettings([](Settings& s) { s.user_rules.clear(); });
      }
      return true;
    case kCmdUpdateFilters:
      UpdateService::RefreshFilterLists(true);
      Inform(L"Filter list updates were requested. Results appear in the Security Control Center. "
             L"A failed or invalid download never replaces the active lists.",
             L"WezCrypt Aegis");
      return true;
    case kCmdCheckUpdates:
      UpdateService::CheckForBrowserUpdate();
      OpenInNewTab("aegis://security/", true);
      return true;
    case kCmdOpenDownloadsFolder: {
      std::wstring dir = ctx->DefaultDownloadDirectory().wstring();
      // Opens Explorer on the folder; files themselves are never launched.
      ::ShellExecuteW(nullptr, L"explore", dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
      return true;
    }
    case kCmdExit: CloseAll(false); return true;
    default: return false;
  }
}

}  // namespace aegis
