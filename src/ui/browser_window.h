// WezCrypt Aegis - top-level browser window built with CEF Views.
#pragma once

#include <functional>
#include <string>
#include <vector>

#include "browser/client_handler.h"
#include "include/views/cef_browser_view.h"
#include "include/views/cef_label_button.h"
#include "include/views/cef_menu_button.h"
#include "include/views/cef_panel.h"
#include "include/views/cef_textfield.h"
#include "include/views/cef_window.h"
#include "security/security_mode.h"

namespace aegis {

class BrowserWindow : public CefWindowDelegate,
                      public CefBrowserViewDelegate,
                      public CefMenuButtonDelegate,
                      public CefMenuModelDelegate,
                      public CefTextfieldDelegate,
                      public TabHost {
 public:
  // Opens a new window. |urls| empty opens the home page.
  static void Open(bool private_window, const std::vector<std::string>& urls);
  // Closes every window (used for fail-closed shutdown).
  static void CloseAll(bool force);
  // Recreates every tab so browser-level engine settings follow the mode.
  static void RecreateAllTabs();
  static int OpenWindowCount();

  // CefWindowDelegate
  void OnWindowCreated(CefRefPtr<CefWindow> window) override;
  void OnWindowClosing(CefRefPtr<CefWindow> window) override;
  void OnWindowDestroyed(CefRefPtr<CefWindow> window) override;
  CefRect GetInitialBounds(CefRefPtr<CefWindow> window) override;
  cef_show_state_t GetInitialShowState(CefRefPtr<CefWindow> window) override;
  bool CanClose(CefRefPtr<CefWindow> window) override;
  bool OnAccelerator(CefRefPtr<CefWindow> window, int command_id) override;
  cef_runtime_style_t GetWindowRuntimeStyle() override { return CEF_RUNTIME_STYLE_ALLOY; }
  CefSize GetMinimumSize(CefRefPtr<CefView> view) override;
  void OnThemeColorsChanged(CefRefPtr<CefWindow> window, bool chrome_theme) override;

  // CefBrowserViewDelegate
  cef_runtime_style_t GetBrowserRuntimeStyle() override { return CEF_RUNTIME_STYLE_ALLOY; }
  bool OnPopupBrowserViewCreated(CefRefPtr<CefBrowserView> browser_view,
                                 CefRefPtr<CefBrowserView> popup_browser_view,
                                 bool is_devtools) override;

  // CefButtonDelegate / CefMenuButtonDelegate
  void OnButtonPressed(CefRefPtr<CefButton> button) override;
  void OnMenuButtonPressed(CefRefPtr<CefMenuButton> menu_button, const CefPoint& screen_point,
                           CefRefPtr<CefMenuButtonPressedLock> button_pressed_lock) override;

  // CefMenuModelDelegate
  void ExecuteCommand(CefRefPtr<CefMenuModel> menu_model, int command_id,
                      cef_event_flags_t event_flags) override;

  // CefTextfieldDelegate
  bool OnKeyEvent(CefRefPtr<CefTextfield> textfield, const CefKeyEvent& event) override;

  // TabHost
  void OnTabCreated(CefRefPtr<CefBrowser> browser) override;
  void OnTabClosed(int browser_id) override;
  void OnTabAddressChanged(int browser_id, const std::string& url) override;
  void OnTabTitleChanged(int browser_id, const std::string& title) override;
  void OnTabLoadingState(int browser_id, bool loading, bool can_back, bool can_forward) override;
  void OnTabStatusMessage(int browser_id, const std::string& text) override;
  void OnTabFindResult(int browser_id, int count, int active, bool final_update) override;
  void OnTabSecurityEvent(int browser_id) override;
  void OpenInNewTab(const std::string& url, bool foreground) override;
  bool IsPrivateWindow() const override { return private_; }
  void* NativeWindowHandle() override;

 private:
  struct Tab {
    int key = 0;
    CefRefPtr<CefBrowserView> view;
    CefRefPtr<CefLabelButton> button;
    CefRefPtr<CefLabelButton> close;
    int browser_id = -1;
    std::string url;
    std::string title;
    bool loading = false;
    bool can_back = false;
    bool can_forward = false;
  };

  BrowserWindow(bool private_window, std::vector<std::string> urls);

  void BuildLayout();
  void InstallAccelerators();
  CefBrowserSettings MakeBrowserSettings() const;
  int AddTab(const std::string& url, bool activate, int index = -1);
  void ActivateTab(int key);
  void CloseTab(int key);
  void RecreateTabs();
  Tab* FindTab(int key);
  Tab* FindTabByBrowser(int browser_id);
  Tab* ActiveTab();
  CefRefPtr<CefBrowser> ActiveBrowser();
  void Navigate(const std::string& input);
  void RefreshToolbar();
  void RefreshTabButton(Tab& t);
  void RefreshSecurityIndicator();
  void ShowFindBar(bool show);
  void FindNext(bool forward);
  void ShowSiteMenu(CefRefPtr<CefMenuButton> button, const CefPoint& pt);
  void ShowMainMenu(CefRefPtr<CefMenuButton> button, const CefPoint& pt);
  void ShowModeMenu(CefRefPtr<CefMenuButton> button, const CefPoint& pt);
  void SetMode(SecurityMode mode);
  void ToggleSiteException(int command_id);
  void ClearData(int command_id);
  void PromptAddRule();
  bool Confirm(const std::wstring& text, const std::wstring& title, bool warning);
  void Inform(const std::wstring& text, const std::wstring& title);
  std::string CurrentSiteKey();
  CefRefPtr<CefLabelButton> MakeIconButton(int id, const char* glyph, const char* tooltip);

  const bool private_;
  std::vector<std::string> initial_urls_;
  CefRefPtr<CefWindow> window_;
  CefRefPtr<ClientHandler> client_;
  CefRefPtr<CefRequestContext> request_context_;

  CefRefPtr<CefPanel> tab_strip_;
  CefRefPtr<CefPanel> toolbar_;
  CefRefPtr<CefPanel> find_bar_;
  CefRefPtr<CefPanel> content_;
  CefRefPtr<CefPanel> status_bar_;
  CefRefPtr<CefLabelButton> new_tab_button_;
  CefRefPtr<CefLabelButton> back_;
  CefRefPtr<CefLabelButton> forward_;
  CefRefPtr<CefLabelButton> reload_;
  CefRefPtr<CefLabelButton> home_;
  CefRefPtr<CefMenuButton> site_button_;
  CefRefPtr<CefTextfield> address_;
  CefRefPtr<CefLabelButton> bookmark_;
  CefRefPtr<CefLabelButton> shield_;
  CefRefPtr<CefMenuButton> mode_button_;
  CefRefPtr<CefMenuButton> menu_button_;
  CefRefPtr<CefTextfield> find_field_;
  CefRefPtr<CefLabelButton> find_status_;
  CefRefPtr<CefLabelButton> status_text_;
  CefRefPtr<CefLabelButton> status_mode_;

  std::vector<Tab> tabs_;
  struct Orphan {
    int browser_id;
    CefRefPtr<CefBrowserView> view;
  };
  std::vector<Orphan> orphans_;
  std::vector<std::string> closed_urls_;
  int active_key_ = -1;
  int next_key_ = 1;
  std::string last_find_;
  bool closing_ = false;

  IMPLEMENT_REFCOUNTING(BrowserWindow);
};

}  // namespace aegis
