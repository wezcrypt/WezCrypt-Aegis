// WezCrypt Aegis - small modal text-entry window (CEF Views).
#pragma once

#include <functional>
#include <string>

#include "include/views/cef_label_button.h"
#include "include/views/cef_textfield.h"
#include "include/views/cef_window.h"

namespace aegis {

class PromptWindow : public CefWindowDelegate, public CefButtonDelegate, public CefTextfieldDelegate {
 public:
  using Callback = std::function<void(const std::string& text)>;

  // Shows a window-modal prompt over |parent|. |on_accept| runs on the UI
  // thread only when the user confirms.
  static void Show(CefRefPtr<CefWindow> parent, const std::string& title, const std::string& message,
                   Callback on_accept);

  void OnWindowCreated(CefRefPtr<CefWindow> window) override;
  void OnWindowDestroyed(CefRefPtr<CefWindow> window) override;
  CefRefPtr<CefWindow> GetParentWindow(CefRefPtr<CefWindow> window, bool* is_menu,
                                       bool* can_activate_menu) override;
  bool IsWindowModalDialog(CefRefPtr<CefWindow>) override { return true; }
  CefRect GetInitialBounds(CefRefPtr<CefWindow> window) override;
  bool CanResize(CefRefPtr<CefWindow>) override { return false; }
  bool CanMaximize(CefRefPtr<CefWindow>) override { return false; }
  bool CanMinimize(CefRefPtr<CefWindow>) override { return false; }
  cef_runtime_style_t GetWindowRuntimeStyle() override { return CEF_RUNTIME_STYLE_ALLOY; }

  void OnButtonPressed(CefRefPtr<CefButton> button) override;
  bool OnKeyEvent(CefRefPtr<CefTextfield> textfield, const CefKeyEvent& event) override;

 private:
  PromptWindow(CefRefPtr<CefWindow> parent, std::string title, std::string message, Callback cb);
  void Accept();

  CefRefPtr<CefWindow> parent_;
  CefRefPtr<CefWindow> window_;
  CefRefPtr<CefTextfield> field_;
  std::string title_;
  std::string message_;
  Callback callback_;
  IMPLEMENT_REFCOUNTING(PromptWindow);
};

}  // namespace aegis
