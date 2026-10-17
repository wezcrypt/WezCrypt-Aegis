#include "ui/prompt_window.h"

#include <windows.h>

#include "include/cef_color_ids.h"
#include "include/views/cef_box_layout.h"
#include "include/views/cef_panel.h"
#include "include/wrapper/cef_helpers.h"
#include "ui/theme.h"

namespace aegis {
namespace {
constexpr int kIdOk = 1;
constexpr int kIdCancel = 2;
}  // namespace

void PromptWindow::Show(CefRefPtr<CefWindow> parent, const std::string& title, const std::string& message,
                        Callback on_accept) {
  CEF_REQUIRE_UI_THREAD();
  CefWindow::CreateTopLevelWindow(new PromptWindow(parent, title, message, std::move(on_accept)));
}

PromptWindow::PromptWindow(CefRefPtr<CefWindow> parent, std::string title, std::string message, Callback cb)
    : parent_(parent), title_(std::move(title)), message_(std::move(message)), callback_(std::move(cb)) {}

CefRefPtr<CefWindow> PromptWindow::GetParentWindow(CefRefPtr<CefWindow>, bool* is_menu, bool* can_activate_menu) {
  *is_menu = false;
  *can_activate_menu = false;
  return parent_;
}

CefRect PromptWindow::GetInitialBounds(CefRefPtr<CefWindow>) {
  CefRect r(0, 0, 620, 170);
  if (parent_) {
    CefRect p = parent_->GetBoundsInScreen();
    r.x = p.x + (p.width - r.width) / 2;
    r.y = p.y + (p.height - r.height) / 3;
  }
  return r;
}

void PromptWindow::OnWindowCreated(CefRefPtr<CefWindow> window) {
  window_ = window;
  window_->SetTitle(title_);
  window_->SetBackgroundColor(theme::kToolbarBackground);
  window_->SetThemeColor(CEF_ColorTextfieldForeground, theme::kTextPrimary);
  window_->SetThemeColor(CEF_ColorTextfieldBackground, theme::kFieldBackground);
  window_->ThemeChanged();
  CefBoxLayoutSettings v;
  v.horizontal = false;
  v.inside_border_insets = {14, 16, 14, 16};
  v.between_child_spacing = 10;
  window_->SetToBoxLayout(v);

  auto label = CefLabelButton::CreateLabelButton(this, message_);
  label->SetEnabled(false);
  label->SetFontList(theme::kUiFont);
  label->SetTextColor(CEF_BUTTON_STATE_DISABLED, theme::kTextPrimary);
  label->SetBackgroundColor(theme::kToolbarBackground);
  label->SetHorizontalAlignment(CEF_HORIZONTAL_ALIGNMENT_LEFT);
  window_->AddChildView(label);

  field_ = CefTextfield::CreateTextfield(this);
  field_->SetFontList(theme::kAddressFont);
  field_->SetBackgroundColor(theme::kFieldBackground);
  field_->SetAccessibleName(title_);
  window_->AddChildView(field_);

  auto buttons = CefPanel::CreatePanel(nullptr);
  buttons->SetBackgroundColor(theme::kToolbarBackground);
  CefBoxLayoutSettings h;
  h.horizontal = true;
  h.between_child_spacing = 8;
  h.main_axis_alignment = CEF_AXIS_ALIGNMENT_END;
  buttons->SetToBoxLayout(h);
  auto ok = CefLabelButton::CreateLabelButton(this, "Add");
  ok->SetID(kIdOk);
  auto cancel = CefLabelButton::CreateLabelButton(this, "Cancel");
  cancel->SetID(kIdCancel);
  for (auto& b : {ok, cancel}) {
    b->SetFontList(theme::kUiFont);
    b->SetEnabledTextColors(b == ok ? theme::kAccentCyan : theme::kTextPrimary);
    b->SetBackgroundColor(theme::kFieldBackground);
    b->SetMinimumSize(CefSize(90, 30));
    buttons->AddChildView(b);
  }
  window_->AddChildView(buttons);
  window_->Show();
  field_->RequestFocus();
}

void PromptWindow::OnWindowDestroyed(CefRefPtr<CefWindow>) {
  window_ = nullptr;
  field_ = nullptr;
  parent_ = nullptr;
}

void PromptWindow::Accept() {
  std::string text = field_ ? field_->GetText().ToString() : std::string();
  Callback cb = std::move(callback_);
  callback_ = nullptr;
  if (window_) window_->Close();
  if (cb) cb(text);
}

void PromptWindow::OnButtonPressed(CefRefPtr<CefButton> button) {
  if (button->GetID() == kIdOk) {
    Accept();
  } else if (button->GetID() == kIdCancel && window_) {
    callback_ = nullptr;
    window_->Close();
  }
}

bool PromptWindow::OnKeyEvent(CefRefPtr<CefTextfield>, const CefKeyEvent& event) {
  if (event.type != KEYEVENT_RAWKEYDOWN) return false;
  if (event.windows_key_code == VK_RETURN) {
    Accept();
    return true;
  }
  if (event.windows_key_code == VK_ESCAPE && window_) {
    callback_ = nullptr;
    window_->Close();
    return true;
  }
  return false;
}

}  // namespace aegis
