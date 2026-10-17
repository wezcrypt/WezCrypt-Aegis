// WezCrypt Aegis - request resource types as understood by filter rules.
#pragma once

#include <cstdint>
#include <string_view>

namespace aegis {

enum ResourceType : std::uint32_t {
  kResourceNone = 0,
  kResourceDocument = 1u << 0,     // top-level navigation
  kResourceSubdocument = 1u << 1,  // iframe / frame
  kResourceStylesheet = 1u << 2,
  kResourceScript = 1u << 3,       // includes worker and service-worker scripts
  kResourceImage = 1u << 4,
  kResourceFont = 1u << 5,
  kResourceObject = 1u << 6,       // plugin content
  kResourceXhr = 1u << 7,          // fetch() / XMLHttpRequest
  kResourcePing = 1u << 8,         // navigator.sendBeacon, <a ping>
  kResourceMedia = 1u << 9,
  kResourceWebSocket = 1u << 10,
  kResourceOther = 1u << 11,
  kResourcePopup = 1u << 12,       // window.open / target=_blank navigations
};

// All types a blocking rule without type options applies to (ABP semantics:
// documents and popups need explicit opt-in).
inline constexpr std::uint32_t kDefaultRuleTypes =
    kResourceSubdocument | kResourceStylesheet | kResourceScript |
    kResourceImage | kResourceFont | kResourceObject | kResourceXhr |
    kResourcePing | kResourceMedia | kResourceWebSocket | kResourceOther;

inline constexpr std::uint32_t kAllResourceTypes =
    kDefaultRuleTypes | kResourceDocument | kResourcePopup;

std::string_view ResourceTypeName(ResourceType t);

}  // namespace aegis
