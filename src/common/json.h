// WezCrypt Aegis - minimal strict JSON (RFC 8259) used for settings,
// update manifests and local stores. Hardened against hostile input with
// size and nesting limits.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace aegis::json {

class Value;
using Array = std::vector<Value>;
using Object = std::map<std::string, Value>;

class Value {
 public:
  enum class Type { kNull, kBool, kNumber, kString, kArray, kObject };

  Value() = default;
  Value(std::nullptr_t) {}
  Value(bool b) : data_(b) {}
  Value(int v) : data_(static_cast<double>(v)) {}
  Value(std::int64_t v) : data_(static_cast<double>(v)) {}
  Value(std::uint64_t v) : data_(static_cast<double>(v)) {}
  Value(double v) : data_(v) {}
  Value(const char* s) : data_(std::string(s)) {}
  Value(std::string s) : data_(std::move(s)) {}
  Value(std::string_view s) : data_(std::string(s)) {}
  Value(Array a) : data_(std::make_shared<Array>(std::move(a))) {}
  Value(Object o) : data_(std::make_shared<Object>(std::move(o))) {}

  Type type() const noexcept;
  bool is_null() const noexcept { return type() == Type::kNull; }
  bool is_bool() const noexcept { return type() == Type::kBool; }
  bool is_number() const noexcept { return type() == Type::kNumber; }
  bool is_string() const noexcept { return type() == Type::kString; }
  bool is_array() const noexcept { return type() == Type::kArray; }
  bool is_object() const noexcept { return type() == Type::kObject; }

  bool as_bool(bool def = false) const noexcept;
  double as_number(double def = 0) const noexcept;
  // Returns |def| unless the number is integral and within range.
  std::int64_t as_int(std::int64_t def = 0) const noexcept;
  const std::string& as_string() const;  // empty string if not a string
  const Array& as_array() const;         // empty array if not an array
  const Object& as_object() const;       // empty object if not an object
  Array& mutable_array();                // converts to array if needed
  Object& mutable_object();              // converts to object if needed

  // Object member lookup; returns nullptr if missing or not an object.
  const Value* Find(std::string_view key) const;
  std::string GetString(std::string_view key, std::string def = {}) const;
  bool GetBool(std::string_view key, bool def) const;
  std::int64_t GetInt(std::string_view key, std::int64_t def) const;

 private:
  // Containers are held through shared_ptr for cheap copies; mutation
  // performs copy-on-write.
  std::variant<std::monostate, bool, double, std::string,
               std::shared_ptr<Array>, std::shared_ptr<Object>>
      data_;
};

struct ParseLimits {
  std::size_t max_bytes = 32 * 1024 * 1024;
  int max_depth = 64;
  std::size_t max_string_bytes = 8 * 1024 * 1024;
  std::size_t max_elements = 2'000'000;
};

struct ParseError {
  std::size_t offset = 0;
  std::string message;
};

std::optional<Value> Parse(std::string_view text, ParseError* error = nullptr,
                           const ParseLimits& limits = {});

// Serializes deterministically (object keys sorted). |indent| < 0 produces
// compact output.
std::string Serialize(const Value& v, int indent = 2);

}  // namespace aegis::json
