#include "common/json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "common/utf8.h"

namespace aegis::json {
namespace {

const std::string& EmptyString() {
  static const std::string* s = new std::string();
  return *s;
}
const Array& EmptyArray() {
  static const Array* a = new Array();
  return *a;
}
const Object& EmptyObject() {
  static const Object* o = new Object();
  return *o;
}

class Parser {
 public:
  Parser(std::string_view text, const ParseLimits& limits)
      : s_(text), limits_(limits) {}

  std::optional<Value> Run(ParseError* err) {
    if (s_.size() > limits_.max_bytes) return Fail(err, "input too large");
    if (!IsValidUtf8(s_)) return Fail(err, "invalid UTF-8");
    // Optional UTF-8 BOM.
    if (s_.size() >= 3 && static_cast<unsigned char>(s_[0]) == 0xEF &&
        static_cast<unsigned char>(s_[1]) == 0xBB &&
        static_cast<unsigned char>(s_[2]) == 0xBF) {
      pos_ = 3;
    }
    Value v;
    if (!ParseValue(&v, 0)) return Fail(err, error_);
    SkipWs();
    if (pos_ != s_.size()) return Fail(err, "trailing characters");
    return v;
  }

 private:
  std::optional<Value> Fail(ParseError* err, const std::string& msg) {
    if (err) {
      err->offset = pos_;
      err->message = msg;
    }
    return std::nullopt;
  }

  bool Error(const char* msg) {
    if (error_.empty()) error_ = msg;
    return false;
  }

  void SkipWs() {
    while (pos_ < s_.size()) {
      char c = s_[pos_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++pos_;
      } else {
        break;
      }
    }
  }

  bool CountElement() {
    if (++elements_ > limits_.max_elements) return Error("too many elements");
    return true;
  }

  bool ParseValue(Value* out, int depth) {
    if (depth > limits_.max_depth) return Error("nesting too deep");
    if (!CountElement()) return false;
    SkipWs();
    if (pos_ >= s_.size()) return Error("unexpected end of input");
    char c = s_[pos_];
    switch (c) {
      case '{': return ParseObject(out, depth);
      case '[': return ParseArray(out, depth);
      case '"': {
        std::string str;
        if (!ParseString(&str)) return false;
        *out = Value(std::move(str));
        return true;
      }
      case 't': return ParseLiteral("true", Value(true), out);
      case 'f': return ParseLiteral("false", Value(false), out);
      case 'n': return ParseLiteral("null", Value(nullptr), out);
      default:
        if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber(out);
        return Error("unexpected character");
    }
  }

  bool ParseLiteral(std::string_view lit, Value v, Value* out) {
    if (s_.substr(pos_, lit.size()) != lit) return Error("invalid literal");
    pos_ += lit.size();
    *out = std::move(v);
    return true;
  }

  bool ParseNumber(Value* out) {
    std::size_t start = pos_;
    if (s_[pos_] == '-') ++pos_;
    if (pos_ >= s_.size()) return Error("invalid number");
    if (s_[pos_] == '0') {
      ++pos_;
    } else if (s_[pos_] >= '1' && s_[pos_] <= '9') {
      while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
    } else {
      return Error("invalid number");
    }
    if (pos_ < s_.size() && s_[pos_] == '.') {
      ++pos_;
      std::size_t d = pos_;
      while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
      if (pos_ == d) return Error("invalid number");
    }
    if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
      ++pos_;
      if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
      std::size_t d = pos_;
      while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
      if (pos_ == d) return Error("invalid number");
    }
    std::size_t len = pos_ - start;
    if (len > 64) return Error("number too long");
    char buf[80];
    std::memcpy(buf, s_.data() + start, len);
    buf[len] = '\0';
    char* end = nullptr;
    double v = std::strtod(buf, &end);
    if (end != buf + len || !std::isfinite(v)) return Error("invalid number");
    *out = Value(v);
    return true;
  }

  bool ParseHex4(unsigned* out) {
    if (pos_ + 4 > s_.size()) return Error("truncated escape");
    unsigned v = 0;
    for (int i = 0; i < 4; ++i) {
      char c = s_[pos_++];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned>(c - 'A' + 10);
      else return Error("invalid escape");
    }
    *out = v;
    return true;
  }

  bool ParseString(std::string* out) {
    ++pos_;  // opening quote
    while (true) {
      if (pos_ >= s_.size()) return Error("unterminated string");
      if (out->size() > limits_.max_string_bytes) return Error("string too long");
      char c = s_[pos_];
      if (c == '"') {
        ++pos_;
        return true;
      }
      if (static_cast<unsigned char>(c) < 0x20) return Error("control character in string");
      if (c != '\\') {
        out->push_back(c);
        ++pos_;
        continue;
      }
      ++pos_;
      if (pos_ >= s_.size()) return Error("unterminated escape");
      char e = s_[pos_++];
      switch (e) {
        case '"': out->push_back('"'); break;
        case '\\': out->push_back('\\'); break;
        case '/': out->push_back('/'); break;
        case 'b': out->push_back('\b'); break;
        case 'f': out->push_back('\f'); break;
        case 'n': out->push_back('\n'); break;
        case 'r': out->push_back('\r'); break;
        case 't': out->push_back('\t'); break;
        case 'u': {
          unsigned cp;
          if (!ParseHex4(&cp)) return false;
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (pos_ + 2 > s_.size() || s_[pos_] != '\\' || s_[pos_ + 1] != 'u')
              return Error("unpaired surrogate");
            pos_ += 2;
            unsigned lo;
            if (!ParseHex4(&lo)) return false;
            if (lo < 0xDC00 || lo > 0xDFFF) return Error("unpaired surrogate");
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            return Error("unpaired surrogate");
          }
          AppendUtf8(static_cast<char32_t>(cp), out);
          break;
        }
        default:
          return Error("invalid escape");
      }
    }
  }

  bool ParseArray(Value* out, int depth) {
    ++pos_;
    Array arr;
    SkipWs();
    if (pos_ < s_.size() && s_[pos_] == ']') {
      ++pos_;
      *out = Value(std::move(arr));
      return true;
    }
    while (true) {
      Value v;
      if (!ParseValue(&v, depth + 1)) return false;
      arr.push_back(std::move(v));
      SkipWs();
      if (pos_ >= s_.size()) return Error("unterminated array");
      if (s_[pos_] == ',') {
        ++pos_;
        continue;
      }
      if (s_[pos_] == ']') {
        ++pos_;
        *out = Value(std::move(arr));
        return true;
      }
      return Error("expected ',' or ']'");
    }
  }

  bool ParseObject(Value* out, int depth) {
    ++pos_;
    Object obj;
    SkipWs();
    if (pos_ < s_.size() && s_[pos_] == '}') {
      ++pos_;
      *out = Value(std::move(obj));
      return true;
    }
    while (true) {
      SkipWs();
      if (pos_ >= s_.size() || s_[pos_] != '"') return Error("expected key");
      std::string key;
      if (!ParseString(&key)) return false;
      SkipWs();
      if (pos_ >= s_.size() || s_[pos_] != ':') return Error("expected ':'");
      ++pos_;
      Value v;
      if (!ParseValue(&v, depth + 1)) return false;
      // Duplicate keys are rejected: ambiguous documents are a classic
      // source of parser-differential bugs in signed data.
      if (obj.count(key)) return Error("duplicate key");
      obj.emplace(std::move(key), std::move(v));
      SkipWs();
      if (pos_ >= s_.size()) return Error("unterminated object");
      if (s_[pos_] == ',') {
        ++pos_;
        continue;
      }
      if (s_[pos_] == '}') {
        ++pos_;
        *out = Value(std::move(obj));
        return true;
      }
      return Error("expected ',' or '}'");
    }
  }

  std::string_view s_;
  const ParseLimits& limits_;
  std::size_t pos_ = 0;
  std::size_t elements_ = 0;
  std::string error_;
};

void SerializeString(const std::string& s, std::string* out) {
  out->push_back('"');
  for (unsigned char c : s) {
    switch (c) {
      case '"': *out += "\\\""; break;
      case '\\': *out += "\\\\"; break;
      case '\n': *out += "\\n"; break;
      case '\r': *out += "\\r"; break;
      case '\t': *out += "\\t"; break;
      case '\b': *out += "\\b"; break;
      case '\f': *out += "\\f"; break;
      default:
        if (c < 0x20 || c == 0x7f) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          *out += buf;
        } else {
          out->push_back(static_cast<char>(c));
        }
    }
  }
  out->push_back('"');
}

void SerializeImpl(const Value& v, int indent, int level, std::string* out) {
  auto newline = [&](int lvl) {
    if (indent < 0) return;
    out->push_back('\n');
    out->append(static_cast<std::size_t>(indent * lvl), ' ');
  };
  switch (v.type()) {
    case Value::Type::kNull: *out += "null"; break;
    case Value::Type::kBool: *out += v.as_bool() ? "true" : "false"; break;
    case Value::Type::kNumber: {
      double d = v.as_number();
      char buf[40];
      if (d == std::floor(d) && std::fabs(d) < 9.007199254740992e15) {
        std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(d));
      } else {
        std::snprintf(buf, sizeof(buf), "%.17g", d);
      }
      *out += buf;
      break;
    }
    case Value::Type::kString: SerializeString(v.as_string(), out); break;
    case Value::Type::kArray: {
      const Array& a = v.as_array();
      out->push_back('[');
      for (std::size_t i = 0; i < a.size(); ++i) {
        if (i) out->push_back(',');
        newline(level + 1);
        SerializeImpl(a[i], indent, level + 1, out);
      }
      if (!a.empty()) newline(level);
      out->push_back(']');
      break;
    }
    case Value::Type::kObject: {
      const Object& o = v.as_object();
      out->push_back('{');
      bool first = true;
      for (const auto& [k, val] : o) {
        if (!first) out->push_back(',');
        first = false;
        newline(level + 1);
        SerializeString(k, out);
        out->push_back(':');
        if (indent >= 0) out->push_back(' ');
        SerializeImpl(val, indent, level + 1, out);
      }
      if (!o.empty()) newline(level);
      out->push_back('}');
      break;
    }
  }
}

}  // namespace

Value::Type Value::type() const noexcept {
  switch (data_.index()) {
    case 0: return Type::kNull;
    case 1: return Type::kBool;
    case 2: return Type::kNumber;
    case 3: return Type::kString;
    case 4: return Type::kArray;
    default: return Type::kObject;
  }
}

bool Value::as_bool(bool def) const noexcept {
  if (auto* b = std::get_if<bool>(&data_)) return *b;
  return def;
}

double Value::as_number(double def) const noexcept {
  if (auto* d = std::get_if<double>(&data_)) return *d;
  return def;
}

std::int64_t Value::as_int(std::int64_t def) const noexcept {
  auto* d = std::get_if<double>(&data_);
  if (!d) return def;
  if (*d != std::floor(*d) || std::fabs(*d) > 9.007199254740992e15) return def;
  return static_cast<std::int64_t>(*d);
}

const std::string& Value::as_string() const {
  if (auto* s = std::get_if<std::string>(&data_)) return *s;
  return EmptyString();
}

const Array& Value::as_array() const {
  if (auto* a = std::get_if<std::shared_ptr<Array>>(&data_)) return **a;
  return EmptyArray();
}

const Object& Value::as_object() const {
  if (auto* o = std::get_if<std::shared_ptr<Object>>(&data_)) return **o;
  return EmptyObject();
}

Array& Value::mutable_array() {
  auto* a = std::get_if<std::shared_ptr<Array>>(&data_);
  if (!a) {
    data_ = std::make_shared<Array>();
    a = std::get_if<std::shared_ptr<Array>>(&data_);
  } else if (a->use_count() > 1) {
    *a = std::make_shared<Array>(**a);
  }
  return **a;
}

Object& Value::mutable_object() {
  auto* o = std::get_if<std::shared_ptr<Object>>(&data_);
  if (!o) {
    data_ = std::make_shared<Object>();
    o = std::get_if<std::shared_ptr<Object>>(&data_);
  } else if (o->use_count() > 1) {
    *o = std::make_shared<Object>(**o);
  }
  return **o;
}

const Value* Value::Find(std::string_view key) const {
  auto* o = std::get_if<std::shared_ptr<Object>>(&data_);
  if (!o) return nullptr;
  auto it = (*o)->find(std::string(key));
  return it == (*o)->end() ? nullptr : &it->second;
}

std::string Value::GetString(std::string_view key, std::string def) const {
  const Value* v = Find(key);
  return (v && v->is_string()) ? v->as_string() : def;
}

bool Value::GetBool(std::string_view key, bool def) const {
  const Value* v = Find(key);
  return (v && v->is_bool()) ? v->as_bool() : def;
}

std::int64_t Value::GetInt(std::string_view key, std::int64_t def) const {
  const Value* v = Find(key);
  return v ? v->as_int(def) : def;
}

std::optional<Value> Parse(std::string_view text, ParseError* error,
                           const ParseLimits& limits) {
  Parser p(text, limits);
  return p.Run(error);
}

std::string Serialize(const Value& v, int indent) {
  std::string out;
  SerializeImpl(v, indent, 0, &out);
  if (indent >= 0) out.push_back('\n');
  return out;
}

}  // namespace aegis::json
