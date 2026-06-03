#pragma once
// Centralised JSON handling for the web engine.
//
// All (de)serialisation goes through the glaze reflection library
// (https://github.com/stephenberry/glaze) rather than the hand-rolled string
// scanners this replaced. glaze escapes strings correctly, reports parse errors,
// and copes with nested objects / quoted-vs-unquoted values — none of which the
// old json_field()/json_token() helpers handled.
//
// The Role <-> string mapping deliberately stays in Role.hpp
// (role_name/role_from_string): the wire names ("admin"/"user"/"viewer"/"guest")
// have a single source of truth there, and glaze v7's enumerate() would emit the
// capitalised enumerator identifiers instead. DTOs in this codebase therefore
// carry the role as a plain string and convert at the boundary.

#include <optional>
#include <string>
#include <string_view>

#include <glaze/glaze.hpp>

#include "Http.hpp"

namespace webengine {

// Parse a JSON request body into T. Unknown keys are ignored (lenient, matching
// the previous behaviour) so clients may send extra fields. Returns nullopt on
// malformed JSON or a type mismatch (e.g. a string where a number is expected).
template <class T>
inline std::optional<T> parse_json(std::string_view body) {
    T value{};
    const auto ec = glz::read<glz::opts{.error_on_unknown_keys = false}>(value, body);
    if (ec) return std::nullopt;
    return value;
}

// Serialise `value` to a JSON string, or nullopt if glaze fails to write (not
// expected for the value types used here).
template <class T>
inline std::optional<std::string> to_json(const T& value) {
    std::string out;
    if (glz::write_json(value, out)) return std::nullopt;   // error_ctx → truthy on error
    return out;
}

// 200 OK whose body is `value` serialised to JSON.
template <class T>
inline Response json_ok(const T& value) {
    if (auto s = to_json(value))
        return json(http::status::ok, std::move(*s));
    return json(http::status::internal_server_error, R"({"error":"serialization failed"})");
}

// A JSON error response: {"error": <message>} with `message` correctly escaped.
inline Response json_error(http::status st, std::string_view message) {
    return json(st, to_json(glz::obj{"error", message})
                        .value_or(std::string{R"({"error":"error"})"}));
}

// The ubiquitous {"status":"ok"} success body.
inline Response json_status_ok() {
    return json(http::status::ok, R"({"status":"ok"})");
}

} // namespace webengine
