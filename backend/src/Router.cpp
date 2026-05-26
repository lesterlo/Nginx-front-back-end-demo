#include "Router.hpp"

http::response<http::string_body>
Router::dispatch(const http::request<http::string_body>& req)
{
    // req.target() returns boost::beast::string_view in Boost 1.74
    auto target = req.target();
    auto method = req.method();

    // ── Auth endpoints ────────────────────────────────────────────────────────
    if (target == "/api/login" && method == http::verb::post)
        return auth_.handle_login(req);

    if (target == "/api/logout" && method == http::verb::post)
        return auth_.handle_logout(req);

    // Called internally by nginx auth_request for /protected/* access.
    if (target == "/auth-check" && method == http::verb::get)
        return auth_.handle_check(req);

    // ── Public API — no authentication required ───────────────────────────────
    if (target == "/api/public" && method == http::verb::get)
        return make_json_response(http::status::ok,
            R"({"message":"This is public data. No authentication required."})");

    // ── Private API — authentication enforced by the backend itself ───────────
    // Unlike /protected/ static files (gated by nginx auth_request), API routes
    // check the token directly so they can return JSON errors instead of redirects.
    if (target == "/api/private" && method == http::verb::get) {
        auto entry = auth_.get_token_entry(req);
        if (!entry)
            return make_json_response(http::status::unauthorized,
                R"({"error":"authentication required"})");
        return make_json_response(http::status::ok,
            R"({"message":"This is private data.","user":")" + entry->username + R"("})");
    }

    return make_response(http::status::not_found, "Not Found");
}
