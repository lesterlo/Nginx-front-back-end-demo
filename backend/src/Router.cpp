#include "Router.hpp"

http::response<http::string_body>
Router::dispatch(const http::request<http::string_body>& req)
{
    // req.target() returns boost::beast::string_view in Boost 1.74
    auto   target = req.target();
    auto   method = req.method();

    if (target == "/api/login" && method == http::verb::post)
        return auth_.handle_login(req);

    if (target == "/api/logout" && method == http::verb::post)
        return auth_.handle_logout(req);

    if (target == "/auth-check" && method == http::verb::get)
        return auth_.handle_check(req);

    return make_response(http::status::not_found, "Not Found");
}
