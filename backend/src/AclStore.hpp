#pragma once
#include <map>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/sha.h>

enum class Role { Guest, User, Admin };

struct UserRecord {
    std::string password_hash;
    Role        role;
};

class AclStore {
public:
    AclStore() {
        // Seed credentials — replace with config-file load for production.
        add_user("admin", "admin123", Role::Admin);
        add_user("alice", "user123",  Role::User);

        // Role → allowed URI prefixes.
        role_acl_[Role::Admin] = {"/protected/"};
        role_acl_[Role::User]  = {"/protected/dashboard.html"};
    }

    bool authenticate(const std::string& username,
                      const std::string& password,
                      Role& out_role) const
    {
        std::shared_lock lock(mutex_);
        auto it = users_.find(username);
        if (it == users_.end()) return false;
        if (it->second.password_hash != sha256(password)) return false;
        out_role = it->second.role;
        return true;
    }

    bool authorize(Role role, const std::string& path) const {
        std::shared_lock lock(mutex_);
        auto it = role_acl_.find(role);
        if (it == role_acl_.end()) return false;
        for (const auto& prefix : it->second)
            if (path.rfind(prefix, 0) == 0) return true;
        return false;
    }

private:
    void add_user(const std::string& user, const std::string& pass, Role role) {
        users_[user] = {sha256(pass), role};
    }

    static std::string sha256(const std::string& input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(input.data()),
               input.size(), hash);
        char hex[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
            snprintf(hex + i * 2, 3, "%02x", hash[i]);
        return {hex, SHA256_DIGEST_LENGTH * 2};
    }

    std::unordered_map<std::string, UserRecord> users_;
    std::map<Role, std::vector<std::string>>     role_acl_;
    mutable std::shared_mutex                    mutex_;
};
