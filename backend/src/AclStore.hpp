#pragma once
#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/sha.h>

enum class Role { Guest = 0, Viewer = 1, User = 2, Admin = 3 };

inline const char* role_name(Role r) {
    switch (r) {
        case Role::Admin:  return "admin";
        case Role::User:   return "user";
        case Role::Viewer: return "viewer";
        default:           return "guest";
    }
}

inline bool role_from_string(const std::string& s, Role& out) {
    if (s == "admin")  { out = Role::Admin;  return true; }
    if (s == "user")   { out = Role::User;   return true; }
    if (s == "viewer") { out = Role::Viewer; return true; }
    if (s == "guest")  { out = Role::Guest;  return true; }
    return false;
}

struct UserRecord {
    std::string password_hash;
    Role        role;
};

struct AclEntry {
    std::string path_prefix;
    Role        min_role;
};

class AclStore {
public:
    AclStore() {
        // Seed users — replace with config-file load for production.
        add_user("admin",  "admin123",  Role::Admin);
        add_user("alice",  "user123",   Role::User);
        add_user("viewer", "viewer123", Role::Viewer);

        // Default ACL: all protected resources require Admin.
        // Lower the min_role for a prefix via set_acl_entry() to open access.
        set_acl_entry("/protected/",  Role::Admin);
        set_acl_entry("/api/private", Role::Admin);
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

    // Matches the longest prefix in the ACL list.
    // If no rule matches, defaults to Admin-only.
    bool authorize(Role role, const std::string& path) const {
        std::shared_lock lock(mutex_);
        const AclEntry* best = nullptr;
        for (const auto& entry : acl_) {
            if (path.rfind(entry.path_prefix, 0) == 0) {
                if (!best || entry.path_prefix.size() > best->path_prefix.size())
                    best = &entry;
            }
        }
        Role required = best ? best->min_role : Role::Admin;
        return static_cast<int>(role) >= static_cast<int>(required);
    }

    // Upsert an ACL entry.
    void set_acl_entry(const std::string& prefix, Role min_role) {
        std::unique_lock lock(mutex_);
        for (auto& e : acl_) {
            if (e.path_prefix == prefix) { e.min_role = min_role; return; }
        }
        acl_.push_back({prefix, min_role});
    }

    void remove_acl_entry(const std::string& prefix) {
        std::unique_lock lock(mutex_);
        acl_.erase(std::remove_if(acl_.begin(), acl_.end(),
            [&](const AclEntry& e){ return e.path_prefix == prefix; }), acl_.end());
    }

    std::vector<AclEntry> list_acl_entries() const {
        std::shared_lock lock(mutex_);
        return acl_;
    }

    // ── User management ───────────────────────────────────────────────────────

    void add_user(const std::string& username, const std::string& password, Role role) {
        std::unique_lock lock(mutex_);
        users_[username] = {sha256(password), role};
    }

    bool remove_user(const std::string& username) {
        std::unique_lock lock(mutex_);
        return users_.erase(username) > 0;
    }

    bool set_user_role(const std::string& username, Role role) {
        std::unique_lock lock(mutex_);
        auto it = users_.find(username);
        if (it == users_.end()) return false;
        it->second.role = role;
        return true;
    }

    // Returns username → role pairs (no passwords).
    std::unordered_map<std::string, Role> list_users() const {
        std::shared_lock lock(mutex_);
        std::unordered_map<std::string, Role> result;
        for (const auto& [k, v] : users_)
            result[k] = v.role;
        return result;
    }

private:
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
    std::vector<AclEntry>                        acl_;
    mutable std::shared_mutex                    mutex_;
};
