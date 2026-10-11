#pragma once
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <array>
#include <stdexcept>

namespace claude_guard {
// OR is represented by separate blocking filters; no overriding permit is installed.
struct Rule {
    GUID layer;
    std::array<FWPM_FILTER_CONDITION0, 2> conditions{};
    UINT32 count = 1;
};

inline std::array<Rule, 4> loopback_only(FWP_BYTE_BLOB* app, UINT16 port) {
    if (!app || !app->data || !app->size || !port) {
        throw std::invalid_argument("Application identity and nonzero gateway port required");
    }
    std::array<Rule, 4> rules{};
    for (auto& rule : rules) {
        rule.layer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        auto& identity = rule.conditions[0];
        identity.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        identity.matchType = FWP_MATCH_EQUAL;
        identity.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        identity.conditionValue.byteBlob = app;
    }
    rules[0].layer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    for (size_t i = 1; i < rules.size(); ++i) {
        rules[i].count = 2;
        rules[i].conditions[1].matchType = FWP_MATCH_NOT_EQUAL;
    }
    auto& address = rules[1].conditions[1];
    address.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    address.conditionValue.type = FWP_UINT32;
    address.conditionValue.uint32 = 0x7f000001;
    auto& endpoint = rules[2].conditions[1];
    endpoint.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    endpoint.conditionValue.type = FWP_UINT16;
    endpoint.conditionValue.uint16 = port;
    auto& protocol = rules[3].conditions[1];
    protocol.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    protocol.conditionValue.type = FWP_UINT8;
    protocol.conditionValue.uint8 = IPPROTO_TCP;
    return rules;
}

inline std::array<Rule, 2> local_services_only(FWP_BYTE_BLOB* app) {
    if (!app || !app->data || !app->size) throw std::invalid_argument("Application identity required");
    static FWP_V4_ADDR_AND_MASK local4{0x7f000000, 0xff000000};
    static FWP_BYTE_ARRAY16 local6{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
    std::array<Rule, 2> rules{};
    for (auto& rule : rules) {
        rule.count = 2;
        auto& identity = rule.conditions[0];
        identity.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        identity.matchType = FWP_MATCH_EQUAL;
        identity.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        identity.conditionValue.byteBlob = app;
        auto& address = rule.conditions[1];
        address.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        address.matchType = FWP_MATCH_NOT_EQUAL;
    }
    rules[0].layer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    rules[0].conditions[1].conditionValue.type = FWP_V4_ADDR_MASK;
    rules[0].conditions[1].conditionValue.v4AddrMask = &local4;
    rules[1].layer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    rules[1].conditions[1].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
    rules[1].conditions[1].conditionValue.byteArray16 = &local6;
    return rules;
}

// Returned structures borrow the application's blob and the rule's conditions.
inline FWPM_FILTER0 filter_for(Rule& rule, const GUID& sublayer, bool persistent) {
    FWPM_FILTER0 filter{};
    filter.layerKey = rule.layer;
    filter.subLayerKey = sublayer;
    filter.flags = persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;
    filter.numFilterConditions = rule.count;
    filter.filterCondition = rule.conditions.data();
    return filter;
}

inline bool matches_filter(const FWPM_FILTER0& filter, const Rule& expected) {
    if (!IsEqualGUID(filter.layerKey, expected.layer) || filter.action.type != FWP_ACTION_BLOCK ||
        !(filter.flags & FWPM_FILTER_FLAG_PERSISTENT) || (filter.flags & FWPM_FILTER_FLAG_DISABLED) ||
        filter.numFilterConditions != expected.count || !filter.filterCondition) return false;
    for (UINT32 i = 0; i < expected.count; ++i) {
        const auto& want = expected.conditions[i];
        bool found = false;
        for (UINT32 j = 0; j < filter.numFilterConditions; ++j) {
            const auto& got = filter.filterCondition[j];
            if (!IsEqualGUID(got.fieldKey, want.fieldKey) || got.matchType != want.matchType ||
                got.conditionValue.type != want.conditionValue.type) continue;
            switch (want.conditionValue.type) {
            case FWP_BYTE_BLOB_TYPE: {
                const auto* a = got.conditionValue.byteBlob;
                const auto* b = want.conditionValue.byteBlob;
                found = a && b && a->data && b->data && a->size == b->size &&
                    memcmp(a->data, b->data, a->size) == 0;
                break;
            }
            case FWP_UINT32: found = got.conditionValue.uint32 == want.conditionValue.uint32; break;
            case FWP_UINT16: found = got.conditionValue.uint16 == want.conditionValue.uint16; break;
            case FWP_UINT8: found = got.conditionValue.uint8 == want.conditionValue.uint8; break;
            case FWP_V4_ADDR_MASK:
                found = got.conditionValue.v4AddrMask && want.conditionValue.v4AddrMask &&
                    got.conditionValue.v4AddrMask->addr == want.conditionValue.v4AddrMask->addr &&
                    got.conditionValue.v4AddrMask->mask == want.conditionValue.v4AddrMask->mask;
                break;
            case FWP_BYTE_ARRAY16_TYPE:
                found = got.conditionValue.byteArray16 && want.conditionValue.byteArray16 &&
                    memcmp(got.conditionValue.byteArray16, want.conditionValue.byteArray16, 16) == 0;
                break;
            default: return false;
            }
            if (found) break;
        }
        if (!found) return false;
    }
    return true;
}
}
