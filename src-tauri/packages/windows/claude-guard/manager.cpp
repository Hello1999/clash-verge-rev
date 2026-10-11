#include "wfp-policy.h"
#include <rpc.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

namespace {
GUID providerKey{0x25d106a3, 0xd7b4, 0x4799, {0x9a, 0x74, 0xe7, 0xe1, 0x56, 0x28, 0x10, 0x62}};
GUID sublayerKey{0xd845056a, 0x78ef, 0x4994, {0x8f, 0xc4, 0x15, 0x44, 0xa1, 0x0f, 0x49, 0x17}};
void check(DWORD result, const char* operation) {
    if (result) throw std::runtime_error(std::string(operation) + ": " + std::to_string(result));
}
template<class T> struct WfpMemory {
    T* value = nullptr;
    ~WfpMemory() { if (value) FwpmFreeMemory0(reinterpret_cast<void**>(&value)); }
};
struct Engine {
    HANDLE value = nullptr;
    bool transaction = false;
    Engine() { check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &value), "Open engine"); }
    ~Engine() {
        if (transaction) FwpmTransactionAbort0(value);
        if (value) FwpmEngineClose0(value);
    }
    void begin() { check(FwpmTransactionBegin0(value, 0), "Begin transaction"); transaction = true; }
    void commit() { check(FwpmTransactionCommit0(value), "Commit transaction"); transaction = false; }
};
struct Enumerator {
    HANDLE engine;
    HANDLE value = nullptr;
    explicit Enumerator(HANDLE handle) : engine(handle) {
        check(FwpmFilterCreateEnumHandle0(engine, nullptr, &value), "Enumerate filters");
    }
    ~Enumerator() { if (value) FwpmFilterDestroyEnumHandle0(engine, value); }
};
bool same_app(const FWPM_FILTER0& filter, const FWP_BYTE_BLOB& app) {
    if (!filter.providerKey || !IsEqualGUID(*filter.providerKey, providerKey) ||
        !IsEqualGUID(filter.subLayerKey, sublayerKey)) return false;
    for (UINT32 i = 0; i < filter.numFilterConditions; ++i) {
        const auto& condition = filter.filterCondition[i];
        if (IsEqualGUID(condition.fieldKey, FWPM_CONDITION_ALE_APP_ID) &&
            condition.matchType == FWP_MATCH_EQUAL && condition.conditionValue.type == FWP_BYTE_BLOB_TYPE) {
            const auto* existing = condition.conditionValue.byteBlob;
            return existing && existing->size == app.size && memcmp(existing->data, app.data, app.size) == 0;
        }
    }
    return false;
}
std::vector<UINT64> owned_filters(HANDLE engine, const FWP_BYTE_BLOB& app) {
    Enumerator enumeration(engine);
    std::vector<UINT64> ids;
    for (;;) {
        WfpMemory<FWPM_FILTER0*> batch;
        UINT32 count = 0;
        check(FwpmFilterEnum0(engine, enumeration.value, 128, &batch.value, &count), "Read filters");
        for (UINT32 i = 0; i < count; ++i) {
            if (same_app(*batch.value[i], app)) ids.push_back(batch.value[i]->filterId);
        }
        if (!count) return ids;
    }
}
void ensure_namespace(HANDLE engine) {
    FWPM_PROVIDER0 provider{};
    provider.providerKey = providerKey;
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    provider.displayData.name = const_cast<wchar_t*>(L"Claude Fixed Exit Guard (personal Windows build)");
    DWORD result = FwpmProviderAdd0(engine, &provider, nullptr);
    if (result != FWP_E_ALREADY_EXISTS) check(result, "Add provider");
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = sublayerKey;
    sublayer.providerKey = &providerKey;
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.weight = 0xFFFF;
    sublayer.displayData.name = provider.displayData.name;
    result = FwpmSubLayerAdd0(engine, &sublayer, nullptr);
    if (result != FWP_E_ALREADY_EXISTS) check(result, "Add sublayer");
}
UINT16 parse_port(const std::wstring& text) {
    if (text.empty() || text.find_first_not_of(L"0123456789") != std::wstring::npos)
        throw std::invalid_argument("Port must be decimal digits");
    unsigned long value = std::stoul(text);
    if (!value || value > 65535) throw std::invalid_argument("Invalid port");
    return static_cast<UINT16>(value);
}
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 1 || (argc == 2 && std::wstring(argv[1]) == L"--help")) {
            std::cout << "Auto Chain Claude guard filter manager.\n"
                "  wfp-manager plan <absolute-exe-path> <port>\n"
                "  wfp-manager verify <absolute-exe-path> <port>\n"
                "  wfp-manager install <absolute-exe-path> <port> --apply\n"
                "  wfp-manager remove <absolute-exe-path> --apply\n"
                "Use local instead of <port> to allow 127.0.0.0/8 and ::1 on all ports/protocols.\n"
                "Install/remove require administrator rights. Plan never opens the filter engine.\n";
            return 0;
        }
        std::wstring operation = argv[1];
        bool remove = operation == L"remove";
        bool plan = operation == L"plan";
        bool verify = operation == L"verify";
        if ((!plan && !verify && !remove && operation != L"install") ||
            ((plan || verify) && argc != 4) || (remove && argc != 4) ||
            (operation == L"install" && argc != 5)) throw std::invalid_argument("Invalid arguments; use --help");
        if (!plan && !verify && std::wstring(argv[argc - 1]) != L"--apply") throw std::invalid_argument("Explicit --apply is required");
        std::filesystem::path path(argv[2]);
        if (!path.is_absolute() || !std::filesystem::is_regular_file(path)) throw std::invalid_argument("Existing absolute executable path required");
        bool local = !remove && std::wstring(argv[3]) == L"local";
        UINT16 port = remove || local ? 0 : parse_port(argv[3]);
        WfpMemory<FWP_BYTE_BLOB> app;
        check(FwpmGetAppIdFromFileName0(path.c_str(), &app.value), "Resolve application identity");
        std::vector<claude_guard::Rule> policy;
        if (local) {
            auto rules = claude_guard::local_services_only(app.value);
            policy.assign(rules.begin(), rules.end());
        } else if (!remove) {
            auto rules = claude_guard::loopback_only(app.value, port);
            policy.assign(rules.begin(), rules.end());
        }
        if (plan) {
            std::wcout << L"PLAN ONLY: " << path.native() << L" -> " << (local ? L"loopback services" : L"assigned proxy port") << L"\n";
            std::cout << policy.size() << " persistent blocking filters. No filters changed.\n";
            return 0;
        }
        Engine engine;
        if (verify) {
            auto& expected = policy;
            auto ids = owned_filters(engine.value, *app.value);
            std::vector<bool> found(expected.size(), false);
            if (ids.size() != expected.size()) throw std::runtime_error("Owned filter count differs from requested policy");
            for (auto id : ids) {
                WfpMemory<FWPM_FILTER0> filter;
                check(FwpmFilterGetById0(engine.value, id, &filter.value), "Read owned filter");
                bool matched = false;
                for (size_t i = 0; i < expected.size(); ++i) {
                    if (!found[i] && claude_guard::matches_filter(*filter.value, expected[i])) {
                        found[i] = true;
                        matched = true;
                        break;
                    }
                }
                if (!matched) throw std::runtime_error("Owned filter does not match required policy");
            }
            std::cout << "FILTERS_VERIFIED: " << expected.size() << " active persistent blocking rules match the requested policy.\n";
            return 0;
        }
        engine.begin();
        auto old = owned_filters(engine.value, *app.value);
        if (!remove) ensure_namespace(engine.value);
        for (auto id : old) check(FwpmFilterDeleteById0(engine.value, id), "Remove owned application filter");
        if (!remove) {
            for (auto& rule : policy) {
                auto filter = claude_guard::filter_for(rule, sublayerKey, true);
                filter.providerKey = &providerKey;
                filter.displayData.name = const_cast<wchar_t*>(local ? L"Claude guard: local services only" : L"Claude guard: only assigned local TCP endpoint");
                check(FwpmFilterAdd0(engine.value, &filter, nullptr, nullptr), "Add blocking filter");
            }
        }
        engine.commit();
        std::cout << (remove ? "Owned application filters removed: " : "Persistent rules installed; replaced filters: ") << old.size() << '\n';
        std::cout << "Existing connections, reboot, package helpers and updates are NOT attested by this command.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAILED: " << error.what() << '\n';
        return 2;
    }
}
