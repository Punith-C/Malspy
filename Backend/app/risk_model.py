from typing import Dict, Any, Tuple, Optional
from androguard.misc import AnalyzeAPK

# ---------------------------
# Risk Model Config
# ---------------------------

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.WRITE_SETTINGS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
}

SUSPICIOUS_APIS = [
    "java/lang/Runtime;->exec",
    "dalvik/system/DexClassLoader;-><init>",
    "java/lang/reflect/Method;->invoke",
    "android/telephony/SmsManager;->sendTextMessage",
    "javax/crypto/Cipher;->init",
]

NETWORK_INDICATORS = ["http://", "https://", "ftp://"]

# ---------------------------
# Feature Extraction
# ---------------------------

def extract_static_features(apk_path: str) -> Dict[str, Any]:
    """Extract permissions, receivers, services, providers, intents, and suspicious APIs."""
    a, d, dx = AnalyzeAPK(apk_path)

    permissions = a.get_permissions() or []
    receivers = a.get_receivers() or []
    services = a.get_services() or []
    providers = a.get_providers() or []

    intents = []
    try:
        for i in a.get_intent_filters("receiver"):
            intents.extend(list(i.keys()))
    except Exception:
        pass

    suspicious_apis = []
    try:
        for cls in dx.get_classes():
            for method in cls.get_methods():
                for s in method.get_xref_to():
                    called = f"{s.class_name}->{s.name}"
                    for needle in SUSPICIOUS_APIS:
                        if needle in called:
                            suspicious_apis.append(needle)
    except Exception:
        pass

    return {
        "package": a.get_package(),
        "permissions": sorted(set(permissions)),
        "receivers": receivers,
        "services": services,
        "providers": providers,
        "intents": sorted(set(intents)),
        "suspicious_apis": sorted(set(suspicious_apis)),
    }

# ---------------------------
# Risk Scoring
# ---------------------------

def static_score(features: Dict[str, Any]) -> Tuple[float, str, str]:
    perms = set(features.get("permissions", []))
    n_danger = len(perms & DANGEROUS_PERMISSIONS)
    perm_score = n_danger / max(1, len(DANGEROUS_PERMISSIONS))

    apis = set(features.get("suspicious_apis", []))
    api_score = len(apis) / max(1, len(SUSPICIOUS_APIS))

    intents = set(features.get("intents", []))
    intent_score = 1.0 if any("BOOT_COMPLETED" in s for s in intents) else 0.0

    risk = 0.5 * perm_score + 0.3 * api_score + 0.2 * intent_score
    risk = max(0.0, min(1.0, risk))

    verdict = "malicious" if risk >= 0.70 else ("suspicious" if risk >= 0.40 else "benign")
    explain = f"Static: dangerous_perms={n_danger}; suspicious_apis={len(apis)}; intent_boot={int(intent_score)}; risk={risk:.2f}"
    return risk, verdict, explain


def dynamic_score(logs: Dict[str, Any]) -> Tuple[float, str, str]:
    net = logs.get("network_calls", []) or []
    sys = logs.get("system_calls", []) or []

    n_net_hits = sum(1 for n in net if any(ind in n for ind in NETWORK_INDICATORS))
    suspicious_sys = {"execve", "chmod", "chown", "ptrace", "kill"}
    n_sys_hits = len(set(sys) & suspicious_sys)

    net_score = min(1.0, n_net_hits / 5.0)
    sys_score = min(1.0, n_sys_hits / 3.0)

    risk = 0.6 * sys_score + 0.4 * net_score
    risk = max(0.0, min(1.0, risk))

    verdict = "malicious" if risk >= 0.65 else ("suspicious" if risk >= 0.35 else "benign")
    explain = f"Dynamic: net_hits={n_net_hits}; sys_hits={n_sys_hits}; risk={risk:.2f}"
    return risk, verdict, explain


def hybrid_score(features: Dict[str, Any], logs: Optional[Dict[str, Any]]) -> Tuple[float, str, str]:
    sr, sv, se = static_score(features)
    if logs:
        dr, dv, de = dynamic_score(logs)
        risk = (sr + dr) / 2.0
        explain = f"Hybrid -> [{se}] + [{de}]"
    else:
        risk, sv, se = static_score(features)
        explain = f"Hybrid fallback -> [{se}]"

    verdict = "malicious" if risk >= 0.70 else ("suspicious" if risk >= 0.40 else "benign")
    return risk, verdict, explain

# ---------------------------
# Main Analyzer
# ---------------------------

def analyze(apk_path: str, mode: str = "static", logs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    features = extract_static_features(apk_path)

    if mode == "static":
        risk, verdict, explain = static_score(features)
        return {
            "analysis_type": "static",
            "verdict": verdict,
            "risk_score": risk,
            "features": features,
            "explain": explain,
        }

    elif mode == "dynamic":
        if not logs:
            logs = {"status": "executed in sandbox (placeholder)", "network_calls": [], "system_calls": []}
        risk, verdict, explain = dynamic_score(logs)
        return {
            "analysis_type": "dynamic",
            "verdict": verdict,
            "risk_score": risk,
            "logs": logs,
            "explain": explain,
        }

    elif mode == "hybrid":
        risk, verdict, explain = hybrid_score(features, logs)
        return {
            "analysis_type": "hybrid",
            "verdict": verdict,
            "risk_score": risk,
            "features": features,
            "logs": logs,
            "explain": explain,
        }

    else:
        raise ValueError("Invalid mode. Choose from: 'static', 'dynamic', or 'hybrid'.")
