from typing import Dict, Any, List
from androguard.misc import AnalyzeAPK
import re
import os

# -----------------------------
# Suspicious patterns and regex
# -----------------------------
SUSPICIOUS_API_SUBSTRINGS = [
    "java/lang/Runtime;->exec",
    "dalvik/system/DexClassLoader;-><init>",
    "java/lang/reflect/Method;->invoke",
    "android/telephony/SmsManager;->sendTextMessage",
    "javax/crypto/Cipher;->init",
    "java/net/HttpURLConnection;->connect",
    "okhttp3/OkHttpClient;->newCall",
    "org/apache/http/client/HttpClient;->execute",
    "java/net/URL;->openConnection",
]

URL_RE = re.compile(rb"(https?://[^\s'\"<>]+)")
IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")

# -----------------------------
# Internal helpers
# -----------------------------
def _match_suspicious_apis(dx) -> List[str]:
    """Scan for suspicious API calls."""
    hits = set()
    try:
        for cls in dx.get_classes():
            for method in cls.get_methods():
                try:
                    for s in method.get_xref_to():
                        called = f"{s.class_name}->{s.name}"
                        for needle in SUSPICIOUS_API_SUBSTRINGS:
                            if needle in called:
                                hits.add(needle)
                except Exception:
                    continue
    except Exception:
        pass
    return sorted(hits)


def _extract_strings_from_apk(apk_path: str) -> bytes:
    """Read raw bytes of the APK."""
    try:
        with open(apk_path, "rb") as f:
            return f.read()
    except Exception:
        return b""


# -----------------------------
# Static analysis
# -----------------------------
def static_features(apk_path: str) -> Dict[str, Any]:
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
    suspicious_apis = _match_suspicious_apis(dx)

    return {
        "package": a.get_package(),
        "permissions": sorted(set(permissions)),
        "receivers": receivers,
        "services": services,
        "providers": providers,
        "intents": sorted(set(intents)),
        "suspicious_apis": suspicious_apis,
        "apk_size": os.path.getsize(apk_path),
        "min_sdk_version": a.get_min_sdk_version(),
        "target_sdk_version": a.get_target_sdk_version(),
        "main_activity": a.get_main_activity(),
    }


# -----------------------------
# Dynamic analysis
# -----------------------------
def dynamic_features(apk_path: str) -> Dict[str, Any]:
    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        return {"error": f"AnalyzeAPK failed: {e}"}

    raw = _extract_strings_from_apk(apk_path)
    urls = {m.group(0).decode(errors="ignore") for m in URL_RE.finditer(raw)}
    ips = {m.group(0).decode(errors="ignore") for m in IP_RE.finditer(raw)}

    net_hits, sys_hits = set(), set()
    try:
        for cls in dx.get_classes():
            for method in cls.get_methods():
                try:
                    for s in method.get_xref_to():
                        called = f"{s.class_name}->{s.name}"
                        for needle in SUSPICIOUS_API_SUBSTRINGS:
                            if needle in called:
                                if (
                                    "Http" in needle
                                    or "URL;" in needle
                                    or "OkHttp" in needle
                                    or "http" in needle.lower()
                                ):
                                    net_hits.add(needle)
                                else:
                                    sys_hits.add(needle)
                except Exception:
                    continue
    except Exception:
        pass

    native_libs = []
    try:
        for f in d.get_files():
            if f.endswith(".so"):
                native_libs.append(os.path.basename(f))
    except Exception:
        pass

    sms_used = any(
        "SmsManager" in s for s in (net_hits | sys_hits | set(SUSPICIOUS_API_SUBSTRINGS))
    )

    return {
        "apk": apk_path,
        "network_calls": sorted(urls),
        "network_ips": sorted(ips),
        "system_calls": sorted(sys_hits) if sys_hits else sorted(net_hits),
        "native_libs": native_libs,
        "sms_used": sms_used,
        "status": "heuristic-dynamic-extraction-complete",
        "behavior_summary": {
            "n_network_calls": len(urls),
            "n_system_indicators": len(sys_hits) or len(net_hits),
            "n_native_libs": len(native_libs),
        },
    }


# -----------------------------
# Hybrid analysis (5 verdicts)
# -----------------------------
def hybrid_features(apk_path: str) -> Dict[str, Any]:
    static = static_features(apk_path)
    dynamic = dynamic_features(apk_path)

    suspicious_count = (
        len(static.get("suspicious_apis", []))
        + dynamic.get("behavior_summary", {}).get("n_system_indicators", 0)
    )

    # 5-level scoring system
    if suspicious_count <= 2:
        risk_score = 0.1
        verdict = "benign"
    elif suspicious_count <= 4:
        risk_score = 0.35
        verdict = "adware"
    elif suspicious_count <= 6:
        risk_score = 0.55
        verdict = "spyware"
    elif suspicious_count <= 9:
        risk_score = 0.75
        verdict = "trojan"
    else:
        risk_score = 0.9
        verdict = "ransomware"

    action = determine_action(verdict, risk_score)

    return {
        "static": static,
        "dynamic": dynamic,
        "summary": {
            "static_suspicious": len(static.get("suspicious_apis", [])),
            "dynamic_network_indicators": len(dynamic.get("network_calls", []) or []),
            "dynamic_sys_indicators": len(dynamic.get("system_calls", []) or []),
        },
        "verdict": verdict,
        "risk_score": risk_score,
        "recommended_action": action,
    }


# -----------------------------
# Action Recommendation
# -----------------------------
def determine_action(verdict: str, risk_score: float) -> str:
    v = verdict.lower()
    if v == "benign":
        return "Safe to use"
    elif v == "adware":
        return "Contains ads or trackers - use caution"
    elif v == "spyware":
        return "Spyware detected - avoid installation"
    elif v == "trojan":
        return "Trojan behaviour - uninstall or block immediately"
    elif v == "ransomware":
        return "Ransomware detected - do not install and isolate device"
    return "Unknown - manual review recommended"


# -----------------------------
# Aliases for main.py
# -----------------------------
def extract_static_features(apk_path: str) -> Dict[str, Any]:
    return static_features(apk_path)


def analyze_dynamic_features(apk_path: str) -> Dict[str, Any]:
    return dynamic_features(apk_path)


def analyze_hybrid_features(apk_path: str) -> Dict[str, Any]:
    return hybrid_features(apk_path)
