import joblib
import os
from typing import Dict, Any, List

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'model.pkl')

def model_exists() -> bool:
    return os.path.exists(MODEL_PATH)

def load_model():
    if not model_exists():
        return None
    return joblib.load(MODEL_PATH)

def extract_vector(static_feats: Dict[str, Any], dynamic_metrics: Dict[str, Any]) -> List[float]:
    perms = set(static_feats.get('permissions', []))
    dangerous = {
        'android.permission.SEND_SMS','android.permission.RECEIVE_SMS','android.permission.READ_SMS',
        'android.permission.CALL_PHONE','android.permission.READ_CONTACTS','android.permission.WRITE_CONTACTS',
        'android.permission.READ_CALL_LOG','android.permission.WRITE_CALL_LOG','android.permission.RECEIVE_BOOT_COMPLETED',
        'android.permission.SYSTEM_ALERT_WINDOW','android.permission.REQUEST_INSTALL_PACKAGES','android.permission.WRITE_SETTINGS',
        'android.permission.READ_PHONE_STATE','android.permission.RECORD_AUDIO','android.permission.CAMERA'
    }
    n_danger = len(perms & dangerous)
    n_api = len(static_feats.get('suspicious_apis', []))

    net_calls = dynamic_metrics.get('network_calls', []) or []
    sys_calls = dynamic_metrics.get('system_calls', []) or []

    n_net = len([x for x in net_calls if isinstance(x, str)])
    suspicious_sys = {'execve','chmod','chown','ptrace','kill'}
    n_sys = len(set(sys_calls) & suspicious_sys)

    intents = static_feats.get('intents', [])
    has_boot = 1 if any('BOOT_COMPLETED' in s for s in intents) else 0

    return [n_danger, n_api, n_net, n_sys, has_boot]
