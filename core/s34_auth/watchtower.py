# ============================================================
# S34Auth -> Primary Watchtower Conditional Intercom
# Reports ONLY when authorization/security requirements fail
# ============================================================

import json
import urllib.error
import urllib.request

PRIMARY_WATCHTOWER_URL = os.getenv(
    "S43_PRIMARY_WATCHTOWER_URL",
    "http://s43-watchtower:9100",
).rstrip("/")

S34AUTH_MODULE_ID = os.getenv(
    "S43_S34AUTH_MODULE_ID",
    "s43-authorization-watchtower",
)

S34AUTH_VERSION = os.getenv("S43_S34AUTH_VERSION", "1.0.0")
S34AUTH_TIMEOUT = float(os.getenv("S43_S34AUTH_TIMEOUT", "2.0"))

_AUTH_REGISTERED = False
_AUTH_REGISTER_LOCK = threading.Lock()


def _primary_watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{PRIMARY_WATCHTOWER_URL}{path}"
    data = None
    headers = {"Content-Type": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urllib.request.urlopen(request, timeout=S34AUTH_TIMEOUT) as response:
            body = response.read().decode("utf-8")
            if not body:
                return {"status_code": response.status}

            parsed = json.loads(body)
            if isinstance(parsed, dict):
                parsed.setdefault("status_code", response.status)
                return parsed

            return {
                "status_code": response.status,
                "body": parsed,
            }

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = str(exc)

        return {
            "error": "primary_watchtower_http_error",
            "status_code": exc.code,
            "detail": detail,
        }

    except Exception as exc:
        return {
            "error": "primary_watchtower_unreachable",
            "detail": str(exc),
        }


def register_s34auth_if_needed() -> dict[str, Any]:
    global _AUTH_REGISTERED

    with _AUTH_REGISTER_LOCK:
        if _AUTH_REGISTERED:
            return {
                "registered": True,
                "cached": True,
                "module_id": S34AUTH_MODULE_ID,
            }

        payload = {
            "module_id": S34AUTH_MODULE_ID,
            "module_type": "authorization-watchtower",
            "version": S34AUTH_VERSION,
            "endpoint": None,
            "capabilities": [
                "authorization_failure_detection",
                "auth_intrusion_detection",
                "failed_login_threshold_detection",
                "network_intrusion_detection",
                "malware_detection",
                "phishing_detection",
                "conditional_security_reporting",
            ],
            "metadata": {
                "communication_mode": "conditional_only",
                "reports_when": "authorization_or_security_requirement_unsatisfactory",
                "classification": "INTERNAL",
                "timestamp": _utc_ts(),
            },
        }

        result = _primary_watchtower_request(
            "POST",
            "/watchtower/modules/register",
            payload,
        )

        _AUTH_REGISTERED = "error" not in result

        return {
            "registered": _AUTH_REGISTERED,
            "module_id": S34AUTH_MODULE_ID,
            "response": result,
        }


def report_authorization_failure(
    *,
    event: SentinelEvent,
    alert: SentinelAlert,
    requirement: str,
    observed_level: str,
    required_level: str,
    decision: str = "unsatisfactory",
) -> dict[str, Any]:
    """
    Report to Primary Watchtower ONLY when authorization/security requirements fail.
    This is intentionally quiet during normal satisfactory authorization.
    """

    register_s34auth_if_needed()

    heartbeat_payload = {
        "module_id": S34AUTH_MODULE_ID,
        "status": "degraded",
        "metrics": {
            "authorization_decision": decision,
            "requirement": requirement,
            "observed_level": observed_level,
            "required_level": required_level,
            "event_id": event.event_id,
            "correlation_id": event.correlation_id,
            "alert_id": alert.alert_id,
            "timestamp": _utc_ts(),
        },
        "message": (
            f"S34Auth authorization requirement unsatisfactory: "
            f"{requirement} observed={observed_level} required={required_level}"
        ),
    }

    dependency_payload = {
        "name": S34AUTH_MODULE_ID,
        "status": "degraded",
        "version": S34AUTH_VERSION,
        "details": {
            "reason": "authorization_requirement_unsatisfactory",
            "requirement": requirement,
            "observed_level": observed_level,
            "required_level": required_level,
            "decision": decision,
            "event": event.to_dict(),
            "alert": alert.to_dict(),
            "timestamp": _utc_ts(),
        },
    }

    analyze_payload = {
        "event": {
            "kind": "security",
            "source": S34AUTH_MODULE_ID,
            "authorization_status": decision,
            "requirement": requirement,
            "observed_level": observed_level,
            "required_level": required_level,
            "event_id": event.event_id,
            "correlation_id": event.correlation_id,
            "alert_id": alert.alert_id,
            "secrets_exposed": False,
            "unsigned_artifact": False,
            "debug_mode_enabled": False,
            "details": {
                "s34auth_event": event.to_dict(),
                "s34auth_alert": alert.to_dict(),
            },
        }
    }

    heartbeat_result = _primary_watchtower_request(
        "POST",
        "/watchtower/modules/heartbeat",
        heartbeat_payload,
    )

    dependency_result = _primary_watchtower_request(
        "POST",
        "/watchtower/dependencies/report",
        dependency_payload,
    )

    analyze_result = _primary_watchtower_request(
        "POST",
        "/watchtower/analyze",
        analyze_payload,
    )

    return {
        "reported": True,
        "module_id": S34AUTH_MODULE_ID,
        "primary_watchtower_url": PRIMARY_WATCHTOWER_URL,
        "heartbeat": heartbeat_result,
        "dependency": dependency_result,
        "analyze": analyze_result,
    }