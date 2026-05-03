# Sentinel-43 AuthManager Audit

## Source Under Review

```python
from datetime import datetime, timezone
from typing import Optional

from .models import AuthContext, AuthResult
from .exceptions import InvalidTokenError, ExpiredTokenError
from .hashing import constant_time_compare


class AuthManager:
    """
    Sentinel-43 unified authentication manager
    """

    def __init__(self, secret: bytes, issuer: str):
        self._secret = secret
        self._issuer = issuer

    def verify_token(self, token: str) -> AuthResult:
        """
        Verify token and return AuthResult
        """

        try:
            context = self._decode_token(token)

            if context.expires_at < datetime.now(timezone.utc):
                raise ExpiredTokenError("Token expired")

            return AuthResult(
                success=True,
                context=context,
            )

        except Exception as e:
            return AuthResult(
                success=False,
                context=None,
                reason=str(e),
            )

    def _decode_token(self, token: str) -> AuthContext:
        """
        Replace this with JWT decode or signed token decode
        """

        # placeholder logic — replace with real JWT or signed blob
        if not token:
            raise InvalidTokenError("Token missing")

        now = datetime.now(timezone.utc)

        return AuthContext(
            subject_id="system",
            device_id="local",
            roles={"core"},
            issued_at=now,
            expires_at=now.replace(year=now.year + 1),
            issuer=self._issuer,
        )
```

---

## BUG-001 — `verify_token` Swallows All Exceptions

**Severity:** High
**Location:** `auth_manager.py` → `AuthManager.verify_token()`

### Problem

`verify_token()` catches every exception with a broad `except Exception as e` block:

```python
except Exception as e:
    return AuthResult(
        success=False,
        context=None,
        reason=str(e),
    )
```

This converts all failures into the same `success=False` result. That includes expected authentication failures such as `InvalidTokenError` and `ExpiredTokenError`, but it also includes internal programming errors, malformed decoded payloads, `AttributeError`, type errors, broken model construction, and unexpected runtime failures.

As a result, callers cannot distinguish between a legitimate token rejection and a broken authentication subsystem. That is dangerous because internal defects can be hidden as normal authentication failures instead of surfacing during development, logging, monitoring, or incident review.

### Impact

A broken `_decode_token()` implementation or corrupted `AuthContext` construction could fail silently. The system would report an ordinary failed authentication attempt instead of exposing an internal failure. That makes debugging harder and can hide production defects.

### Recommendation

Catch only expected authentication exceptions and let unexpected exceptions either propagate or be logged separately before returning failure.

Example direction:

```python
except (InvalidTokenError, ExpiredTokenError) as e:
    return AuthResult(success=False, context=None, reason=str(e))
```

Unexpected exceptions should not be silently flattened into normal auth rejection responses. That is how bugs get fake IDs and walk past the bouncer.

---

## BUG-002 — `_secret` Is Accepted but Never Used

**Severity:** High
**Location:** `auth_manager.py` → `AuthManager.__init__()`, `AuthManager._decode_token()`

### Problem

The constructor accepts and stores a secret:

```python
self._secret = secret
```

However, `_secret` is never referenced anywhere in the class. `_decode_token()` does not perform JWT validation, HMAC verification, signature verification, or any other secret-backed token validation.

Instead, the current placeholder logic accepts any non-empty token:

```python
if not token:
    raise InvalidTokenError("Token missing")
```

After that check, the method fabricates an `AuthContext`:

```python
return AuthContext(
    subject_id="system",
    device_id="local",
    roles={"core"},
    issued_at=now,
    expires_at=now.replace(year=now.year + 1),
    issuer=self._issuer,
)
```

This means every non-empty token string is treated as valid and granted the same hardcoded privileged identity.

### Impact

If this placeholder is reachable in any real execution path, authentication is effectively bypassed. A token such as `"abc"`, `"test"`, or `"let-me-in"` would produce a successful `AuthResult` with `roles={"core"}`.

The class interface implies secret-backed verification, but no such verification exists. That mismatch is especially risky because downstream code may trust `AuthManager` as if it performs real authentication.

### Recommendation

Fail closed until real decoding and verification are implemented.

Example direction:

```python
def _decode_token(self, token: str) -> AuthContext:
    if not token:
        raise InvalidTokenError("Token missing")

    raise InvalidTokenError("Token decoding not implemented")
```

When implemented for real, `_decode_token()` should verify token integrity using the configured secret before constructing an `AuthContext`.

---

## BUG-003 — `constant_time_compare` Is Imported but Never Used

**Severity:** Medium
**Location:** `auth_manager.py` → imports

### Problem

The module imports `constant_time_compare`:

```python
from .hashing import constant_time_compare
```

But the function is never called. This appears directly related to the missing secret-backed verification in BUG-002. The import suggests signature or MAC comparison was intended, but the verification path was never wired up.

### Impact

This is not just cosmetic dead code. In an authentication component, an unused constant-time comparison helper is a warning sign that signature verification was started but not completed.

If real token verification is added later and this issue is missed, a developer may use a naive `==` comparison for signatures or token hashes, creating a timing side-channel risk.

### Recommendation

Either remove the unused import until verification is implemented, or wire it into real HMAC/signature verification logic.

For security-sensitive comparisons, avoid direct equality checks such as:

```python
provided_signature == expected_signature
```

Use the constant-time comparison helper instead.

---

## BUG-004 — `expires_at` Calculation Can Crash on Leap Day

**Severity:** Medium
**Location:** `auth_manager.py` → `AuthManager._decode_token()`

### Problem

The placeholder expiration uses `datetime.replace()` to add one year:

```python
expires_at=now.replace(year=now.year + 1)
```

This is not safe date arithmetic. If `now` is February 29 during a leap year, replacing the year with a non-leap year raises `ValueError` because February 29 does not exist in the target year.

### Impact

This creates an intermittent date-dependent crash. It would only appear on leap day, which makes it easy to miss in testing and annoying to diagnose later. Humanity has apparently decided calendars were not already hostile enough.

Although this code is placeholder logic, the pattern is dangerous if copied into real token generation or expiration logic.

### Recommendation

Use duration-based arithmetic instead of direct year replacement.

Example direction:

```python
from datetime import timedelta

expires_at = now + timedelta(days=365)
```

For true calendar-year behavior, use a calendar-aware library such as `dateutil.relativedelta`, but for token TTLs, a fixed duration is usually clearer and safer.

---

## Summary

| ID      | Location                        | Severity | Issue                                                                     |
| ------- | ------------------------------- | -------: | ------------------------------------------------------------------------- |
| BUG-001 | `verify_token()`                |     High | Broad exception handling hides internal failures as normal auth rejection |
| BUG-002 | `__init__()`, `_decode_token()` |     High | `_secret` is stored but never used; any non-empty token is accepted       |
| BUG-003 | imports                         |   Medium | `constant_time_compare` is imported but unused                            |
| BUG-004 | `_decode_token()`               |   Medium | `now.replace(year=now.year + 1)` can crash on February 29                 |

---

## Bottom Line

The class shape is usable, but the current implementation is not performing real authentication. The highest-risk issue is that any non-empty token currently becomes a valid `AuthContext` with `roles={"core"}`. Until real token verification is implemented, `_decode_token()` should fail closed instead of fabricating a privileged context.
