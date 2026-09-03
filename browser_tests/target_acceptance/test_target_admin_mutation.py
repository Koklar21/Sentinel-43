# =============================================================================
# Sentinel-43 -- target acceptance: ADMIN MUTATION scenarios.
#
# disable / role-change / password-reset / session-replay. These MUTATE
# accounts, so they run only against a DEDICATED throwaway admin + operator
# pair, and only when S43_TARGET_ADMIN_SCOPE=explicit-dedicated-account.
# Never point these at an owner's ordinary account.
#
# The `admin_mutation_cred` fixture fails loudly (INCOMPLETE, not skip) when
# the scope / cred file is absent.
# =============================================================================

from __future__ import annotations

import pytest

from _targetlib import read_cred, target_request


@pytest.fixture(scope="session")
def dedicated_operator_cred(admin_mutation_cred):
    # A second dedicated account the admin tests may disable / re-enable.
    return read_cred("S43_TARGET_MUTATION_OPERATOR_CRED_FILE",
                     purpose="admin-mutation acceptance (the account under test)")


def _login_token(username: str, password: str) -> str:
    status, body = target_request("POST", "/auth/login",
                                  body={"username": username, "password": password})
    assert status == 200, (status, body)
    return body.get("access_token") or body.get("token")


def test_admin_disable_invalidates_the_targets_live_session(
        admin_mutation_cred, dedicated_operator_cred):
    op_token = _login_token(*dedicated_operator_cred)
    admin_token = _login_token(*admin_mutation_cred)

    status, users = target_request(
        "GET", "/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert status == 200
    op_id = next(u["user_id"] for u in users
                 if u["username"] == dedicated_operator_cred[0])

    try:
        s, _ = target_request("PATCH", f"/users/{op_id}", body={"is_active": False},
                              headers={"Authorization": f"Bearer {admin_token}"})
        assert s == 200
        s, _ = target_request("GET", "/v1/status",
                              headers={"Authorization": f"Bearer {op_token}"})
        assert s == 401  # the operator's live token is rejected immediately
    finally:
        target_request("PATCH", f"/users/{op_id}", body={"is_active": True},
                       headers={"Authorization": f"Bearer {admin_token}"})


def test_password_reset_revokes_the_targets_sessions(
        admin_mutation_cred, dedicated_operator_cred):
    op_token = _login_token(*dedicated_operator_cred)
    admin_token = _login_token(*admin_mutation_cred)
    status, users = target_request(
        "GET", "/users", headers={"Authorization": f"Bearer {admin_token}"})
    op_id = next(u["user_id"] for u in users
                 if u["username"] == dedicated_operator_cred[0])
    new_pw = dedicated_operator_cred[1]  # reset to the same known value
    s, _ = target_request("PATCH", f"/users/{op_id}/password",
                          body={"password": new_pw},
                          headers={"Authorization": f"Bearer {admin_token}"})
    assert s == 200
    s, _ = target_request("GET", "/v1/status",
                          headers={"Authorization": f"Bearer {op_token}"})
    assert s == 401
