from scripts.audit_public_history_paths import inspect_paths


def test_flags_secret_and_acme_paths():
    paths = [
        "src/normal.py", "deploy/proxy/certs/account.conf",
        "deploy/proxy/certs/http.header", "deploy/proxy/certs/ca/ca.key",
        "deploy/proxy/certs/site_ecc/site.cer", "config/.env.production",
        "keys/id_ed25519", "server.pfx",
    ]
    found = inspect_paths(paths)
    assert len(found) == 7
    assert "src/normal.py" not in found


def test_does_not_flag_examples_as_secrets():
    assert inspect_paths([".env.example", "config/.env.sample", "docs/readme.md"]) == []
