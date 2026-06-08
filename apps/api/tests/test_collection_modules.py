from __future__ import annotations


def test_modules_endpoint_exposes_expanded_accessible_catalog(test_app):
    client = test_app["client"]
    db = test_app["db"]
    user = db.run(db.create_user("modules_tester", "modules_tester@test.local"))
    headers = test_app["headers_for"](user)

    response = client.get("/api/v1/modules", headers=headers)

    assert response.status_code == 200
    modules = response.json()["modules"]
    module_ids = {module["id"] for module in modules}

    assert {"dc_health", "replication", "audit_logging", "tiering_crown_jewels", "exposure_quick_checks"} <= module_ids
    assert len(modules) >= 20

    command_count = sum(
        len(group["commands"])
        for module in modules
        for group in module["command_groups"]
    )
    assert command_count >= 135

    assert all(module["read_only"] is False for module in modules)


def test_modules_endpoint_requires_auth(test_app):
    response = test_app["client"].get("/api/v1/modules")
    assert response.status_code == 401


def test_exposure_modules_endpoint_is_scoped_to_quick_checks(test_app):
    db = test_app["db"]
    user = db.run(db.create_user("exposure_tester", "exposure_tester@test.local"))
    headers = test_app["headers_for"](user)
    response = test_app["client"].get("/api/v1/modules/exposure", headers=headers)

    assert response.status_code == 200
    modules = response.json()["modules"]
    assert [module["id"] for module in modules] == ["exposure_quick_checks"]
    commands = [
        command["id"]
        for group in modules[0]["command_groups"]
        for command in group["commands"]
    ]
    assert {"quick-get-aduser-risk", "quick-ldap-asrep", "quick-nmap-smb-signing"} <= set(commands)
