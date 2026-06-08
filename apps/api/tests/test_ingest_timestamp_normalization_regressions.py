from __future__ import annotations

from adbygod_api.routes.ingest import _coerce_datetime, _normalise_attrs


def test_coerce_datetime_accepts_filetime_epoch_and_iso() -> None:
    filetime = _coerce_datetime(133585596000000000)
    epoch = _coerce_datetime(1715904000)
    iso = _coerce_datetime("2026-05-17T00:00:00Z")
    assert filetime is not None
    assert epoch is not None
    assert iso is not None
    assert iso.year == 2026


def test_normalise_attrs_maps_laps_and_delegation_aliases() -> None:
    attrs = _normalise_attrs({
        "has_laps": True,
        "pwdneverexpires": True,
        "uac_trusted_to_auth_for_delegation": True,
    })
    assert attrs["laps_installed"] is True
    assert attrs["pwd_never_expires"] is True
    assert attrs["constrained_delegation_any_protocol"] is True
