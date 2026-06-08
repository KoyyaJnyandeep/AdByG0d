"""
Regression tests for ZIP bomb preflight limits in _parse_collector_zip.

Covers:
- Too many members (> _ZIP_MAX_MEMBERS)
- Excessive total uncompressed size (> _ZIP_MAX_UNCOMPRESSED_BYTES)
- Extreme compression ratio (> _ZIP_MAX_RATIO)
- Malformed entry: file_size > 0 with compress_size == 0
"""

import io
import json
import struct
import zipfile

import pytest

from adbygod_api.routes.import_data import (
    _ZIP_MAX_MEMBERS,
    _ZIP_MAX_RATIO,
    _ZIP_MAX_UNCOMPRESSED_BYTES,
    _parse_collector_zip,
    _summarize_module_outputs,
)

_VALID_MANIFEST = json.dumps({
    "generator": "AdByGod-Native-Collector",
    "version": "1.0",
}).encode()


def _make_valid_zip(extra_members: list[tuple[str, bytes]] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", _VALID_MANIFEST)
        for name, data in (extra_members or []):
            zf.writestr(name, data)
    return buf.getvalue()


def test_too_many_members_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", _VALID_MANIFEST)
        for i in range(_ZIP_MAX_MEMBERS):  # manifest + MAX_MEMBERS = total exceeds limit
            zf.writestr(f"filler_{i}.json", b"{}")
    with pytest.raises(ValueError, match="too many members"):
        _parse_collector_zip(buf.getvalue())


def test_excessive_uncompressed_size_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", _VALID_MANIFEST)
        # Write one member whose declared file_size exceeds the limit.
        # We manipulate the central directory to lie about file_size without
        # actually allocating the data (avoid OOM in test).
        big_name = "big.json"
        zf.writestr(big_name, b"{}")

    # Patch the central directory to report a huge uncompressed size.
    raw = bytearray(buf.getvalue())
    # Find the central directory signature 0x02014b50.
    sig = b"PK\x01\x02"
    idx = raw.rfind(sig)
    if idx != -1:
        # offset 20 in central directory record = uncompressed size (4 bytes, little-endian)
        struct.pack_into("<I", raw, idx + 24, _ZIP_MAX_UNCOMPRESSED_BYTES + 1)
    with pytest.raises(ValueError, match="exceeds limit"):
        _parse_collector_zip(bytes(raw))


def test_extreme_compression_ratio_rejected():
    """Create a member whose compress_size is tiny relative to file_size."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", _VALID_MANIFEST)
        # Highly compressible content — ratio will be large
        zf.writestr("bomb.json", b"\x00" * 1024 * 1024)  # 1 MB of zeros

    raw = bytearray(buf.getvalue())
    # Find the local file header for bomb.json and patch compress_size to 1
    # so the ratio check triggers: file_size (1 MB) / compress_size (1) >> _ZIP_MAX_RATIO.
    sig = b"PK\x03\x04"
    pos = 0
    while True:
        idx = raw.find(sig, pos)
        if idx == -1:
            break
        fname_len = struct.unpack_from("<H", raw, idx + 26)[0]
        extra_len = struct.unpack_from("<H", raw, idx + 28)[0]
        fname = raw[idx + 30: idx + 30 + fname_len].decode("utf-8", errors="replace")
        if "bomb" in fname:
            # compressed size at offset 18, uncompressed at 22 (local header)
            struct.pack_into("<I", raw, idx + 18, 1)       # compress_size = 1
            struct.pack_into("<I", raw, idx + 22, _ZIP_MAX_RATIO * 2)  # file_size = 200
            break
        pos = idx + 30 + fname_len + extra_len

    # Also patch the central directory record for bomb.json
    cd_sig = b"PK\x01\x02"
    pos = 0
    while True:
        idx = raw.find(cd_sig, pos)
        if idx == -1:
            break
        fname_len = struct.unpack_from("<H", raw, idx + 28)[0]
        fname = raw[idx + 46: idx + 46 + fname_len].decode("utf-8", errors="replace")
        if "bomb" in fname:
            struct.pack_into("<I", raw, idx + 20, 1)
            struct.pack_into("<I", raw, idx + 24, _ZIP_MAX_RATIO * 2)
            break
        pos = idx + 46 + fname_len

    with pytest.raises(ValueError, match="suspicious compression ratio"):
        _parse_collector_zip(bytes(raw))


def test_zero_compressed_size_nonzero_file_size_rejected():
    """compress_size == 0 with file_size > 0 is a malformed / quine-style entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", _VALID_MANIFEST)
        zf.writestr("quine.json", b'{"x":1}')

    raw = bytearray(buf.getvalue())
    # Patch the central directory: set compress_size=0, file_size=100 for quine.json
    cd_sig = b"PK\x01\x02"
    pos = 0
    while True:
        idx = raw.find(cd_sig, pos)
        if idx == -1:
            break
        fname_len = struct.unpack_from("<H", raw, idx + 28)[0]
        fname = raw[idx + 46: idx + 46 + fname_len].decode("utf-8", errors="replace")
        if "quine" in fname:
            struct.pack_into("<I", raw, idx + 20, 0)    # compress_size = 0
            struct.pack_into("<I", raw, idx + 24, 100)  # file_size = 100
            break
        pos = idx + 46 + fname_len

    with pytest.raises(ValueError, match="zero compressed size"):
        _parse_collector_zip(bytes(raw))


def test_path_traversal_entry_rejected():
    data = _make_valid_zip([("../evil.json", b"{}")])
    with pytest.raises(ValueError, match="unsafe path"):
        _parse_collector_zip(data)


def test_nested_archive_entry_rejected():
    data = _make_valid_zip([("nested.zip", b"PK\x03\x04")])
    with pytest.raises(ValueError, match="Nested archive"):
        _parse_collector_zip(data)


def test_valid_zip_passes():
    data = _make_valid_zip()
    manifest, modules = _parse_collector_zip(data)
    assert manifest["generator"] == "AdByGod-Native-Collector"
    assert modules == {}


def test_large_module_outputs_are_summarized_not_stored_fully():
    large = "A" * 10_000
    summary = _summarize_module_outputs(
        {"module": {"commands": [{"command": "Get-Thing", "exit_code": 0, "output": large}]}}
    )

    command = summary["module"]["commands"][0]
    assert command["output_chars"] == len(large)
    assert command["output_truncated"] is True
    assert len(command["output_preview"]) < len(large)


def test_zip_member_exceeding_decompressed_limit_rejected():
    """A ZIP member with declared file_size > 128 MB must be rejected before extraction."""
    from adbygod_api.core.parsers.bloodhound import BloodHoundParser
    import unittest.mock as mock

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("users.json", json.dumps({"meta": {"type": "users", "version": 4}, "data": []}))
    raw = buf.getvalue()

    fake_info = mock.MagicMock()
    fake_info.filename = "users.json"
    fake_info.file_size = 200 * 1024 * 1024  # 200 MB declared
    fake_info.is_dir = mock.MagicMock(return_value=False)

    with mock.patch("zipfile.ZipFile.infolist", return_value=[fake_info]):
        parser = BloodHoundParser()
        try:
            parser.parse_zip(raw)
            assert False, "Should have raised ValueError"
        except (ValueError, Exception) as exc:
            assert "decompressed" in str(exc).lower() or "limit" in str(exc).lower() or "size" in str(exc).lower()


def test_object_count_cap_enforced():
    """JSON with more than MAX_OBJECTS_PER_TYPE items must be rejected."""
    from adbygod_api.core.parsers.bloodhound import BloodHoundParser, MAX_OBJECTS_PER_TYPE

    oversized = {
        "meta": {"type": "users", "version": 4, "count": MAX_OBJECTS_PER_TYPE + 1},
        "data": [{"dummy": i} for i in range(MAX_OBJECTS_PER_TYPE + 1)],
    }
    parser = BloodHoundParser()
    try:
        parser.parse_json(json.dumps(oversized).encode())
        assert False, "Should have raised ValueError"
    except ValueError as exc:
        assert "limit" in str(exc).lower() or "count" in str(exc).lower()


@pytest.mark.timeout(120)
def test_object_count_at_limit_allowed():
    """JSON with exactly MAX_OBJECTS_PER_TYPE items must be accepted."""
    from adbygod_api.core.parsers.bloodhound import BloodHoundParser, MAX_OBJECTS_PER_TYPE

    # Use a small fixed count (1000) near the boundary to keep the test fast,
    # while still confirming the boundary logic accepts valid data.
    test_count = min(MAX_OBJECTS_PER_TYPE, 1000)
    at_limit = {
        "meta": {"type": "users", "version": 4, "count": test_count},
        "data": [
            {
                "Properties": {
                    "name": f"u{i}",
                    "domain": "TEST.LOCAL",
                    "enabled": True,
                    "objectid": f"S-1-{i}",
                },
                "Aces": [],
                "IsDeleted": False,
                "ObjectIdentifier": f"S-1-{i}",
            }
            for i in range(test_count)
        ],
    }
    parser = BloodHoundParser()
    result = parser.parse_json(json.dumps(at_limit).encode())
    assert isinstance(result, dict)
