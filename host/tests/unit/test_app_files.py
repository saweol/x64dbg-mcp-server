"""file_upload / file_download through app.Gateway."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from tests.fakes.fake_runtime import EXE, GUEST_ROOT, make_lab
from x64dbg_vm_gateway.errors import PathNotAllowed, StateViolation

POSIX = os.name == "posix"


@pytest.fixture
def lab(tmp_path):
    lab = make_lab(tmp_path)
    yield lab
    lab.close()


# ── upload ──────────────────────────────────────────────────────────
def test_upload_into_an_explicit_guest_dir_without_a_job(lab):
    src = lab.samples / "tool.exe"
    src.write_bytes(b"tool bytes")
    out = lab.gateway().file_upload(str(src), guest_dir="C:\\Tools")
    assert out["guest_path"] == "C:\\Tools\\tool.exe"
    assert out["size"] == 10 and out["sha256"] == hashlib.sha256(b"tool bytes").hexdigest()
    assert lab.guest.read("C:\\Tools\\tool.exe") == b"tool bytes"


def test_upload_defaults_to_the_job_input_dir(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    src = lab.samples / "config.dat"
    src.write_bytes(b"cfg")
    out = gw.file_upload(str(src))
    assert out["guest_path"] == f"{GUEST_ROOT}\\{job_id}\\in\\config.dat"


def test_upload_without_job_needs_a_guest_dir(lab):
    src = lab.samples / "a.bin"
    src.write_bytes(b"a")
    with pytest.raises(StateViolation):
        lab.gateway().file_upload(str(src))


def test_upload_outside_the_allowed_roots_is_refused(lab, tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_bytes(b"PRIVATE KEY")
    with pytest.raises(PathNotAllowed):
        lab.gateway().file_upload(str(secret), guest_dir="C:\\Tools")
    assert not lab.guest.calls_of("copy_to_guest")


def test_upload_outside_the_allowed_roots_names_the_roots_and_the_setting(lab, tmp_path):
    """The refusal says which roots are allowed and which config key widens them."""
    secret = tmp_path / "notes.txt"
    secret.write_bytes(b"x")
    with pytest.raises(PathNotAllowed) as ei:
        lab.gateway().file_upload(str(secret), guest_dir="C:\\Tools")
    err = ei.value
    assert str(lab.samples.resolve()) in err.message
    assert "gateway.upload_roots" in err.message and "gateway.upload_roots" in (err.hint or "")
    assert err.details["allowed_roots"] == [str(lab.samples.resolve())]


@pytest.mark.skipif(not POSIX, reason="symlinks")
def test_upload_symlink_escaping_the_root_is_refused(lab, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"s")
    (lab.samples / "link.txt").symlink_to(secret)
    with pytest.raises(PathNotAllowed):
        lab.gateway().file_upload(str(lab.samples / "link.txt"), guest_dir="C:\\Tools")


def test_upload_of_a_directory_is_refused(lab):
    (lab.samples / "dir").mkdir()
    with pytest.raises(PathNotAllowed):
        lab.gateway().file_upload(str(lab.samples / "dir"), guest_dir="C:\\Tools")


@pytest.mark.parametrize("guest_dir", ["\\\\server\\share", "C:\\a\\..\\b", "relative\\dir", "C:\\x:ads"])
def test_upload_validates_the_guest_dir(lab, guest_dir):
    src = lab.samples / "a.bin"
    src.write_bytes(b"a")
    with pytest.raises(PathNotAllowed):
        lab.gateway().file_upload(str(src), guest_dir=guest_dir)


# ── download ────────────────────────────────────────────────────────
def test_download_from_the_job_dir(lab):
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    guest = f"{GUEST_ROOT}\\{job_id}\\out\\dump one.bin"
    lab.guest.write(guest, b"DUMP")
    out = gw.file_download(guest)
    p = Path(out["host_path"])
    assert p.parent == Path(lab.config.jobs_root) / job_id / "artifacts" / "raw" / "extra"
    assert p.name == "0000_dump_one.bin"
    assert p.read_bytes() == b"DUMP" and out["sha256"] == hashlib.sha256(b"DUMP").hexdigest()
    assert out["size"] == 4
    if POSIX:
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    second = Path(gw.file_download(guest)["host_path"])
    assert second.name == "0001_dump_one.bin"


def test_download_from_the_debugger_dir_is_allowed(lab):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    ini = EXE["x64"].rsplit("\\", 1)[0] + "\\x64dbg.ini"
    lab.guest.write(ini, b"[Engine]")
    assert Path(gw.file_download(ini)["host_path"]).read_bytes() == b"[Engine]"


@pytest.mark.parametrize("path", ["C:\\Windows\\System32\\config\\SAM", "C:\\mcp\\jobs\\other\\x.bin",
                                  "C:\\mcp\\jobs\\..\\secret.txt", "\\\\host\\share\\x"])
def test_download_outside_allowed_roots_is_refused(lab, path):
    gw = lab.gateway()
    gw.analysis_start(str(lab.sample()))
    with pytest.raises(PathNotAllowed):
        gw.file_download(path)


def test_download_needs_a_job(lab):
    with pytest.raises(StateViolation):
        lab.gateway().file_download("C:\\mcp\\jobs\\x\\out\\a.bin")


def test_downloads_survive_a_later_collection(lab):
    """collect_artifacts clears artifacts/raw/extra; earlier downloads must not be lost."""
    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    guest = f"{GUEST_ROOT}\\{job_id}\\out\\early.bin"
    lab.guest.write(guest, b"EARLY")
    downloaded = Path(gw.file_download(guest)["host_path"])
    col = gw.analysis_collect()
    kept = [Path(p) for p in col["preserved_downloads"]]
    assert len(kept) == 1 and kept[0].read_bytes() == b"EARLY"
    assert kept[0].parent == Path(lab.config.jobs_root) / job_id / "artifacts" / "downloads"
    assert not downloaded.exists()  # moved, not copied
    # files the previous collection fetched itself are not mistaken for downloads
    col2 = gw.analysis_collect()
    assert col2["preserved_downloads"] == []


# ── host secrets stay on the host (review finding) ──────────────────
@pytest.mark.parametrize("rel", [".ssh/id_rsa", ".gnupg/private.key", "proj/.env", ".netrc"])
def test_upload_of_hidden_files_under_a_root_is_refused(lab, rel):
    p = lab.samples / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"secret")
    gw = lab.gateway()
    with pytest.raises(PathNotAllowed):
        gw.file_upload(str(p), guest_dir="C:\\Tools")
    with pytest.raises(PathNotAllowed):
        gw.analysis_start(str(p))
    assert not lab.guest.calls_of("copy_to_guest")


def test_upload_of_the_gateway_env_file_and_config_is_refused(lab):
    env = lab.samples / "gw.env"
    env.write_bytes(b"GW_TEST_GUEST_PW=guest-pw\n")
    conf = lab.samples / "config.toml"
    conf.write_bytes(b"[gateway]\n")
    lab.set_config(env_file=str(env), config_path=str(conf))
    gw = lab.gateway()
    for p in (env, conf):
        with pytest.raises(PathNotAllowed):
            gw.file_upload(str(p), guest_dir="C:\\Tools")
    assert not lab.guest.calls_of("copy_to_guest")


def test_upload_from_a_hidden_root_itself_is_allowed(lab, tmp_path):
    root = tmp_path / ".samples"
    root.mkdir()
    (root / "a.bin").write_bytes(b"a")
    lab.set_config(upload_roots=(str(root),))
    out = lab.gateway().file_upload(str(root / "a.bin"), guest_dir="C:\\Tools")
    assert out["guest_path"] == "C:\\Tools\\a.bin"


# ── download size limit and serialisation with collect ──────────────
def test_download_over_the_size_limit_is_refused_before_copying(lab):
    from x64dbg_vm_gateway.errors import TransferError
    from x64dbg_vm_gateway.transfer import FetchLimits

    gw = lab.gateway(fetch_limits=FetchLimits(max_file_bytes=10, min_host_free_bytes=0))
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    guest = f"{GUEST_ROOT}\\{job_id}\\out\\big.bin"
    lab.guest.write(guest, b"x" * 20)
    with pytest.raises(TransferError) as ei:
        gw.file_download(guest)
    assert ei.value.details["reason"] == "too-large"
    assert not [a for a, _ in lab.guest.calls_of("copy_from_guest") if a[0] == guest]
    extra = Path(lab.config.jobs_root) / job_id / "artifacts" / "raw" / "extra"
    assert not extra.exists() or list(extra.iterdir()) == []


def test_download_is_refused_while_a_collection_runs(lab):
    import threading

    gw = lab.gateway()
    job_id = gw.analysis_start(str(lab.sample()))["job_id"]
    guest = f"{GUEST_ROOT}\\{job_id}\\out\\a.bin"
    lab.guest.write(guest, b"A")
    entered, release = threading.Event(), threading.Event()
    real = lab.vm.screenshot

    def slow_screenshot(path):
        entered.set()
        assert release.wait(10)
        real(path)

    lab.vm.screenshot = slow_screenshot  # type: ignore[method-assign]
    t = threading.Thread(target=gw.analysis_collect, daemon=True)
    t.start()
    try:
        assert entered.wait(5)
        with pytest.raises(StateViolation) as ei:
            gw.file_download(guest)
        assert "analysis_collect" in ei.value.hint
    finally:
        release.set()
        t.join(10)
    assert Path(gw.file_download(guest)["host_path"]).read_bytes() == b"A"
