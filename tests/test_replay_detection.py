"""``--replay DIR``: the vendor is read from the directory name, so replays need neither pyATS nor --device-type."""

from __future__ import annotations

from pathlib import Path

import pytest

import main
from src.vendors import supported_device_types

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
# Sample directories whose parser is pure Python: replaying them must not require Cisco pyATS/Genie.
NON_GENIE_SAMPLES = ["vyos", "arista_eos", "huawei", "aruba_aoscx"]


def _args(replay: Path, *extra: str):
    return main.parse_args(["--replay", str(replay), *extra])


# ====================================================== detection from the path
@pytest.mark.parametrize("device_type", supported_device_types())
def test_a_directory_named_after_a_device_type_is_detected(tmp_path, device_type):
    assert main.detect_replay_device_type(tmp_path / device_type) == device_type


def test_detection_ignores_case_and_a_trailing_slash(tmp_path):
    assert main.detect_replay_device_type(Path(f"{tmp_path}/VyOS/")) == "vyos"


def test_a_relative_dot_is_resolved_before_matching(tmp_path, monkeypatch):
    target = tmp_path / "arista_eos"
    target.mkdir()
    monkeypatch.chdir(target)
    assert main.detect_replay_device_type(Path(".")) == "arista_eos"


def test_an_unrelated_directory_name_is_not_detected(tmp_path):
    assert main.detect_replay_device_type(tmp_path / "my_router") is None


def test_a_vendor_name_higher_up_the_path_is_not_picked_up(tmp_path):
    assert main.detect_replay_device_type(tmp_path / "vyos" / "my_router") is None


# ====================================================== precedence
def test_an_explicit_device_type_beats_the_directory_name(tmp_path):
    args = _args(tmp_path / "vyos", "--device-type", "arista_eos")
    assert main.replay_device_type(args, {}) == "arista_eos"


def test_the_directory_name_beats_the_settings_file(tmp_path):
    settings = {
        "seeds": {"device_type": "cisco_ios", "devices": [{"device_type": "cisco_xr"}]}
    }
    assert main.replay_device_type(_args(tmp_path / "huawei"), settings) == "huawei"


def test_shared_seeds_device_type_is_the_first_fallback(tmp_path):
    settings = {
        "seeds": {"device_type": "juniper_junos", "devices": [{"device_type": "vyos"}]},
        "device": {"device_type": "cisco_xr"},
    }
    assert (
        main.replay_device_type(_args(tmp_path / "my_router"), settings)
        == "juniper_junos"
    )


def test_the_first_seed_device_type_is_the_second_fallback(tmp_path):
    settings = {
        "seeds": {"devices": [{"device_type": "vyos"}, {"device_type": "cisco_xr"}]},
        "device": {"device_type": "cisco_nxos"},
    }
    assert main.replay_device_type(_args(tmp_path / "my_router"), settings) == "vyos"


def test_the_legacy_device_block_is_the_third_fallback(tmp_path):
    settings = {"device": {"device_type": "cisco_nxos"}}
    assert (
        main.replay_device_type(_args(tmp_path / "my_router"), settings) == "cisco_nxos"
    )


@pytest.mark.parametrize(
    "settings",
    [
        {},
        {"seeds": None, "device": None},
        {"seeds": {"devices": []}},
        {"seeds": {"devices": ["not-a-mapping"]}},
        {"seeds": "not-a-mapping"},
    ],
)
def test_cisco_ios_is_the_default_when_nothing_says_otherwise(tmp_path, settings):
    assert (
        main.replay_device_type(_args(tmp_path / "my_router"), settings) == "cisco_ios"
    )


# ====================================================== build_poller
@pytest.mark.parametrize("sample", NON_GENIE_SAMPLES)
def test_replaying_a_vendor_sample_needs_no_genie_and_no_device_type(sample):
    args = _args(SAMPLES / sample)
    poller = main.build_poller(args, {}, ingest=None)

    (replay,) = poller.pollers
    assert replay.device_type == sample
    # The step run() performs before polling: it is what failed with "pyATS/Genie is not installed".
    main.ParserPool().get(replay.device_type, replay.process_id)
