"""Tests for the generic CustomToolWrapper runner and its arg validation."""

from __future__ import annotations

import pytest
from ice_9.tools.custom import CustomToolWrapper


def _tool() -> CustomToolWrapper:
    return CustomToolWrapper(name="x", binary="/bin/echo")


class TestBuildCommand:
    def test_order_binary_pre_target_post_args(self):
        cmd = _tool().build_command(
            "tgt", pre_args=["-v"], post_args=["--out", "f"], args=["-x"]
        )
        assert cmd == ["/bin/echo", "-v", "tgt", "--out", "f", "-x"]

    def test_empty_target_omitted(self):
        cmd = _tool().build_command("", pre_args=["-h"])
        assert "tgt" not in cmd
        assert cmd == ["/bin/echo", "-h"]

    def test_no_args_is_just_binary_and_target(self):
        assert _tool().build_command("tgt") == ["/bin/echo", "tgt"]


class TestArgValidation:
    @pytest.mark.parametrize("field", ["pre_args", "post_args", "args"])
    def test_bare_string_rejected(self, field):
        with pytest.raises(ValueError, match="list of strings"):
            _tool().build_command("tgt", **{field: "-rf"})

    @pytest.mark.parametrize("field", ["pre_args", "post_args", "args"])
    def test_non_string_element_rejected(self, field):
        with pytest.raises(ValueError, match="must be a string"):
            _tool().build_command("tgt", **{field: ["ok", 7]})

    def test_none_element_rejected(self):
        with pytest.raises(ValueError, match="must be a string"):
            _tool().build_command("tgt", args=["ok", None])

    def test_null_byte_rejected(self):
        with pytest.raises(ValueError, match="null byte"):
            _tool().build_command("tgt", args=["a\x00b"])

    def test_none_coerces_to_empty(self):
        assert _tool().build_command("tgt", pre_args=None, args=None) == [
            "/bin/echo",
            "tgt",
        ]

    def test_tuple_accepted(self):
        cmd = _tool().build_command("tgt", args=("-a", "-b"))
        assert cmd == ["/bin/echo", "tgt", "-a", "-b"]
