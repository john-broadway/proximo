"""The 0.49.1 review, pinned: the shell path's vmid is ASCII digits only (pct reads no other). Its other low
finding, a read on an unmapped route marking the session before it refuses, stays as ruled: on a read the taint
mark comes before the client build so a box with both faults reports `taint` (test_spine,
test_on_a_read_the_taint_refusal_still_speaks_before_the_config_one); the mark only makes the box stricter."""

from __future__ import annotations

import pytest

from proximo.core import shell


@pytest.mark.parametrize("vmid", ["\u0661\u0660\u0661", "\uff11\uff10\uff11", "1\u0660\u0661"])
def test_a_vmid_in_non_ascii_digits_is_not_a_shell_address(vmid):
    assert shell._match(f"/nodes/pve1/lxc/{vmid}/exec") is None
    assert shell._match("/nodes/pve1/lxc/101/exec") is not None
