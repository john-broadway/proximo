"""gen_tools_doc.type_str — the doc renderer must not leak raw JSON-schema type structures.

pydantic v2 emits LIST-form types for a nullable scalar (`["string", "null"]` for `str | None`);
the renderer used to fall through to str(t) and print "['string', 'null']" into ~1,100 doc cells.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import gen_tools_doc as g  # noqa: E402


def test_list_form_nullable_scalar_renders_readably():
    assert g.type_str({"type": ["string", "null"]}) == "string (nullable)"
    assert g.type_str({"type": ["integer", "null"]}) == "integer (nullable)"


def test_plain_and_array_and_anyof_still_render():
    assert g.type_str({"type": "string"}) == "string"
    assert g.type_str({"type": "array", "items": {"type": "string"}}) == "array<string>"
    assert g.type_str({"anyOf": [{"type": "object"}, {"type": "null"}]}) == "object (nullable)"
    assert g.type_str({"enum": ["a", "b"]}) == "enum(a, b)"


def test_no_raw_list_bracket_leaks():
    # The exact defect: a bracketed list must never survive into a cell.
    assert "[" not in g.type_str({"type": ["string", "null"]})


def test_current_tools_doc_has_no_raw_type_lists():
    """The committed docs/TOOLS.md must carry no raw ['...'] type cells (regen after the fix)."""
    doc = (REPO_ROOT / "docs" / "TOOLS.md").read_text()
    assert "['string', 'null']" not in doc
    assert "['integer', 'null']" not in doc
