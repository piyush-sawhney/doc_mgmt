from __future__ import annotations

from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import fitz
import pytest

from worker.printing import PAPER_MM, compose_pdf, layout_cells
from worker.rendering import _validate_office_archive, inspect_pdf, render_page


def _pdf(text: str = "sample") -> bytes:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), text)
    result = document.tobytes()
    document.close()
    return result


def test_inspect_and_render_valid_pdf() -> None:
    source = _pdf()

    details = inspect_pdf(source)
    rendered = render_page(source, mime="application/pdf", page=1, recipe={}, max_edge=600)
    image = rendered["data"]
    info = rendered["info"]

    assert details["page_count"] == 1
    assert info["page_count"] == 1
    assert max(info["width"], info["height"]) <= 600
    assert image.startswith(b"\x89PNG\r\n\x1a\n")


def test_inspect_rejects_javascript_action() -> None:
    document = fitz.open()
    document.new_page()
    action_xref = document.get_new_xref()
    document.update_object(action_xref, "<< /S /JavaScript /JS (app.alert) >>")
    document.xref_set_key(document.pdf_catalog(), "OpenAction", f"{action_xref} 0 R")
    malicious_pdf = document.tobytes()
    document.close()

    with pytest.raises(ValueError, match="unsupported content"):
        inspect_pdf(malicious_pdf)


@pytest.mark.parametrize("paper", sorted(PAPER_MM))
@pytest.mark.parametrize("cells", [(1,), (2,), (4,), (6,), (9,)])
def test_grid_cells_fit_inside_paper(paper: str, cells: tuple[int]) -> None:
    page, boxes = layout_cells(
        {
            "paper": paper,
            "orientation": "portrait",
            "margin_mm": 5,
            "gutter_mm": 4,
            "cells_per_side": cells[0],
        }
    )

    assert len(boxes) == cells[0]
    assert all(page.contains(box) for box in boxes)


def test_composer_preserves_requested_page_order_and_metadata() -> None:
    result = compose_pdf(
        pages=[
            {"data": _pdf("first"), "mime": "application/pdf", "page": 1},
            {"data": _pdf("second"), "mime": "application/pdf", "page": 1},
            {"data": _pdf("third"), "mime": "application/pdf", "page": 1},
        ],
        layout={
            "paper": "A4",
            "orientation": "portrait",
            "margin_mm": 5,
            "gutter_mm": 4,
            "cells_per_side": 2,
            "duplex": True,
            "fit_mode": "contain",
        },
    )
    composed = fitz.open(stream=result, filetype="pdf")
    try:
        assert composed.page_count == 2
        assert not composed.metadata["title"]
        assert not composed.metadata["author"]
        assert "first" in composed[0].get_text()
        assert "second" in composed[0].get_text()
        assert "third" in composed[1].get_text()
    finally:
        composed.close()


def test_office_archive_rejects_external_relationships() -> None:
    package = BytesIO()
    with ZipFile(package, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
        archive.writestr(
            "word/_rels/document.xml.rels",
            '<Relationships><Relationship TargetMode="External"/></Relationships>',
        )

    with pytest.raises(ValueError, match="External Office relationships"):
        _validate_office_archive(package.getvalue(), ".docx")
