"""The print layout contract from ``docs/12``.

Geometry is the one part of printing that is easy to get subtly wrong: a grid
that looks right on A4 can leave a negative cell on A3, and a tiny scan that is
"filled" to a page is a silent quality downgrade. These tests pin the numbers
and the no-upscale rule.
"""

from __future__ import annotations

import math

import fitz
import pytest
from PIL import Image, ImageOps
from pydantic import ValidationError

from app.api.printing import PrintLayout
from worker.printing import PAPER_MM, compose_pdf, layout_cells

MM = 72 / 25.4


def _layout(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "paper": "A4",
        "orientation": "portrait",
        "margin_mm": 5,
        "gutter_mm": 4,
        "cells_per_side": 1,
        "duplex": False,
        "fit_mode": "contain",
    }
    values.update(overrides)
    return values


def _small_page(width: float = 20, height: float = 20) -> bytes:
    document = fitz.open()
    page = document.new_page(width=width, height=height)
    page.draw_rect(page.rect, color=(0, 0, 0), fill=(0, 0, 0))
    result = document.tobytes()
    document.close()
    return result


def _ink_bbox(page: fitz.Page) -> tuple[int, int, int, int]:
    pixmap = page.get_pixmap(dpi=72, alpha=False)
    image = Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)
    bbox = ImageOps.invert(image.convert("L")).getbbox()
    assert bbox is not None
    return bbox


def test_a4_one_up_uses_the_documented_box() -> None:
    page, cells = layout_cells(_layout())

    margin = 5 * MM
    assert page.width == pytest.approx(210 * MM)
    assert page.height == pytest.approx(297 * MM)
    assert len(cells) == 1
    assert cells[0].x0 == pytest.approx(margin)
    assert cells[0].y0 == pytest.approx(margin)
    assert cells[0].width == pytest.approx(200 * MM)
    assert cells[0].height == pytest.approx(287 * MM)


def test_four_up_cells_are_row_major_and_do_not_overlap() -> None:
    _page, cells = layout_cells(_layout(cells_per_side=4))

    gutter = 4 * MM
    expected_width = (200 * MM - gutter) / 2
    expected_height = (287 * MM - gutter) / 2
    assert len(cells) == 4
    assert [cell.width for cell in cells] == pytest.approx([expected_width] * 4)
    assert [cell.height for cell in cells] == pytest.approx([expected_height] * 4)
    # Reading order is left-to-right, then top-to-bottom.
    assert cells[0].x0 < cells[1].x0
    assert cells[0].y0 == pytest.approx(cells[1].y0)
    assert cells[2].y0 > cells[0].y0
    assert cells[2].x0 == pytest.approx(cells[0].x0)
    for index, cell in enumerate(cells):
        for other in cells[index + 1 :]:
            assert not cell.intersects(other)


def test_landscape_swaps_the_paper_axes() -> None:
    page, cells = layout_cells(_layout(orientation="landscape"))

    assert page.width == pytest.approx(297 * MM)
    assert page.height == pytest.approx(210 * MM)
    assert cells[0].width == pytest.approx(287 * MM)
    assert cells[0].height == pytest.approx(200 * MM)


@pytest.mark.parametrize("paper", sorted(PAPER_MM))
def test_every_paper_and_grid_stays_inside_the_page(paper: str) -> None:
    for cells_per_side in (1, 2, 4, 6, 9):
        for orientation in ("portrait", "landscape"):
            page, cells = layout_cells(
                _layout(
                    paper=paper,
                    orientation=orientation,
                    cells_per_side=cells_per_side,
                    margin_mm=25,
                    gutter_mm=12,
                )
            )
            assert len(cells) == cells_per_side
            assert all(page.contains(cell) for cell in cells)


def test_contain_never_enlarges_a_small_source() -> None:
    result = compose_pdf(
        pages=[{"data": _small_page(), "mime": "application/pdf", "page": 1}],
        layout=_layout(),
    )
    document = fitz.open(stream=result, filetype="pdf")
    try:
        left, top, right, bottom = _ink_bbox(document[0])
        assert right - left <= 21
        assert bottom - top <= 21
        # Centred inside the printable box, not pushed into a corner.
        assert abs((left + right) / 2 - document[0].rect.width / 2) <= 2
        assert abs((top + bottom) / 2 - document[0].rect.height / 2) <= 2
    finally:
        document.close()


def test_fill_crops_but_still_does_not_enlarge() -> None:
    result = compose_pdf(
        pages=[{"data": _small_page(), "mime": "application/pdf", "page": 1}],
        layout=_layout(fit_mode="fill"),
    )
    document = fitz.open(stream=result, filetype="pdf")
    try:
        left, top, right, bottom = _ink_bbox(document[0])
        assert right - left <= 21
        assert bottom - top <= 21
        # A square source is centre-cropped to the tall A4 cell ratio.
        assert (bottom - top) > (right - left)
    finally:
        document.close()


def test_a_large_source_is_scaled_down_to_the_cell() -> None:
    result = compose_pdf(
        pages=[{"data": _small_page(1200, 1200), "mime": "application/pdf", "page": 1}],
        layout=_layout(),
    )
    document = fitz.open(stream=result, filetype="pdf")
    try:
        left, top, right, bottom = _ink_bbox(document[0])
        # A square source is limited by the printable width, not the height.
        assert right - left == pytest.approx(bottom - top, abs=2)
        assert right - left <= math.ceil(200 * MM) + 2
        assert right - left > 500
    finally:
        document.close()


@pytest.mark.parametrize(
    ("overrides", "valid"),
    [
        pytest.param({"margin_mm": 0}, True, id="zero-margin"),
        pytest.param({"margin_mm": 25}, True, id="maximum-margin"),
        pytest.param({"margin_mm": 6}, False, id="margin-not-a-five-step"),
        pytest.param({"margin_mm": 30}, False, id="margin-above-maximum"),
        pytest.param({"gutter_mm": 12}, True, id="maximum-gutter"),
        pytest.param({"gutter_mm": 13}, False, id="gutter-above-maximum"),
        pytest.param({"gutter_mm": -1}, False, id="negative-gutter"),
    ],
)
def test_layout_limits_match_the_documented_ranges(
    overrides: dict[str, object], valid: bool
) -> None:
    if valid:
        PrintLayout(**overrides)
    else:
        with pytest.raises(ValidationError):
            PrintLayout(**overrides)


def test_duplex_requires_a_flip_edge_and_vice_versa() -> None:
    PrintLayout(duplex=True, flip_edge="long")
    with pytest.raises(ValidationError):
        PrintLayout(duplex=True)
    with pytest.raises(ValidationError):
        PrintLayout(duplex=False, flip_edge="long")
