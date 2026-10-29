"""PDF composition primitives for the isolated render worker."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import fitz  # type: ignore[import-untyped]
from PIL import Image

from worker.rendering import render_page

PAPER_MM = {
    "A5": (148, 210),
    "A4": (210, 297),
    "A3": (297, 420),
    "Letter": (215.9, 279.4),
    "Legal": (215.9, 355.6),
}
GRID = {1: (1, 1), 2: (1, 2), 4: (2, 2), 6: (2, 3), 9: (3, 3)}
MAX_PAGE_MM = 2000


def _page_document(page: dict[str, Any]) -> tuple[Any, int]:
    data = page["data"]
    mime = page["mime"]
    recipe = page.get("recipe", {})
    recipe_changed = recipe and (
        any(value for key, value in recipe.items() if key != "gamma") or recipe.get("gamma", 1) != 1
    )
    if recipe_changed:
        rendered = render_page(
            data,
            mime=mime,
            page=page["page"],
            recipe=recipe,
            max_edge=2400,
        )["data"]
        data, mime, page = rendered, "image/png", {**page, "page": 1}
    if mime == "application/pdf":
        document = fitz.open(stream=data, filetype="pdf")
        page_no = page["page"] - 1
        if document.is_encrypted or document.is_repaired or page_no < 0 or page_no >= len(document):
            document.close()
            raise ValueError("The PDF page is unavailable or malformed.")
        source = document[page_no]
        max_page_points = MAX_PAGE_MM / 25.4 * 72
        if source.rect.width > max_page_points or source.rect.height > max_page_points:
            document.close()
            raise ValueError("The PDF page exceeds the maximum dimensions.")
        return document, page_no
    if mime not in ("image/jpeg", "image/png"):
        raise ValueError("The print source format is unsupported.")
    image = Image.open(__import__("io").BytesIO(data))
    if image.width > 40_000 or image.height > 40_000 or image.width * image.height > 40_000_000:
        raise ValueError("The image exceeds the print dimension limit.")
    image.load()
    pdf = fitz.open()
    page_size = (image.width * 72 / 300, image.height * 72 / 300)
    created = pdf.new_page(width=page_size[0], height=page_size[1])
    created.insert_image(created.rect, stream=data, keep_proportion=False)
    return pdf, 0


def _paper_size(layout: dict[str, Any]) -> tuple[float, float]:
    width_mm, height_mm = PAPER_MM[layout["paper"]]
    if layout["orientation"] == "landscape":
        width_mm, height_mm = height_mm, width_mm
    width_pt, height_pt = width_mm * 72 / 25.4, height_mm * 72 / 25.4
    return width_pt, height_pt


def layout_cells(layout: dict[str, Any]) -> tuple[Any, list[Any]]:
    paper_width, paper_height = _paper_size(layout)
    margin = layout["margin_mm"] * 72 / 25.4
    gutter = layout["gutter_mm"] * 72 / 25.4
    cols, rows = GRID[layout["cells_per_side"]]
    page_rect = fitz.Rect(0, 0, paper_width, paper_height)
    box = fitz.Rect(
        page_rect.x0 + margin,
        page_rect.y0 + margin,
        page_rect.x1 - margin,
        page_rect.y1 - margin,
    )
    width = (box.width - gutter * (cols - 1)) / cols
    height = (box.height - gutter * (rows - 1)) / rows
    if width <= 0 or height <= 0:
        raise ValueError("Margins and gutters leave no printable area.")
    cells = [
        fitz.Rect(
            box.x0 + col * (width + gutter),
            box.y0 + row * (height + gutter),
            box.x0 + col * (width + gutter) + width,
            box.y0 + row * (height + gutter) + height,
        )
        for row in range(rows)
        for col in range(cols)
    ]
    return page_rect, cells


def compose_pdf(*, pages: Sequence[dict[str, Any]], layout: dict[str, Any]) -> bytes:
    if not pages:
        raise ValueError("A print job requires at least one page.")
    page_rect, cells = layout_cells(layout)
    output = fitz.open()
    for offset in range(0, len(pages), len(cells)):
        side = output.new_page(width=page_rect.width, height=page_rect.height)
        for cell, item in zip(cells, pages[offset : offset + len(cells)], strict=False):
            source_document, source_page = _page_document(item)
            try:
                source_rect = source_document[source_page].rect
                if layout["fit_mode"] == "fill":
                    source_ratio = source_rect.width / source_rect.height
                    target_ratio = cell.width / cell.height
                    clip = fitz.Rect(source_rect)
                    if source_ratio > target_ratio:
                        clip_width = source_rect.height * target_ratio
                        clip.x0 += (source_rect.width - clip_width) / 2
                        clip.x1 = clip.x0 + clip_width
                    else:
                        clip_height = source_rect.width / target_ratio
                        clip.y0 += (source_rect.height - clip_height) / 2
                        clip.y1 = clip.y0 + clip_height
                    side.show_pdf_page(cell, source_document, source_page, clip=clip)
                else:
                    scale = min(cell.width / source_rect.width, cell.height / source_rect.height)
                    target = fitz.Rect(
                        cell.x0 + (cell.width - source_rect.width * scale) / 2,
                        cell.y0 + (cell.height - source_rect.height * scale) / 2,
                        cell.x0 + (cell.width + source_rect.width * scale) / 2,
                        cell.y0 + (cell.height + source_rect.height * scale) / 2,
                    )
                    side.show_pdf_page(target, source_document, source_page, keep_proportion=True)
            finally:
                source_document.close()
    output.set_metadata(
        {
            "producer": "DocVault",
            "title": "",
            "author": "",
            "subject": "",
            "keywords": "",
            "creator": "",
            "creationDate": "",
            "modDate": "",
        }
    )
    return bytes(output.tobytes(garbage=4, deflate=True))
