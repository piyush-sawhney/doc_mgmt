"""Hostile-input corpus for the render worker (``docs/12`` §6, ``docs/17`` S5).

The worker is the only component that parses untrusted bytes. These tests keep
the corpus honest: every malformed, encrypted, oversized, active, or
mismatched input must fail as a ``ValueError`` before it can reach a PDF or an
image decoder's happy path. Nothing here needs a database.
"""

from __future__ import annotations

from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import fitz
import pytest
from PIL import Image

from worker.printing import compose_pdf
from worker.rendering import (
    MAX_DIMENSION,
    MAX_PIXELS,
    _validate_office_archive,
    inspect_pdf,
    render_page,
)

LAYOUT = {
    "paper": "A4",
    "orientation": "portrait",
    "margin_mm": 5,
    "gutter_mm": 4,
    "cells_per_side": 1,
    "duplex": False,
    "fit_mode": "contain",
}


def _pdf(*, text: str = "sample") -> bytes:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), text)
    result = document.tobytes()
    document.close()
    return result


def _png(size: tuple[int, int], mode: str = "RGB") -> bytes:
    image = Image.new(mode, size, "white")
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _encrypted_pdf() -> bytes:
    document = fitz.open()
    document.new_page()
    result = document.tobytes(
        encryption=fitz.PDF_ENCRYPT_AES_256,
        owner_pw="owner-secret",
        user_pw="user-secret",
    )
    document.close()
    return result


def _pdf_with_embedded_file() -> bytes:
    document = fitz.open()
    document.new_page()
    document.embfile_add("note.txt", b"payload")
    result = document.tobytes()
    document.close()
    return result


def _pdf_with_hidden_javascript() -> bytes:
    document = fitz.open()
    document.new_page()
    xref = document.get_new_xref()
    document.update_object(xref, "<< /S /JavaScript /JS (app.alert(1)) >>")
    result = document.tobytes()
    document.close()
    return result


def _pdf_with_page_above_the_print_limit() -> bytes:
    document = fitz.open()
    # 3000 mm > the 2000 mm print limit.
    document.new_page(width=3000 * 72 / 25.4, height=3000 * 72 / 25.4)
    result = document.tobytes()
    document.close()
    return result


@pytest.mark.parametrize(
    ("label", "data"),
    [
        pytest.param("empty", b"", id="empty"),
        pytest.param("header-only", b"%PDF-1.7\n", id="header-only"),
        pytest.param("plain-text", b"this is not a pdf", id="plain-text"),
        pytest.param("truncated", _pdf()[:40], id="truncated"),
        pytest.param("encrypted", _encrypted_pdf(), id="encrypted"),
        pytest.param("embedded-file", _pdf_with_embedded_file(), id="embedded-file"),
        pytest.param("hidden-javascript", _pdf_with_hidden_javascript(), id="hidden-javascript"),
    ],
)
def test_malformed_or_active_pdfs_are_refused(label: str, data: bytes) -> None:
    del label
    with pytest.raises(ValueError, match="PDF"):
        inspect_pdf(data)


def test_a_pdf_above_the_print_dimension_limit_is_refused_by_the_composer() -> None:
    with pytest.raises(ValueError, match="maximum dimensions"):
        compose_pdf(
            pages=[
                {
                    "data": _pdf_with_page_above_the_print_limit(),
                    "mime": "application/pdf",
                    "page": 1,
                }
            ],
            layout=LAYOUT,
        )


def test_an_empty_pdf_is_refused_by_the_page_renderer() -> None:
    with pytest.raises(ValueError, match="PDF"):
        render_page(b"", mime="application/pdf", page=1, recipe={})


def test_a_page_outside_the_document_is_refused() -> None:
    with pytest.raises(ValueError, match="does not exist"):
        render_page(_pdf(), mime="application/pdf", page=2, recipe={})
    with pytest.raises(ValueError, match="does not exist"):
        render_page(_pdf(), mime="application/pdf", page=0, recipe={})


@pytest.mark.parametrize("edge", [0, -1, 2401])
def test_an_impossible_render_size_is_refused(edge: int) -> None:
    with pytest.raises(ValueError, match="render size"):
        render_page(_pdf(), mime="application/pdf", page=1, recipe={}, max_edge=edge)


def test_a_mime_mismatch_is_refused() -> None:
    png = _png((32, 32))
    with pytest.raises(ValueError, match="not a JPEG"):
        render_page(png, mime="image/jpeg", page=1, recipe={})

    jpeg = BytesIO()
    Image.new("RGB", (32, 32), "white").save(jpeg, format="JPEG")
    with pytest.raises(ValueError, match="not a PNG"):
        render_page(jpeg.getvalue(), mime="image/png", page=1, recipe={})

    with pytest.raises(ValueError, match="Unsupported source format"):
        render_page(png, mime="image/tiff", page=1, recipe={})


def test_an_image_with_too_many_pixels_is_refused() -> None:
    pixels = _png((6500, 6500), mode="L")
    with pytest.raises(ValueError, match="pixel count"):
        render_page(pixels, mime="image/png", page=1, recipe={})


def test_an_image_over_the_dimension_limit_is_refused() -> None:
    wide = _png((MAX_DIMENSION + 1, 1), mode="L")
    with pytest.raises(ValueError, match="dimensions"):
        render_page(wide, mime="image/png", page=1, recipe={})


def test_the_pixel_limit_is_the_documented_number() -> None:
    assert MAX_PIXELS == 40_000_000
    assert MAX_DIMENSION == 20_000


def test_transparency_is_flattened_onto_white() -> None:
    image = Image.new("RGBA", (40, 40), (0, 0, 0, 0))
    image.paste((0, 0, 0, 255), (10, 10, 30, 30))
    output = BytesIO()
    image.save(output, format="PNG")

    rendered = render_page(output.getvalue(), mime="image/png", page=1, recipe={}, max_edge=400)

    result = Image.open(BytesIO(rendered["data"])).convert("RGB")
    assert result.getpixel((0, 0)) == (255, 255, 255)
    assert result.getpixel((result.width // 2, result.height // 2)) == (0, 0, 0)


def test_a_docx_without_its_content_types_is_refused() -> None:
    package = BytesIO()
    with ZipFile(package, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", "<document/>")
    with pytest.raises(ValueError, match="incomplete"):
        _validate_office_archive(package.getvalue(), ".docx")


def test_a_docx_with_a_macro_is_refused() -> None:
    package = BytesIO()
    with ZipFile(package, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
        archive.writestr("word/vbaProject.bin", b"macro")
    with pytest.raises(ValueError, match="macros"):
        _validate_office_archive(package.getvalue(), ".docx")


def test_a_docx_zip_bomb_is_refused() -> None:
    package = BytesIO()
    with ZipFile(package, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", b"\x00" * 2_000_000)
    with pytest.raises(ValueError, match="compression ratio"):
        _validate_office_archive(package.getvalue(), ".docx")


def test_an_odt_without_its_mimetype_is_refused() -> None:
    package = BytesIO()
    with ZipFile(package, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("content.xml", "<office/>")
    with pytest.raises(ValueError, match="incomplete"):
        _validate_office_archive(package.getvalue(), ".odt")


def test_a_malformed_office_archive_is_refused() -> None:
    with pytest.raises(ValueError, match="malformed"):
        _validate_office_archive(b"PK\x03\x04 not a zip", ".docx")
