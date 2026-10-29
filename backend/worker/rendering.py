"""Document decoding, validation, and image recipes."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

import fitz  # type: ignore[import-untyped]
from PIL import Image, ImageChops, ImageEnhance, ImageFilter, ImageOps, UnidentifiedImageError

MAX_PAGES = 5000
MAX_PIXELS = 40_000_000
MAX_DIMENSION = 20_000
MAX_OFFICE_PDF_BYTES = 100 * 1024 * 1024
OFFICE_EXTENSIONS = {".doc", ".docx", ".odt"}
ACTIVE_PDF_NAMES = re.compile(
    r"/(?:JavaScript|JS|Launch|EmbeddedFiles?|OpenAction|AA)(?![A-Za-z0-9])"
)


def _pdf_document(data: bytes) -> Any:
    document = fitz.open(stream=data, filetype="pdf")
    if document.is_encrypted or document.is_repaired or document.page_count < 1:
        document.close()
        raise ValueError("The PDF is encrypted, repaired, or empty.")
    if document.page_count > MAX_PAGES:
        document.close()
        raise ValueError("The PDF contains too many pages.")
    for key in ("OpenAction", "AA", "JavaScript", "JS", "EmbeddedFiles"):
        kind, value = document.xref_get_key(-1, key)
        if kind != "null" and value.lower() not in ("null", "none", ""):
            document.close()
            raise ValueError("The PDF contains active content or embedded files.")
    for xref in range(1, document.xref_length()):
        if ACTIVE_PDF_NAMES.search(document.xref_object(xref, compressed=False)):
            document.close()
            raise ValueError("The PDF contains active content or embedded files.")
    if document.embfile_count():
        document.close()
        raise ValueError("The PDF contains embedded files.")
    return document


def inspect_pdf(data: bytes) -> dict[str, Any]:
    try:
        document = _pdf_document(data)
    except (fitz.FileDataError, fitz.EmptyFileError, ValueError) as exc:
        raise ValueError("The PDF is malformed or contains unsupported content.") from exc
    try:
        dimensions = [
            {"width_pt": page.rect.width, "height_pt": page.rect.height} for page in document
        ]
        return {"page_count": document.page_count, "dimensions": dimensions}
    finally:
        document.close()


def _apply_recipe(image: Image.Image, recipe: dict[str, Any]) -> Image.Image:
    rotate = recipe.get("rotate", 0)
    if rotate:
        image = image.rotate(-rotate, expand=True, resample=Image.Resampling.BICUBIC)
    straighten = recipe.get("straighten", 0)
    if straighten:
        image = image.rotate(straighten, expand=True, resample=Image.Resampling.BICUBIC)
    crop = recipe.get("crop")
    if crop is not None:
        left, top, right, bottom = crop
        box = (
            round(left * image.width),
            round(top * image.height),
            round(right * image.width),
            round(bottom * image.height),
        )
        image = image.crop(box)
    if recipe.get("grayscale"):
        image = ImageOps.grayscale(image)
    if recipe.get("invert"):
        image = ImageOps.invert(image.convert("RGB"))
    brightness = recipe.get("brightness", 0)
    if brightness:
        image = ImageEnhance.Brightness(image).enhance(1 + brightness / 100)
    contrast = recipe.get("contrast", 0)
    if contrast:
        image = ImageEnhance.Contrast(image).enhance(1 + contrast / 100)
    gamma = recipe.get("gamma", 1)
    if gamma != 1:
        lut = [min(255, round(((value / 255) ** (1 / gamma)) * 255)) for value in range(256)]
        image = image.point(lut * (len(image.getbands())))
    threshold = recipe.get("threshold")
    if threshold is not None:
        image = ImageOps.grayscale(image).point(
            lambda value: 255 if value >= threshold else 0, mode="1"
        )
    if recipe.get("despeckle"):
        image = image.filter(ImageFilter.MedianFilter(size=3))
    if recipe.get("auto_trim"):
        background = Image.new(image.mode, image.size, 255)
        difference = ImageChops.difference(image, background)
        bounds = difference.getbbox()
        if bounds:
            image = image.crop(bounds)
    return image


def _open_image(data: bytes, mime: str) -> Image.Image:
    try:
        image = Image.open(BytesIO(data))
        image.load()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("The image is malformed or exceeds decoder limits.") from exc
    if image.width > MAX_DIMENSION or image.height > MAX_DIMENSION:
        raise ValueError("Image dimensions exceed the render limit.")
    if image.width * image.height > MAX_PIXELS:
        raise ValueError("Image pixel count exceeds the render limit.")
    if mime == "image/jpeg" and image.format != "JPEG":
        raise ValueError("The file is not a JPEG image.")
    if mime == "image/png" and image.format != "PNG":
        raise ValueError("The file is not a PNG image.")
    if image.mode in ("RGBA", "LA") or "transparency" in image.info:
        rgba = image.convert("RGBA")
        background = Image.new("RGB", rgba.size, "white")
        background.paste(rgba, mask=rgba.getchannel("A"))
        return background
    return image.convert("RGB")


def render_page(
    data: bytes,
    *,
    mime: str,
    page: int,
    recipe: dict[str, Any],
    max_edge: int = 1200,
) -> dict[str, Any]:
    if max_edge < 1 or max_edge > 2400:
        raise ValueError("The requested render size is outside the allowed range.")
    if mime == "application/pdf":
        document = _pdf_document(data)
        try:
            if page < 1 or page > document.page_count:
                raise ValueError("The requested page does not exist.")
            source = document[page - 1]
            scale = min(max_edge / source.rect.width, max_edge / source.rect.height)
            pixmap = source.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
            image = Image.frombytes("RGB", (pixmap.width, pixmap.height), pixmap.samples)
            dimensions = (source.rect.width, source.rect.height)
            page_count = document.page_count
        finally:
            document.close()
    elif mime in ("image/jpeg", "image/png"):
        if page != 1:
            raise ValueError("An image has only one page.")
        image = _open_image(data, mime)
        dimensions = image.size
        page_count = 1
    else:
        raise ValueError("Unsupported source format.")
    image = _apply_recipe(image, recipe)
    image.thumbnail((max_edge, max_edge), Image.Resampling.LANCZOS)
    output = BytesIO()
    image.save(output, format="PNG", optimize=False)
    return {
        "data": output.getvalue(),
        "info": {
            "page_count": page_count,
            "width": image.width,
            "height": image.height,
            "source_dimensions": list(dimensions),
        },
    }


def _validate_office_archive(data: bytes, extension: str) -> None:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > 10_000 or sum(item.file_size for item in entries) > 200_000_000:
                raise ValueError("The Office archive exceeds its structural limits.")
            if any(
                item.file_size > 0 and item.file_size / max(item.compress_size, 1) > 500
                for item in entries
            ):
                raise ValueError("The Office archive has an excessive compression ratio.")
            names = {item.filename for item in entries}
            if extension == ".docx":
                if not {"[Content_Types].xml", "word/document.xml"} <= names:
                    raise ValueError("The DOCX package is incomplete.")
                if any(
                    name.lower().startswith("word/embeddings/")
                    or name.lower().endswith("vbaproject.bin")
                    for name in names
                ):
                    raise ValueError("DOCX macros and embedded files are not accepted.")
            elif (
                "content.xml" not in names
                or archive.read("mimetype") != b"application/vnd.oasis.opendocument.text"
            ):
                raise ValueError("The ODT package is incomplete.")
            for item in entries:
                if item.filename.endswith(".rels") and item.file_size <= 1_000_000:
                    relations = archive.read(item.filename)
                    if re.search(rb'TargetMode\s*=\s*["\']External["\']', relations, re.I):
                        raise ValueError("External Office relationships are not accepted.")
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise ValueError("The Office archive is malformed.") from exc


def convert_office(data: bytes, *, filename: str, converter: str) -> bytes:
    extension = Path(filename).suffix.lower()
    if extension not in OFFICE_EXTENSIONS:
        raise ValueError("Only DOC, DOCX, and ODT files can be converted.")
    if not Path(converter).is_file():
        raise FileNotFoundError("The configured Office converter does not exist.")
    if extension in {".docx", ".odt"}:
        _validate_office_archive(data, extension)
    with tempfile.TemporaryDirectory(prefix="docvault-office-") as directory:
        work = Path(directory)
        input_path = work / f"source{extension}"
        input_path.write_bytes(data)
        input_path.chmod(0o600)
        profile = work / "profile"
        command = [
            converter,
            "-env:UserInstallation=" + profile.as_uri(),
            "--headless",
            "--convert-to",
            "pdf",
            "--outdir",
            str(work),
            str(input_path),
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=60,
            cwd=work,
            env={"HOME": str(work), "TMPDIR": str(work), "PATH": os.defpath},
        )
        if completed.returncode != 0:
            raise ValueError("The Office document could not be converted.")
        output_path = work / "source.pdf"
        if not output_path.is_file() or output_path.stat().st_size > MAX_OFFICE_PDF_BYTES:
            raise ValueError("The conversion output is missing or exceeds the size limit.")
        result = output_path.read_bytes()
        inspect_pdf(result)
        return result
