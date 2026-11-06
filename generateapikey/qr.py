"""QR codes for MFA setup. Needs the optional extra: ``pip install generateapikey[qr]``."""

from __future__ import annotations

import io
from typing import Any

__all__ = ["qr_ascii", "qr_png", "qr_svg"]


def _qrcode() -> Any:
    try:
        import qrcode
    except ImportError:  # pragma: no cover - depends on environment
        raise ImportError("QR support needs the 'qrcode' package: pip install generateapikey[qr]") from None
    return qrcode


def _make(data: str) -> Any:
    qrcode = _qrcode()
    qr = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(data)
    qr.make(fit=True)
    return qr


def qr_ascii(data: str, invert: bool = False) -> str:
    """Return a QR code drawn with text, for printing in a terminal."""
    out = io.StringIO()
    _make(data).print_ascii(out=out, invert=invert)
    return out.getvalue()


def qr_svg(data: str) -> str:
    """Return a QR code as an SVG string (embed straight into HTML)."""
    from qrcode.image.svg import SvgPathImage

    img = _make(data).make_image(image_factory=SvgPathImage)
    out = io.BytesIO()
    img.save(out)
    return out.getvalue().decode()


def qr_png(data: str) -> bytes:
    """Return a QR code as PNG bytes (uses ``pypng``, installed with the extra)."""
    from qrcode.image.pure import PyPNGImage

    img = _make(data).make_image(image_factory=PyPNGImage)
    out = io.BytesIO()
    img.save(out)
    return out.getvalue()
