# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Thumbnail generation (PIL if available)."""

import logging
from io import BytesIO
from typing import Optional

from hokora.constants import MAX_THUMBNAIL_BYTES

logger = logging.getLogger(__name__)

_PIL_AVAILABLE = False
try:
    from PIL import Image

    _PIL_AVAILABLE = True
except ImportError:
    pass


def generate_thumbnail(
    image_data: bytes,
    max_size: tuple[int, int] = (128, 128),
    max_bytes: int = MAX_THUMBNAIL_BYTES,
) -> Optional[bytes]:
    """Generate a thumbnail from image data. Returns JPEG bytes or None."""
    if not _PIL_AVAILABLE:
        logger.debug("PIL not available, skipping thumbnail generation")
        return None

    try:
        img = Image.open(BytesIO(image_data))
        img.thumbnail(max_size, Image.Resampling.LANCZOS)

        # Convert to RGB if needed (e.g., PNG with alpha)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        buf = BytesIO()
        quality = 85
        while quality >= 20:
            buf.seek(0)
            buf.truncate()
            img.save(buf, format="JPEG", quality=quality)
            if buf.tell() <= max_bytes:
                return buf.getvalue()
            quality -= 10

        logger.warning("Could not generate thumbnail within size limit")
        return None

    except Exception as e:
        logger.warning(f"Thumbnail generation failed: {e}")
        return None
