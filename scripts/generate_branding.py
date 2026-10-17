#!/usr/bin/env python3
"""Generate WezCrypt Aegis branding assets (original artwork).

Outputs into assets/branding/:
  logo.svg            vector logo (shield + W chevron)
  aegis-<N>.png       raster icons (16..256 px)
  aegis.ico           multi-resolution Windows icon

The artwork is drawn from simple geometry defined in this file, so the
assets can be regenerated reproducibly:  python3 scripts/generate_branding.py
"""
import argparse
import logging
import math
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:  # pragma: no cover
    sys.exit("Pillow is required: pip install pillow")

LOG = logging.getLogger("branding")
CYAN = (34, 227, 255)
BLUE = (47, 107, 255)
WHITE = (233, 246, 255)
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]

SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="256" height="256">
  <title>WezCrypt Aegis</title>
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#22e3ff"/>
      <stop offset="1" stop-color="#2f6bff"/>
    </linearGradient>
  </defs>
  <path d="M32 4 L56 13 V30 C56 45 46 55 32 60 C18 55 8 45 8 30 V13 Z" fill="#121417"
        stroke="url(#g)" stroke-width="4" stroke-linejoin="round"/>
  <path d="M20 22 L26 42 L32 28 L38 42 L44 22" fill="none" stroke="#e9f6ff" stroke-width="4"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""


def cubic(p0, p1, p2, p3, steps=48):
    pts = []
    for i in range(steps + 1):
        t = i / steps
        a = (1 - t) ** 3
        b = 3 * (1 - t) ** 2 * t
        c = 3 * (1 - t) * t ** 2
        d = t ** 3
        pts.append((a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0],
                    a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1]))
    return pts


def shield_outline():
    pts = [(32, 4), (56, 13), (56, 30)]
    pts += cubic((56, 30), (56, 45), (46, 55), (32, 60))[1:]
    pts += cubic((32, 60), (18, 55), (8, 45), (8, 30))[1:]
    pts += [(8, 13)]
    return pts


def gradient(size):
    img = Image.new("RGBA", (size, size))
    px = img.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * (size - 1))
            px[x, y] = tuple(int(CYAN[i] + (BLUE[i] - CYAN[i]) * t) for i in range(3)) + (255,)
    return img


def render(size):
    scale = 16  # supersampling factor
    big = size * scale
    k = big / 64.0
    outline = [(x * k, y * k) for x, y in shield_outline()]
    stroke = max(1, int(round(4 * k)))

    base = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(base)
    d.polygon(outline, fill=(18, 20, 23, 255))

    mask = Image.new("L", (big, big), 0)
    md = ImageDraw.Draw(mask)
    md.line(outline + [outline[0]], fill=255, width=stroke, joint="curve")
    for x, y in outline:
        md.ellipse([x - stroke / 2, y - stroke / 2, x + stroke / 2, y + stroke / 2], fill=255)
    base.paste(gradient(big), (0, 0), mask)

    chevron = [(20 * k, 22 * k), (26 * k, 42 * k), (32 * k, 28 * k), (38 * k, 42 * k), (44 * k, 22 * k)]
    d = ImageDraw.Draw(base)
    d.line(chevron, fill=WHITE + (255,), width=stroke, joint="curve")
    for x, y in (chevron[0], chevron[-1]):
        d.ellipse([x - stroke / 2, y - stroke / 2, x + stroke / 2, y + stroke / 2], fill=WHITE + (255,))
    return base.resize((size, size), Image.LANCZOS)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parent.parent / "assets" / "branding")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "logo.svg").write_text(SVG, encoding="utf-8")
    images = {}
    for s in SIZES:
        images[s] = render(s)
        path = args.out / f"aegis-{s}.png"
        images[s].save(path, optimize=True)
        LOG.debug("wrote %s", path)
    ico_sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    images[256].save(args.out / "aegis.ico", sizes=[(s, s) for s in ico_sizes])
    LOG.info("branding assets written to %s", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
