#!/usr/bin/env python3
"""
Generate WSTS raster brand assets with Pillow (no SVG/cairo dependency).

Outputs into wsts/static/img/:
  • wsts_shield.png  (440x440, retina-friendly hero/logo)
  • favicon.png      (64x64)
  • wsts.ico         (multi-size Windows icon for the .exe + browser)

Run:  python wsts/gen_wsts_assets.py
"""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent / "static" / "img"
OUT.mkdir(parents=True, exist_ok=True)

# Brand palette
EDGE_TOP  = (255, 107, 133, 255)   # #ff6b85
EDGE_BOT  = (233, 69, 96, 255)     # #e94560
BODY_TOP  = (42, 13, 20, 255)      # #2a0d14
BODY_BOT  = (13, 6, 8, 255)        # #0d0608
PANE      = (255, 122, 144, 255)   # #ff7a90
SWEEP     = (255, 107, 133, 230)
WORD      = (255, 208, 216, 255)   # #ffd0d8


def _vgrad(size, top, bot):
    """Vertical gradient image."""
    w, h = size
    base = Image.new("RGBA", size, top)
    top_r, top_g, top_b, top_a = top
    bot_r, bot_g, bot_b, bot_a = bot
    for y in range(h):
        t = y / max(h - 1, 1)
        r = int(top_r + (bot_r - top_r) * t)
        g = int(top_g + (bot_g - top_g) * t)
        b = int(top_b + (bot_b - top_b) * t)
        a = int(top_a + (bot_a - top_a) * t)
        for x in range(w):
            base.putpixel((x, y), (r, g, b, a))
    return base


def _shield_path(s):
    """Return shield outline polygon points scaled to size s (square)."""
    def p(x, y):
        return (x / 220 * s, y / 220 * s)
    return [
        p(110, 12), p(196, 42), p(196, 112),
        p(170, 160), p(110, 208), p(50, 160), p(24, 112), p(24, 42),
    ]


def make_shield(size: int) -> Image.Image:
    SS = 4  # supersample for smooth edges
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Body mask
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).polygon(_shield_path(s), fill=255)

    # Gradient body clipped to shield
    body = _vgrad((s, s), BODY_TOP, BODY_BOT)
    img.paste(body, (0, 0), mask)

    # Edge stroke (gradient approximated by top colour)
    draw.line(_shield_path(s) + [_shield_path(s)[0]],
              fill=EDGE_BOT, width=int(6 * SS), joint="curve")

    # Inner bevel
    def p(x, y):
        return (x / 220 * s, y / 220 * s)
    bevel = [p(110, 26), p(184, 52), p(184, 110),
             p(150, 152), p(110, 192), p(70, 152), p(36, 110), p(36, 52)]
    draw.line(bevel + [bevel[0]], fill=(233, 69, 96, 90), width=max(1, int(1.5 * SS)))

    # Windows four-pane glyph (slightly tilted via offset rects)
    panes = [(84, 84, 104, 106), (110, 80, 136, 104),
             (84, 110, 104, 132), (110, 108, 136, 134)]
    for (x0, y0, x1, y1) in panes:
        draw.rounded_rectangle([p(x0, y0), p(x1, y1)],
                               radius=int(2 * SS), fill=PANE)

    # Scanner sweep line
    draw.line([p(60, 150), p(160, 150)], fill=SWEEP, width=int(3 * SS))
    draw.ellipse([p(156, 146), p(164, 154)], fill=SWEEP)

    # Wordmark
    try:
        font = ImageFont.truetype("segoeuib.ttf", int(22 * SS))
    except OSError:
        try:
            font = ImageFont.truetype("arialbd.ttf", int(22 * SS))
        except OSError:
            font = ImageFont.load_default()
    text = "WSTS"
    tb = draw.textbbox((0, 0), text, font=font)
    tw = tb[2] - tb[0]
    draw.text((s / 2 - tw / 2, 162 / 220 * s), text, font=font, fill=WORD)

    return img.resize((size, size), Image.LANCZOS)


def main():
    shield = make_shield(440)
    shield.save(OUT / "wsts_shield.png")
    print(f"Written: {OUT / 'wsts_shield.png'}")

    fav = make_shield(64)
    fav.save(OUT / "favicon.png")
    print(f"Written: {OUT / 'favicon.png'}")

    # Multi-size Windows icon
    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    make_shield(256).save(
        OUT / "wsts.ico",
        sizes=[(n, n) for n in ico_sizes],
    )
    print(f"Written: {OUT / 'wsts.ico'}")
    print("Done.")


if __name__ == "__main__":
    main()
