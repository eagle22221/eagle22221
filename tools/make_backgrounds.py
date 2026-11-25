#!/usr/bin/env python3
"""Generate vex's background tiles: ribbons (periodic in x) and sparkles
(periodic in x and y), one set per theme.

    python3 tools/make_backgrounds.py vex/web

Ribbon tiles: each ribbon is one closed path, a band between two curves that
repeat every TW units, drawn from -TW/4 to 1.25*TW so that the blur of the
glow just outside the tile matches the tile on the other side; the SVG's
viewBox (0..TW) clips it. The same path is filled (the translucent body, plus
a blurred copy for the haze) and stroked (the bright edges, plus a blurred
copy for their glow). Since the band is closed beyond both ends of the tile,
its stroke inside the tile is just the two edges.
"""
import math
import random
import sys
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")

STEP_DIV = 160  # points per tile width


def f(v):
    s = f"{v:.1f}"
    return "0" if s in ("0.0", "-0.0") else (s[:-2] if s.endswith(".0") else s)


def band_path(TW, r):
    """Points of the band: top edge left to right, bottom edge right to left."""
    n0, n1 = -STEP_DIV // 4, STEP_DIV + STEP_DIV // 4
    top, bot = [], []
    for i in range(n0, n1 + 1):
        u = i / STEP_DIV
        x = u * TW
        yc = r["c"]
        for (a, k, p) in r["wave"]:
            yc += a * math.sin(2 * math.pi * (k * u + p))
        hw = r["w"] / 2 * (r["m"] + (1 - r["m"]) * math.cos(2 * math.pi * (r["kt"] * u + r["pt"])))
        top.append((x, yc - hw))
        bot.append((x, yc + hw))
    pts = top + bot[::-1]
    d = "M" + f(pts[0][0]) + " " + f(pts[0][1]) + "".join(
        "L" + f(x) + " " + f(y) for x, y in pts[1:]) + "Z"
    return d


def ribbon_svg(TW, TH, ribbons, theme, label):
    if theme == "dark":
        body = [("0", "#B9A4FF", ".55"), (".5", "#7C5CFF", ".30"), ("1", "#B9A4FF", ".55")]
        haze = "#8A6BFF"
        edge = [("0", "#E4DBFF", "1"), (".5", "#B7A2FF", ".55"), ("1", "#E4DBFF", "1")]
    else:
        body = [("0", "#F2FDFF", ".62"), (".5", "#9FE6FF", ".34"), ("1", "#F2FDFF", ".62")]
        haze = "#DDF8FF"
        edge = [("0", "#FFFFFF", "1"), (".5", "#D8F6FF", ".6"), ("1", "#FFFFFF", "1")]
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {TW} {TH}" width="{TW}" height="{TH}">',
           f"<!-- vex background: {label}. Ribbons of light that repeat every {TW} units",
           "     across, so the tile joins seamlessly to the next copy. -->",
           "<defs>"]
    for gi, (gid, stops) in enumerate((("b", body), ("e", edge))):
        out.append(f'<linearGradient id="{gid}" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="{TW}" y2="0" spreadMethod="repeat">'
                   + "".join(f'<stop offset="{o}" stop-color="{c}" stop-opacity="{a}"/>' for o, c, a in stops)
                   + "</linearGradient>")
    x0, w = -TW // 3, TW + 2 * (TW // 3)
    out.append(f'<filter id="haze" filterUnits="userSpaceOnUse" x="{x0}" y="-{TH}" width="{w}" height="{3 * TH}"><feGaussianBlur stdDeviation="9"/></filter>')
    out.append(f'<filter id="glow" filterUnits="userSpaceOnUse" x="{x0}" y="-{TH}" width="{w}" height="{3 * TH}"><feGaussianBlur stdDeviation="2.4"/></filter>')
    for i, r in enumerate(ribbons):
        out.append(f'<path id="r{i}" d="{band_path(TW, r)}"/>')
    out.append("</defs>")
    for i, r in enumerate(ribbons):
        o = r["o"]
        out.append(f'<use href="#r{i}" fill="{haze}" opacity="{o * r.get("haze", .5):.2f}" filter="url(#haze)"/>')
        out.append(f'<use href="#r{i}" fill="url(#b)" opacity="{o * r.get("body", .6):.2f}"/>')
        out.append(f'<use href="#r{i}" fill="none" stroke="url(#e)" stroke-width="3.6" opacity="{o * .55:.2f}" filter="url(#glow)"/>')
        out.append(f'<use href="#r{i}" fill="none" stroke="url(#e)" stroke-width="1.1" opacity="{o * .95:.2f}"/>')
    out.append("</svg>")
    return "\n".join(out) + "\n"


def sparkle_svg(TW, TH, n, big_share, seed, theme, label, size=1.0):
    rnd = random.Random(seed)
    halo = "#C9BBFF" if theme == "dark" else "#FFFFFF"
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {TW} {TH}" width="{TW}" height="{TH}">',
           f"<!-- vex background: {label}. Points of light in a tile that repeats",
           "     across and down: anything near an edge is drawn again on the other side. -->",
           "<defs>",
           f'<radialGradient id="h"><stop offset="0" stop-color="{halo}" stop-opacity=".6"/><stop offset=".35" stop-color="{halo}" stop-opacity=".18"/><stop offset="1" stop-color="{halo}" stop-opacity="0"/></radialGradient>',
           f'<radialGradient id="o"><stop offset="0" stop-color="#FFFFFF" stop-opacity=".7"/><stop offset=".3" stop-color="#FFFFFF" stop-opacity=".4"/><stop offset=".6" stop-color="{halo}" stop-opacity=".18"/><stop offset="1" stop-color="{halo}" stop-opacity="0"/></radialGradient>',
           "</defs>"]
    for _ in range(n):
        x, y = rnd.random() * TW, rnd.random() * TH
        big = rnd.random() < big_share
        if big:
            r = (1.8 + rnd.random() * 1.6) * size
            a = .15 + rnd.random() * .15
            items = [("o", r * 2.2, a)]
        else:
            r = (.5 + rnd.random() * .75) * size
            a = .55 + rnd.random() * .4
            items = [("h", r * 3.4, a * .7), ("c", r, a)]
        ext = max(rr for _, rr, _ in items)
        for dx in (-TW, 0, TW):
            for dy in (-TH, 0, TH):
                cx, cy = x + dx, y + dy
                if cx + ext < 0 or cx - ext > TW or cy + ext < 0 or cy - ext > TH:
                    continue
                for kind, rr, aa in items:
                    fill = "#FFFFFF" if kind == "c" else f"url(#{kind})"
                    out.append(f'<circle cx="{f(cx)}" cy="{f(cy)}" r="{rr:.2f}" fill="{fill}" opacity="{aa:.2f}"/>')
    out.append("</svg>")
    return "\n".join(out) + "\n"


# --- the ribbon sets ------------------------------------------------------
# c: centre line (units from the top of the tile), wave: [(amplitude, cycles
# per tile, phase)], w: width, m: how much of the width stays at the narrowest
# point (below .5 the edges cross: the ribbon twists), kt/pt: its rhythm.
RIBBONS = {
    # the near layer: the broad ribbon and two finer ones
    "a": (1800, 360, [
        dict(c=180, wave=[(58, 1, .05), (12, 3, .4)], w=128, m=.3, kt=2, pt=.1, o=1.0, haze=.6, body=.62),
        dict(c=196, wave=[(50, 1, .22), (9, 2, .7)], w=34, m=.12, kt=3, pt=.6, o=.9, haze=.4, body=.5),
        dict(c=172, wave=[(46, 2, .62), (8, 3, .2)], w=56, m=.22, kt=2, pt=.8, o=.6, haze=.4, body=.48),
    ]),
    # the far layer, at a steeper angle: dimmer, slower
    "b": (2100, 360, [
        dict(c=180, wave=[(60, 1, .55), (10, 2, .1)], w=92, m=.35, kt=2, pt=.35, o=.8, haze=.5, body=.55),
        dict(c=170, wave=[(44, 2, .8)], w=22, m=.1, kt=1, pt=.9, o=.7, haze=.3, body=.45),
        dict(c=188, wave=[(40, 1, .25)], w=16, m=.05, kt=1, pt=.2, o=.55, haze=.25, body=.4),
    ]),
}
SPARKLES = {
    "a": (480, 480, 21, .06, 11, 1.0),
    "b": (840, 630, 14, .45, 23, 1.15),
}

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for theme in ("dark", "light"):
        for name, (TW, TH, ribbons) in RIBBONS.items():
            (OUT / f"ribbons-{theme}-{name}.svg").write_text(
                ribbon_svg(TW, TH, ribbons, theme, f"{theme} theme, ribbon layer {name}"))
        for name, (TW, TH, n, big, seed, size) in SPARKLES.items():
            (OUT / f"sparkles-{theme}-{name}.svg").write_text(
                sparkle_svg(TW, TH, n, big, seed, theme, f"{theme} theme, sparkle layer {name}", size))
    for p in sorted(OUT.glob("*.svg")):
        print(p.name, p.stat().st_size)
