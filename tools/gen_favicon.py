"""Generator favicon portalu — czysty stdlib (zlib+struct), bez Pillow.

Renderuje znak marki (heksagon-hub z gradientem cyan->violet->purple, jak logo
w sidebarze) na ciemnym zaokrąglonym kaflu, z miękkim anti-aliasingiem liczonym
analitycznie z pól odległości (SDF) — bez supersamplingu.

Uruchomienie (z katalogu repo): python tools/gen_favicon.py
Wyjście: backend/app/static/favicon-{512,256,180,32}.png
"""
import math
import os
import struct
import zlib

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "backend", "app", "static")
SIZES = [512, 256, 180, 32]

# Paleta (jak --grad w style.css)
C1 = (0x2E, 0xE6, 0xFF)  # cyan
C2 = (0x7B, 0x8C, 0xFF)  # violet
C3 = (0xC7, 0x7D, 0xFF)  # purple
BG_TOP = (0x11, 0x1A, 0x33)
BG_BOTTOM = (0x07, 0x0B, 0x15)

# Geometria w przestrzeni jednostkowej 0..1 (y w dół)
TILE_RADIUS = 0.22          # promień rogów kafla
HEX_R = 0.30                # promień heksagonu (pointy-top)
STROKE_HW = 0.026           # połowa grubości obrysu heksagonu
SPOKE_HW = 0.0135           # połowa grubości szprych
SPOKE_LEN = 0.62            # długość szprychy jako ułamek HEX_R
CENTER_R = 0.075            # promień węzła centralnego
DOT_R = 0.046               # promień kropek na końcach szprych
CX, CY = 0.5, 0.5


def lerp(a, b, t):
    return a + (b - a) * t


def grad_color(t):
    """Gradient wzdłuż przekątnej: 0 -> cyan, 0.55 -> violet, 1 -> purple."""
    t = max(0.0, min(1.0, t))
    if t < 0.55:
        u = t / 0.55
        return tuple(lerp(C1[i], C2[i], u) for i in range(3))
    u = (t - 0.55) / 0.45
    return tuple(lerp(C2[i], C3[i], u) for i in range(3))


def seg_dist(px, py, ax, ay, bx, by):
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    seg_len2 = vx * vx + vy * vy
    t = 0.0 if seg_len2 == 0 else max(0.0, min(1.0, (wx * vx + wy * vy) / seg_len2))
    dx, dy = px - (ax + vx * t), py - (ay + vy * t)
    return math.hypot(dx, dy)


def build_geometry():
    # Wierzchołki heksagonu pointy-top: kąty 90..390 co 60 stopni (y ekranowe w dół)
    verts = []
    for k in range(6):
        a = math.radians(90 + 60 * k)
        verts.append((CX + HEX_R * math.cos(a), CY - HEX_R * math.sin(a)))
    edges = [(verts[i], verts[(i + 1) % 6]) for i in range(6)]

    # Szprychy do trzech górnych wierzchołków (jak w logo): 90, 30, 150 stopni
    spokes, dots = [], []
    dot_colors = [C1, C2, C3]
    for idx, ang in enumerate((90, 30, 150)):
        a = math.radians(ang)
        ex = CX + HEX_R * SPOKE_LEN * math.cos(a)
        ey = CY - HEX_R * SPOKE_LEN * math.sin(a)
        spokes.append(((CX, CY), (ex, ey)))
        dots.append(((ex, ey), dot_colors[idx]))
    return edges, spokes, dots


EDGES, SPOKES, DOTS = build_geometry()


def render(size):
    px = 1.0 / size  # szerokość 1 piksela w przestrzeni jednostkowej (krawędź AA)
    half = 0.5
    inner = half - TILE_RADIUS
    rows = []

    for j in range(size):
        y = (j + 0.5) * px
        row = bytearray()
        for i in range(size):
            x = (i + 0.5) * px

            # --- kafel: SDF zaokrąglonego kwadratu ---
            qx = abs(x - 0.5) - inner
            qy = abs(y - 0.5) - inner
            tile_sdf = math.hypot(max(qx, 0.0), max(qy, 0.0)) - TILE_RADIUS
            alpha = max(0.0, min(1.0, 0.5 - tile_sdf / px))
            if alpha == 0.0:
                row += b"\x00\x00\x00\x00"
                continue

            # --- tło: pionowy gradient + delikatne poświaty w rogach ---
            r = lerp(BG_TOP[0], BG_BOTTOM[0], y)
            g = lerp(BG_TOP[1], BG_BOTTOM[1], y)
            b = lerp(BG_TOP[2], BG_BOTTOM[2], y)
            glow_c = math.exp(-(((x - 0.22) ** 2 + (y - 0.18) ** 2) / 0.10)) * 0.10
            glow_p = math.exp(-(((x - 0.82) ** 2 + (y - 0.85) ** 2) / 0.12)) * 0.08
            r += C1[0] * glow_c + C3[0] * glow_p
            g += C1[1] * glow_c + C3[1] * glow_p
            b += C1[2] * glow_c + C3[2] * glow_p

            t = (x + y) / 2.0
            gc = grad_color(t)

            # --- halo za heksagonem ---
            d_hex = min(seg_dist(x, y, a[0], a[1], c[0], c[1]) for a, c in EDGES)
            halo = max(0.0, 1.0 - max(d_hex - STROKE_HW, 0.0) / 0.09)
            halo = halo * halo * 0.22
            r = lerp(r, gc[0], halo)
            g = lerp(g, gc[1], halo)
            b = lerp(b, gc[2], halo)

            # --- szprychy (przygaszone) ---
            d_spoke = min(seg_dist(x, y, a[0], a[1], c[0], c[1]) for a, c in SPOKES)
            cov = max(0.0, min(1.0, 0.5 - (d_spoke - SPOKE_HW) / px)) * 0.75
            if cov > 0.0:
                r = lerp(r, gc[0], cov)
                g = lerp(g, gc[1], cov)
                b = lerp(b, gc[2], cov)

            # --- obrys heksagonu ---
            cov = max(0.0, min(1.0, 0.5 - (d_hex - STROKE_HW) / px))
            if cov > 0.0:
                r = lerp(r, gc[0], cov)
                g = lerp(g, gc[1], cov)
                b = lerp(b, gc[2], cov)

            # --- węzeł centralny ---
            d = math.hypot(x - CX, y - CY) - CENTER_R
            cov = max(0.0, min(1.0, 0.5 - d / px))
            if cov > 0.0:
                r = lerp(r, gc[0], cov)
                g = lerp(g, gc[1], cov)
                b = lerp(b, gc[2], cov)

            # --- kropki-węzły na końcach szprych (stałe kolory) ---
            for (dx_, dy_), col in DOTS:
                d = math.hypot(x - dx_, y - dy_) - DOT_R
                cov = max(0.0, min(1.0, 0.5 - d / px))
                if cov > 0.0:
                    r = lerp(r, col[0], cov)
                    g = lerp(g, col[1], cov)
                    b = lerp(b, col[2], cov)

            row += bytes((
                max(0, min(255, round(r))),
                max(0, min(255, round(g))),
                max(0, min(255, round(b))),
                round(alpha * 255),
            ))
        rows.append(bytes(row))
    return rows


def write_png(path, size, rows):
    def chunk(tag, data):
        payload = tag + data
        return struct.pack(">I", len(data)) + payload + struct.pack(">I", zlib.crc32(payload))

    raw = b"".join(b"\x00" + row for row in rows)  # filtr 0 per scanline
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # RGBA8
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as f:
        f.write(png)


if __name__ == "__main__":
    out = os.path.abspath(OUT_DIR)
    for size in SIZES:
        rows = render(size)
        path = os.path.join(out, f"favicon-{size}.png")
        write_png(path, size, rows)
        print(f"OK {path} ({os.path.getsize(path)} B)")
