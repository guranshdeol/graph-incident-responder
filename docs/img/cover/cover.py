"""Blog cover, 1600x840: many alerting nodes, every path converging on one cause. Console palette + type."""
import math, random, pathlib
from playwright.sync_api import sync_playwright
random.seed(7)
W, H = 1600, 840
cause = (1235, 600)
# a loose three-layer graph above the cause: alerts (top), shared infrastructure (middle)
alerts = [(880 + i * 72 + random.uniform(-18, 18), 150 + random.uniform(-45, 55)) for i in range(10)]
mids = [(960, 360), (1120, 330), (1300, 375), (1450, 340)]
links_am = [(a, mids[min(3, int(i / 2.6))]) for i, a in enumerate(alerts)]
noise = [(random.uniform(840, 1560), random.uniform(90, 790)) for _ in range(26)]
noise = [p for p in noise if math.dist(p, cause) > 110 and all(math.dist(p, m) > 70 for m in mids)]
def curve(p, q, cls):
    mx = (p[0] + q[0]) / 2
    return f'<path class="{cls}" d="M{p[0]:.0f},{p[1]:.0f} C{mx:.0f},{p[1] + 80:.0f} {mx:.0f},{q[1] - 80:.0f} {q[0]:.0f},{q[1]:.0f}"/>'
svg = []
for i, p in enumerate(noise):   # the rest of the estate, quiet
    q = noise[(i * 7 + 3) % len(noise)]
    if math.dist(p, q) < 260:
        svg.append(f'<line class="faint" x1="{p[0]:.0f}" y1="{p[1]:.0f}" x2="{q[0]:.0f}" y2="{q[1]:.0f}"/>')
for a, m in links_am:
    svg.append(curve(a, m, "edge"))
for m in mids:
    svg.append(curve(m, cause, "edge strong"))
svg.append(f'<circle cx="{cause[0]}" cy="{cause[1]}" r="58" class="halo"/>')
for p in noise:
    svg.append(f'<circle cx="{p[0]:.0f}" cy="{p[1]:.0f}" r="4.5" class="dot"/>')
for m in mids:
    svg.append(f'<rect x="{m[0]-13}" y="{m[1]-13}" width="26" height="26" rx="6" class="mid"/>')
for a in alerts:
    svg.append(f'<circle cx="{a[0]:.0f}" cy="{a[1]:.0f}" r="11" class="alert"/>')
svg.append(f'<circle cx="{cause[0]}" cy="{cause[1]}" r="30" class="cause"/>')
svg.append(f'<text x="{cause[0]}" y="{cause[1] + 92}" class="lbl">the cause</text>')
svg.append(f'<text x="{alerts[0][0] - 6:.0f}" y="62" class="lbl l">10 alerts</text>')
html = f"""<html><head>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=Geist+Mono:wght@500&display=swap" rel="stylesheet">
<style>
html,body{{margin:0;width:{W}px;height:{H}px;background:#f4f2f0;overflow:hidden}}
.wrap{{position:absolute;inset:0}}
.txt{{position:absolute;left:96px;top:0;bottom:0;width:720px;display:flex;flex-direction:column;justify-content:center}}
.eye{{font:500 20px 'Geist Mono';letter-spacing:.14em;text-transform:uppercase;color:#6d6c6b;margin-bottom:34px;display:flex;gap:14px;align-items:center}}
.eye i{{width:12px;height:12px;border-radius:50%;background:#e4f222;box-shadow:0 0 0 2px #0c0a08}}
h1{{font:600 104px/0.98 'IBM Plex Sans';letter-spacing:-0.035em;color:#0c0a08;margin:0}}
h1 span{{background:linear-gradient(transparent 62%,#e4f222 62%,#e4f222 92%,transparent 92%);padding:0 6px;margin:0 -6px}}
p{{font:400 30px/1.4 'IBM Plex Sans';color:#3d3b39;margin:34px 0 0;max-width:640px}}
.foot{{position:absolute;left:96px;bottom:64px;font:500 18px 'Geist Mono';letter-spacing:.08em;color:#6d6c6b;text-transform:uppercase}}
svg{{position:absolute;inset:0}}
.faint{{stroke:#d9d6d2;stroke-width:1.2}} .dot{{fill:#fff;stroke:#c9c5c0;stroke-width:1.5}}
.edge{{fill:none;stroke:#a3a2a0;stroke-width:1.6}} .strong{{stroke:#0c0a08;stroke-width:2.4}}
.alert{{fill:#fbf1d6;stroke:#c98a00;stroke-width:3}} .mid{{fill:#fff;stroke:#0c0a08;stroke-width:2}}
.cause{{fill:#0c0a08}} .halo{{fill:#e4f222}}
.lbl{{font:500 20px 'Geist Mono';fill:#0c0a08;text-anchor:middle;letter-spacing:.06em;text-transform:uppercase}} .l{{text-anchor:start;fill:#8a5a00}}
</style></head><body><div class="wrap">
<svg viewBox="0 0 {W} {H}">{''.join(svg)}</svg>
<div class="txt"><div class="eye"><i></i>rootgraph · on a FalkorDB graph</div>
<h1>Many alerts.<br><span>One cause.</span></h1>
<p>We broke a real AWS account by hand, and taught a graph to find who did it.</p></div>
<div class="foot">Graph Hacks · WeMakeDevs × FalkorDB</div>
</div></body></html>"""
out = pathlib.Path(__file__).parent
(out / "cover.html").write_text(html)
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/opt/rootgraph/video/chrome/chrome-headless-shell-linux64/chrome-headless-shell")
    pg = b.new_page(viewport={"width": W, "height": H}, device_scale_factor=1)
    pg.goto((out / "cover.html").as_uri(), wait_until="networkidle"); pg.evaluate("document.fonts.ready"); pg.wait_for_timeout(500)
    pg.screenshot(path=str(out.parent / "blog-cover.png")); b.close()
print("ok")
