# rootgraph console: design system

> An operations desk on paper. Ink, hairlines, and one signal colour that means "a person needs to act".

rootgraph is used during incidents. The design serves that moment: status must be unmistakable at a glance, machine output must look like machine output, and nothing on screen may compete with the one thing that needs a human. It borrows its structure from Ramp's editorial finance desk (monochrome, hairlines, a single chartreuse signal) and its technical texture from Vercel's terminal-on-paper (monospace labels, `▲` before commands, `✓` on success). It is light, flat and quiet on purpose: no glow, no glass, no gradients.

## Principles

1. **One signal.** Chartreuse marks only what needs a person now: the primary action on a screen, an open incident, a fix awaiting approval, the active filter or tab. If it isn't waiting on a human, it isn't chartreuse.
2. **Ink and hairlines do the structure.** Depth comes from white surfaces on a warm canvas and 1 px borders, never from shadows.
3. **Machine text is mono.** IDs, timestamps, resource ids, commands, Cypher and column labels use the mono face. Human sentences use the sans.
4. **Status is a small, separate vocabulary.** Red, amber and green exist only to report state (broken, degraded, verified) on badges, timeline dots and graph edges. They are never decoration and never buttons.
5. **Say it in words first.** Every number or colour has a sentence next to it ("payments can no longer reach orders-db").

## Tokens

### Surfaces and ink

| Token | Value | Use |
|---|---|---|
| `--canvas` | `#f4f2f0` | App background (warm bone) |
| `--paper` | `#ffffff` | Cards, tables, sidebar, inputs, modals |
| `--wash` | `#f4f2f0` | Hover rows, secondary fills, list items inside cards |
| `--ink` | `#0c0a08` | Primary text, headings, outlined-button borders, graph root-cause node |
| `--obsidian` | `#1a1919` | Dark bands: the live metric strip, the root-cause plate |
| `--ash` | `#6d6c6b` | Secondary text, captions, column labels |
| `--smoke` | `#a3a2a0` | Placeholders, disabled, tertiary metadata |
| `--hair` | `#e5e7eb` | Every border and divider |
| `--hair-strong` | `#d3d3d3` | Input borders, focused panel edges |

### Signal

| Token | Value | Use |
|---|---|---|
| `--signal` | `#e4f222` | Primary button fill (ink text), open/proposed badges, nav count, active tab underline, active chip, "now" step, live values on the dark strip |
| `--signal-ink` | `#0c0a08` | Text on signal |

### Status extension (documented deviation from the monochrome base)

| State | Text | Fill | Where |
|---|---|---|---|
| Broken / failed / unhealthy | `#b42318` | `#fdecea` | badges, the broken path and culprit rule in the graph, "the cause" tag, timeline dot |
| Degraded / warning / alerting | `#8a5a00` | `#fbf1d6` | badges, alerting node ring, alerts timeline dot |
| Verified / healthy / resolved | `#1e6b3a` | `#e3f2e8` | badges, completed steps, `✓` results |
| Neutral | `#0c0a08` | `#f4f2f0` | everything else |

### Type

| Role | Face | Size / line height | Weight |
|---|---|---|---|
| Page title | IBM Plex Sans | 22 / 1.2, tracking -0.01em | 500 |
| Root cause (on the dark plate) | IBM Plex Sans | 30 / 1.15 | 500 |
| KPI value | IBM Plex Sans | 28 / 1.1, tabular figures | 400 |
| Section heading | IBM Plex Sans | 15 / 1.3 | 500 |
| Body, table cells | IBM Plex Sans | 13–14 / 1.5 | 400 |
| Labels, column heads, eyebrows | Geist Mono | 10.5–11, uppercase, tracking 0.06em | 500 |
| IDs, timestamps, rids, commands, Cypher | Geist Mono | 12 / 1.5 | 400 |

Hierarchy comes from size and colour, not weight: 400 for text, 500 for headings and emphasis, never above 500.

### Shape and space

- Radius: 6 px buttons and badges, 8 px inputs and list items, 12 px wash panels and the dark plate, 14 px cards. Never pills, never 0 on interactive elements.
- 4 px grid. Card padding 18–20 px, element gap 8–12 px, panel gap 16 px. Full-width console, content max 1360 px.
- Table rows 36–40 px, hairline dividers, no zebra stripes, hover in `--wash`.
- No `box-shadow` on surfaces. Modals and menus get a 1 px `--hair-strong` border and a single soft shadow only because they float.

### Motion

0.2–0.3 s ease-out on colour, background and border only. The one exception is the slow pulse on an open incident's dot. Respect `prefers-reduced-motion`.

## Components

- **Primary button:** `--signal` fill, ink text, 6 px radius, 8 × 14 px. At most one per view (Sign in, Approve and execute, Simulate incident).
- **Secondary button:** transparent, 1 px ink border, ink text. **Ghost:** no border, `--ash` text, `--wash` on hover.
- **Badges:** 6 px radius, 2 × 8 px, 11.5 px sans 500, colours from the status table; open/proposed use `--signal` with a small ink dot.
- **Sidebar:** white, hairline right edge, ink wordmark. Active item: ink text on `--wash` with a 2 px signal bar on the left. Environment switcher at the top: a bordered block with a status dot (green for Production, amber for Staging).
- **Live metric strip (Overview):** one `--obsidian` band, mono uppercase labels in `#a3a2a0`, values in white; a value that needs a person turns `--signal`.
- **Root-cause plate:** `--obsidian` band, 12 px radius, mono eyebrow, white name, mono rid, one plain-language sentence. The only dark element on an incident page, so the eye lands on it first.
- **Tables:** white, mono uppercase column labels in `--ash`, hairline rows, tabular figures right-aligned, IDs in mono ink.
- **Command blocks:** `--wash` fill, hairline border, mono, prefixed with `▲`. Successful results are prefixed with `✓` in the verified green.
- **Graph:** white canvas, hairline border. Nodes are white with a 1 px ink border and ink labels; firewalls are rounded squares, databases barrels. The root cause is a filled ink node; alerting nodes get an amber ring; the broken path and the blamed rule are the only red lines; the selection gets a signal halo. Edges are grey hairlines, dashed for runs-on/protects, dotted for allowed-by-rule.
- **Timeline:** mono time, small dot, sentence. Context in `--smoke`, the cause in ink with a red "the cause" tag, alerts in amber, the decision in ink.

## Don't

- No gradients, glows, glass, blur-as-decoration, spotlights or background grids.
- No second accent colour, no chartreuse for decoration, no status colours on buttons.
- No weights above 500, no display serif, no centred body text.
- No marketing devices inside the console: hero headlines, stat tiles without context, feature grids.
