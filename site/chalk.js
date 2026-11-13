// SPDX-License-Identifier: AGPL-3.0-only
//
// Draws the site's pictures as a hand would with chalk on a board, and
// writes them to templates/chalk.html: every line wobbles a little and is
// gone over twice, as rough.js does. The seeds are fixed, so the drawings
// come out the same each time; run `npm run chalk` after changing them.
"use strict";
const fs = require("fs");
const path = require("path");
const rough = require("roughjs");

const g = rough.generator();
let seed = 7;
const opts = (o = {}) => Object.assign({ roughness: 0.75, bowing: 0.7, strokeWidth: 1, seed: seed++, preserveVertices: true }, o);
const round = (d) => d.replace(/-?\d+\.\d+/g, (n) => String(Math.round(parseFloat(n) * 10) / 10));
const paths = (d) => g.toPaths(d).map((p) => round(p.d)).join(" ");
const shapes = {
  rect: (x, y, w, h, r) => g.path(`M${x + r} ${y}H${x + w - r}Q${x + w} ${y} ${x + w} ${y + r}V${y + h - r}Q${x + w} ${y + h} ${x + w - r} ${y + h}H${x + r}Q${x} ${y + h} ${x} ${y + h - r}V${y + r}Q${x} ${y} ${x + r} ${y}Z`, opts()),
  line: (x1, y1, x2, y2) => g.line(x1, y1, x2, y2, opts({ roughness: 0.7 })),
  path: (d) => g.path(d, opts()),
  circle: (cx, cy, d) => g.circle(cx, cy, d, opts({ roughness: 0.6 })),
};
const draw = (list) => list.map(([kind, ...args]) => paths(shapes[kind](...args))).join(" ");

// A device centred at (x, y), at scale s.
function device(kind, x, y, s = 1) {
  const R = (a, b, w, h, r) => ["rect", x + a * s, y + b * s, w * s, h * s, r * s];
  const L = (a, b, c, d) => ["line", x + a * s, y + b * s, x + c * s, y + d * s];
  const C = (a, b, d) => ["circle", x + a * s, y + b * s, d * s];
  const P = (d) => ["path", d.replace(/(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)/g, (m, a, b) => `${x + a * s} ${y + b * s}`)];
  switch (kind) {
    case "phone": return [R(-19, -33, 38, 66, 8), L(-9, -20, 9, -20), L(-9, -12, 1, -12), L(-6, 25, 6, 25)];
    case "tablet": return [R(-27, -34, 54, 68, 7), L(-16, -22, 16, -22), L(-16, -14, 2, -14), L(-4, 26, 4, 26)];
    case "laptop": return [R(-30, -27, 60, 40, 4), L(-20, -16, 10, -16), L(-20, -7, 0, -7), P("M-40,19 L40,19 L34,27 L-34,27 Z")];
    // A desktop: a monitor on a stand, and the system unit beside it.
    case "desktop": return [
      R(-42, -28, 58, 40, 4), L(-33, -17, -3, -17), L(-33, -8, -15, -8), L(-13, 12, -13, 20), L(-26, 21, 0, 21),
      R(24, -26, 19, 47, 3), C(33.5, -15, 6), L(28, -4, 39, -4), L(28, 2, 39, 2),
    ];
    case "mac": return [R(-34, -31, 68, 48, 5), L(-34, 6, 34, 6), L(-24, -20, 6, -20), L(-24, -12, -4, -12), L(-5, 17, -8, 28), L(5, 17, 8, 28), L(-16, 29, 16, 29)];
    case "tv": return [R(-40, -27, 80, 46, 4), L(-28, -15, 6, -15), L(-28, -7, -6, -7), L(-26, 19, -31, 28), L(26, 19, 31, 28)];
  }
}
// The box each device fills at scale 1: left, top, right, bottom.
const box = {
  phone: [-19, -33, 19, 33], tablet: [-27, -34, 27, 34], laptop: [-40, -27, 40, 27],
  desktop: [-42, -28, 43, 21], mac: [-34, -31, 34, 29], tv: [-40, -27, 40, 28],
};

// The hero, in a box of 640 by 330: a laptop and a phone joined through
// the key by one straight yellow line; the key's traces branch above and
// below it and never cross it.
const hero = {
  white: draw([
    ["rect", 28, 66, 134, 88, 7], ["path", "M12 172 L178 172 L168 185 L22 185 Z"], ["line", 48, 90, 118, 90], ["line", 48, 110, 94, 110], ["line", 48, 130, 106, 130],
    ["rect", 540, 40, 72, 140, 15], ["line", 556, 70, 596, 70], ["line", 556, 88, 580, 88], ["line", 566, 164, 586, 164],
    ["rect", 423, 206, 64, 50, 9], ["path", "M435 206 V193 A20 20 0 0 1 475 193 V206"], ["circle", 455, 227, 12], ["line", 455, 233, 455, 243],
    ["path", "M272 84 H238 L222 68"], ["circle", 216, 62, 16], ["path", "M272 136 H238 L222 152"], ["circle", 216, 158, 16],
    ["path", "M368 84 H402 L418 68"], ["circle", 424, 62, 16], ["path", "M368 136 H402 L418 152"], ["circle", 424, 158, 16],
  ]),
  yellow: draw([
    ["circle", 320, 110, 100], ["path", "M286 136 A40 40 0 0 1 284 86"], ["circle", 320, 88, 24],
    ["path", "M308 158 V262 L320 284 L332 262 V248 L325 241 L332 234 V225 L325 218 L332 211 V202 L325 195 L332 188 V158"],
  ]),
  links: draw([["line", 162, 110, 270, 110], ["line", 370, 110, 540, 110]]),
};

// A group, in a box of 420 by 310: the hub in the middle, four devices
// around it, and the links between them. Each link points from the hub's
// centre to the device's and stops short of both and of their labels,
// which the page writes under each device, so no line runs into either.
function group(hub, scale, others) {
  const at = [[66, 60], [354, 58], [66, 246], [354, 246]];
  const gap = 8, label = 28;
  // Where the segment from (x1, y1) to (x2, y2) leaves the box b, grown by
  // gap, around (x1, y1): the fraction of the way along it.
  const leave = (x1, y1, x2, y2, b, s) => {
    let [l, t, r, u] = b.map((v) => v * s);
    u += label;
    const dx = x2 - x1, dy = y2 - y1;
    const fx = dx > 0 ? (r + gap) / dx : dx < 0 ? (l - gap) / dx : Infinity;
    const fy = dy > 0 ? (u + gap) / dy : dy < 0 ? (t - gap) / dy : Infinity;
    return Math.min(fx, fy);
  };
  // The room each link has; then every link gets the shortest one's
  // length, in the middle of its room, so the four look alike.
  const room = others.map((kind, i) => {
    const [x, y] = at[i];
    const a = leave(210, 150, x, y, box[hub], scale);
    const b = 1 - leave(x, y, 210, 150, box[kind], 1);
    return { x, y, a, b, len: Math.hypot(x - 210, y - 150) };
  });
  const len = Math.min(...room.map((r) => (r.b - r.a) * r.len));
  const links = room.map(({ x, y, a, b, len: d }) => {
    const m = (a + b) / 2, h = len / d / 2;
    const p = (f) => [210 + (x - 210) * f, 150 + (y - 150) * f];
    return ["line", ...p(m - h), ...p(m + h)];
  });
  return {
    yellow: draw(device(hub, 210, 150, scale)),
    white: draw(others.flatMap((kind, i) => device(kind, at[i][0], at[i][1]))),
    links: "",
    segs: links.map(([, x1, y1, x2, y2]) => [x1, y1, x2, y2]),
    // Each link on its own, so the stylesheet can go over them in turn.
    parts: links.map((l, i) => ["y link r" + i, draw([l])]),
  };
}
// The three steps of setting up, each in a box of 200 by 150. White and
// yellow lines never cross. 1: the phone downloads the app, its progress
// bar nearly full. 2: a desktop computer runs one command, and a check
// says it is installed. 3: the computer shows a QR code, and the phone's
// camera frames it.
seed = 61;
// A QR code at (x, y), of size n: three finder squares, a dot in each
// when there is room for it, and a few dots.
const qr = (x, y, n, dots = true) => {
  const f = n * 0.36, d = n * 0.13, inner = n >= 40;
  const finder = (a, b) => [["rect", a, b, f, f, 2], ...(inner ? [["rect", a + f * 0.32, b + f * 0.32, f * 0.36, f * 0.36, 1]] : [])];
  return [
    ...finder(x, y), ...finder(x + n - f, y), ...finder(x, y + n - f),
    ...(dots ? [["rect", x + n * 0.6, y + n * 0.6, d, d, 1], ["rect", x + n - d, y + n - d, d, d, 1], ["rect", x + n * 0.6, y + n - d, d, d, 1], ["rect", x + n - d, y + n * 0.6, d, d, 1]] : []),
  ];
};
const step1 = {
  white: draw([
    ["rect", 68, 12, 64, 124, 11], ["line", 92, 25, 108, 25], ["line", 93, 124, 107, 124],
    ["rect", 80, 98, 40, 10, 5],
  ]),
  yellow: draw([["path", "M84 70 V82 H116 V70"]]),
  links: "",
  parts: [["g arrow", [["y", draw([["line", 100, 38, 100, 72], ["path", "M88 61 L100 73 L112 61"]])]]], ["y bar", draw([["line", 85, 103, 108, 103]])]],
};
const step2 = {
  white: draw([
    ["rect", 16, 22, 112, 78, 6], ["line", 72, 100, 72, 114], ["line", 50, 118, 94, 118],
    ["rect", 144, 26, 40, 92, 5], ["circle", 164, 44, 10], ["line", 154, 64, 174, 64], ["line", 154, 74, 174, 74],
  ]),
  yellow: draw([["path", "M30 40 L39 46 L30 52"]]),
  links: "",
  parts: [["w cmd", draw([["line", 52, 46, 104, 46]])], ["w cursor", draw([["line", 110, 52, 120, 52]])], ["y check", draw([["path", "M32 74 L40 82 L54 66"]])]],
};
const step3 = {
  white: draw([
    ["rect", 6, 24, 92, 72, 6], ["line", 52, 96, 52, 110], ["line", 34, 114, 70, 114],
    ["rect", 106, 30, 17, 78, 3], ["circle", 114.5, 41, 6],
    ...qr(28, 36, 48),
    ["rect", 140, 28, 52, 96, 10], ["line", 160, 116, 172, 116],
    ...qr(155, 59, 22, false),
  ]),
  yellow: "",
  links: "",
  parts: [
    ["g brackets", [["y", draw([["path", "M148 62 V52 H158"], ["path", "M174 52 H184 V62"], ["path", "M148 78 V88 H158"], ["path", "M184 78 V88 H174"]])]]],
    ["y check", draw([["path", "M159 100 L164 105 L174 95"]])],
  ],
};
seed = 38;
const computer = group("desktop", 1.15, ["phone", "laptop", "phone", "mac"]);
const phones = group("phone", 1.35, ["desktop", "tv", "tablet", "phone"]);

// pathLength lets the stylesheet draw each line in, as a hand would.
const line = (cls, d) => (d ? `<path class="${cls}" pathLength="1" d="${d}"/>` : "");
// The parts the stylesheet moves come on their own: a path, or a group
// ("g name") of them.
const part = ([cls, d]) => (cls.startsWith("g ") ? `<g class="${cls.slice(2)}">${d.map(part).join("")}</g>` : line(cls, d));
// The still lines and the moving parts are groups of their own, each with
// the chalk's filter: a moving part then makes the browser filter again
// only its own small box, not the whole board, on every frame.
const still = (d) => line("y link", d.links) + line("w", d.white) + line("y", d.yellow);
const lines = (d) => (d.parts ? `<g>${still(d)}</g><g>${d.parts.map(part).join("")}</g>` : `<g>${still(d)}</g>`);
const out = `<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Written by chalk.js: the lines of the chalk drawings, without their
     labels, which the pages add in their own language. -->
{{define "chalk-hero"}}${lines(hero)}{{end}}
{{define "chalk-computer"}}${lines(computer)}{{end}}
{{define "chalk-phones"}}${lines(phones)}{{end}}
{{define "chalk-step1"}}${lines(step1)}{{end}}
{{define "chalk-step2"}}${lines(step2)}{{end}}
{{define "chalk-step3"}}${lines(step3)}{{end}}
`;
if (require.main === module) fs.writeFileSync(path.join(__dirname, "templates", "chalk.html"), out);
module.exports = { draw, device, group, qr, hero, step1, step2, step3, computer, phones, setSeed: (n) => { seed = n; } };
