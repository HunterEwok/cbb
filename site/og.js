// SPDX-License-Identifier: AGPL-3.0-only
//
// Draws the picture a link to the site shows in chats and social networks,
// one for each language: static/og/<language>.jpg, 1200 by 630, the title
// of the home page beside its figure 1. Run `npm run og` after changing
// the title or the drawing; it needs Playwright's Chromium. The fonts are
// the site's own, and for Chinese Noto Sans SC installed or named in
// OG_FONTS, a stylesheet of @font-face rules.
"use strict";
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const dir = __dirname;
const read = (f) => fs.readFileSync(path.join(dir, f), "utf8");
const hero = read("templates/chalk.html").match(/{{define "chalk-hero"}}([\s\S]*?){{end}}/)[1];
const extra = process.env.OG_FONTS ? fs.readFileSync(process.env.OG_FONTS, "utf8") : "";
const fileURL = (f) => "file://" + path.join(dir, f);
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

const langs = [{ code: "en", texts: {} }].concat(
  fs.readdirSync(path.join(dir, "l10n")).filter((f) => f.endsWith(".json")).sort()
    .map((f) => ({ code: f.slice(0, -5), texts: JSON.parse(read("l10n/" + f)) })));

function page(lang) {
  const t = (s) => esc(lang.texts[s] || s);
  const rtl = lang.texts["@dir"] === "rtl";
  const word = (x, y, s, accent) => `<text x="${x}" y="${y}" text-anchor="middle"${accent ? ' class="y"' : ""}>${t(s)}</text>`;
  const font = (family, file, range) => `@font-face { font-family: "${family}"; font-weight: 400 600; src: url(${fileURL("static/fonts/" + file)});${range ? " unicode-range: " + range + ";" : ""} }`;
  return `<!doctype html><html lang="${lang.texts["@lang"] || lang.code}" dir="${rtl ? "rtl" : "ltr"}"><meta charset="utf-8"><style>
${extra}
${font("IBM Plex Sans", "ibm-plex-sans-latin.woff2", "U+0000-00FF, U+2000-206F")}
${font("IBM Plex Sans", "ibm-plex-sans-latin-ext.woff2", "U+0100-02FF")}
${font("IBM Plex Sans", "ibm-plex-sans-cyrillic.woff2", "U+0400-045F")}
${font("IBM Plex Sans Arabic", "ibm-plex-sans-arabic-600-arabic.woff2")}
${font("IBM Plex Sans Hebrew", "ibm-plex-sans-hebrew-600-hebrew.woff2")}
${font("IBM Plex Sans Devanagari", "ibm-plex-sans-devanagari-600-devanagari.woff2")}
@font-face { font-family: Plex Mono; src: url(${fileURL("static/fonts/ibm-plex-mono-500-latin.woff2")}); }
@font-face { font-family: Plex Mono; src: url(${fileURL("static/fonts/ibm-plex-mono-500-cyrillic.woff2")}); unicode-range: U+0400-045F; }
body { margin: 0; width: 1200px; height: 630px; overflow: hidden; display: flex; align-items: center; gap: 48px; padding: 0 64px; box-sizing: border-box;
  font-family: "IBM Plex Sans", "IBM Plex Sans Arabic", "IBM Plex Sans Hebrew", "IBM Plex Sans Devanagari", "Noto Sans SC", sans-serif;
  color: #E6F0FF; background-color: #0B2545;
  background-image: linear-gradient(rgba(127,209,255,.13) 1px, transparent 1px), linear-gradient(90deg, rgba(127,209,255,.13) 1px, transparent 1px), linear-gradient(rgba(127,209,255,.08) 1px, transparent 1px), linear-gradient(90deg, rgba(127,209,255,.08) 1px, transparent 1px);
  background-size: 160px 160px, 160px 160px, 32px 32px, 32px 32px; background-position: -1px -1px; }
.text { flex: 1; min-width: 0; }
.brand { display: flex; align-items: center; gap: 16px; font-size: 28px; font-weight: 600; }
.brand img { width: 64px; height: 64px; }
h1 { font-size: 62px; font-weight: 600; line-height: 1.05; letter-spacing: ${rtl ? "0" : "-.02em"}; margin: 36px 0 30px; }
h1 span { color: #7FD1FF; }
p { font: 500 15px/1.4 "Plex Mono", monospace; letter-spacing: .1em; color: #9DB8DA; margin: 0; white-space: nowrap; }
.frame { position: relative; width: 480px; flex: none; border: 1px solid rgba(127,209,255,.42); border-radius: 3px; background: #0D2A4F; }
.frame i { position: absolute; width: 14px; height: 14px; border: 0 solid #7FD1FF; }
.frame .a { top: -1px; left: -1px; border-top-width: 2px; border-left-width: 2px; } .frame .b { top: -1px; right: -1px; border-top-width: 2px; border-right-width: 2px; }
.frame .c { bottom: -1px; left: -1px; border-bottom-width: 2px; border-left-width: 2px; } .frame .d { bottom: -1px; right: -1px; border-bottom-width: 2px; border-right-width: 2px; }
.surface { padding: 26px 8px 6px; background-image: linear-gradient(rgba(127,209,255,.08) 1px, transparent 1px), linear-gradient(90deg, rgba(127,209,255,.08) 1px, transparent 1px); background-size: 20px 20px; }
svg.board { display: block; width: 100%; height: auto; }
.chalk path { fill: none; stroke-width: 2.2; stroke-linecap: square; stroke-linejoin: miter; }
.w { stroke: #E6F0FF; } .y { stroke: #7FD1FF; }
.words text { font: 500 17px "Plex Mono", "IBM Plex Sans Arabic", "IBM Plex Sans Hebrew", "IBM Plex Sans Devanagari", "Noto Sans SC", monospace; letter-spacing: ${rtl || /^(zh|hi)$/.test(lang.code) ? "0" : ".08em"}; text-transform: uppercase; fill: #9DB8DA; } .words text.y { fill: #7FD1FF; }
</style>
<div class="text">
  <div class="brand"><img src="${fileURL("static/icon-dark.png")}" alt="">Copy Beyond Borders</div>
  <h1>${t("Copy here,")} <span>${t("paste on any of your devices.")}</span></h1>
  <p>ANDROID · IPHONE · AURORA · WINDOWS · MAC · LINUX</p>
</div>
<div class="frame"><i class="a"></i><i class="b"></i><i class="c"></i><i class="d"></i><div class="surface"><svg class="board" viewBox="0 0 640 330"><g class="chalk">${hero}</g><g class="words">${word(95, 228, "Computer")}${word(455, 292, "TLS 1.3", true)}${word(576, 228, "Phone")}</g></svg></div></div>
</html>`;
}

(async () => {
  const out = path.join(dir, "static", "og");
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch();
  const tab = await browser.newPage({ viewport: { width: 1200, height: 630 } });
  for (const lang of langs) {
    const file = path.join(out, lang.code + ".html");
    fs.writeFileSync(file, page(lang)); // a file, so the page may load the fonts beside it
    await tab.goto("file://" + file);
    await tab.evaluate(() => document.fonts.ready);
    await tab.screenshot({ path: path.join(out, lang.code + ".jpg"), type: "jpeg", quality: 86 });
    fs.unlinkSync(file);
  }
  await browser.close();
})();
