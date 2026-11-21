// SPDX-License-Identifier: AGPL-3.0-only
//
// Draws the picture a link to the site shows in chats and social networks,
// one for each language: static/og/<language>.jpg, 1200 by 630, the title
// of the home page beside its chalk board. Run `npm run og` after changing
// the title or the drawing; it needs Playwright's Chromium, and for
// Chinese, Arabic, Hebrew and Hindi Noto fonts installed or named in
// OG_FONTS, a stylesheet of @font-face rules.
"use strict";
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const dir = __dirname;
const read = (f) => fs.readFileSync(path.join(dir, f), "utf8");
const hero = read("templates/chalk.html").match(/{{define "chalk-hero"}}([\s\S]*?){{end}}/)[1];
const filters = read("templates/layout.html").match(/<filter[\s\S]*?<\/filter>/g).join("\n");
const extra = process.env.OG_FONTS ? fs.readFileSync(process.env.OG_FONTS, "utf8") : "";
const fileURL = (f) => "file://" + path.join(dir, f);
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

const langs = [{ code: "en", texts: {} }].concat(
  fs.readdirSync(path.join(dir, "l10n")).filter((f) => f.endsWith(".json")).sort()
    .map((f) => ({ code: f.slice(0, -5), texts: JSON.parse(read("l10n/" + f)) })));

function page(lang) {
  const t = (s) => esc(lang.texts[s] || s);
  const rtl = lang.texts["@dir"] === "rtl";
  const word = (x, y, s, yellow) => `<text x="${x}" y="${y}" text-anchor="middle"${yellow ? ' class="y"' : ""}>${t(s)}</text>`;
  return `<!doctype html><html lang="${lang.texts["@lang"] || lang.code}" dir="${rtl ? "rtl" : "ltr"}"><meta charset="utf-8"><style>
${extra}
@font-face { font-family: Forum; src: url(${fileURL("static/fonts/forum-400-latin.woff2")}); unicode-range: U+0000-00FF, U+2000-206F; }
@font-face { font-family: Forum; src: url(${fileURL("static/fonts/forum-400-cyrillic.woff2")}); unicode-range: U+0400-045F; }
@font-face { font-family: Plex; src: url(${fileURL("static/fonts/ibm-plex-mono-500-latin.woff2")}); }
@font-face { font-family: Caveat; src: url(${fileURL("static/fonts/caveat-600-latin.woff2")}); unicode-range: U+0000-00FF; }
@font-face { font-family: Caveat; src: url(${fileURL("static/fonts/caveat-600-cyrillic.woff2")}); unicode-range: U+0400-045F; }
body { margin: 0; width: 1200px; height: 630px; overflow: hidden; display: flex; align-items: center; gap: 44px; padding: 0 64px; box-sizing: border-box;
  color: #F1EAD8; background: radial-gradient(50rem 30rem at 30% 10%, rgba(60, 110, 120, .2), transparent 70%), radial-gradient(120% 90% at 50% 40%, transparent 50%, rgba(0, 0, 0, .5)), url(${fileURL("static/felt.jpg")}) 0 0 / 256px; }
.text { flex: 1; min-width: 0; }
.brand { display: flex; align-items: center; gap: 18px; font: 30px/1 Forum, serif; letter-spacing: .14em; text-transform: uppercase; color: #D8B46A; }
.brand img { width: 72px; height: 72px; }
h1 { font: 400 70px/1.04 Forum, "Noto Serif SC", "Noto Naskh Arabic", "Frank Ruhl Libre", "Noto Serif Devanagari", serif; text-transform: uppercase; letter-spacing: .03em; margin: 38px 0 30px; }
h1 span { display: block; background: linear-gradient(180deg, #F6DC9C, #C99A45 60%, #F1D48A); -webkit-background-clip: text; background-clip: text; color: transparent; }
p { font: 500 17px/1.4 Plex, monospace; letter-spacing: .14em; color: #A8B9B9; margin: 0; white-space: nowrap; }
.frame { position: relative; width: 470px; padding: 18px; flex: none; box-shadow: 0 28px 46px -22px #000;
  background: url(${fileURL("static/wood-h.jpg")}) -200px -30px / auto 150px; }
.surface { background-color: #141514; background-image: linear-gradient(rgba(255,255,255,.045) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.045) 1px, transparent 1px); background-size: 20px 20px; box-shadow: inset 0 3px 6px rgba(0,0,0,.8); }
svg.board { display: block; width: 100%; height: auto; }
.chalk { filter: url(#chalk); } .chalk path { fill: none; stroke-width: 3.6; stroke-linecap: round; stroke-linejoin: round; }
.w { stroke: #F2F0EA; } .y { stroke: #EFD38E; }
.words { filter: url(#chalk-words); } .words text { font: 600 27px Caveat, "Noto Sans SC", "Noto Sans Arabic", "Noto Sans Hebrew", "Noto Sans Devanagari", cursive; fill: #ECE9E1; } .words text.y { fill: #EFD38E; }
</style>
<svg width="0" height="0" style="position:absolute">${filters}</svg>
<div class="text">
  <div class="brand"><img src="${fileURL("static/icon-dark.png")}" alt="">Copy Beyond Borders</div>
  <h1>${t("Copy here,")} <span>${t("paste on any of your devices.")}</span></h1>
  <p>ANDROID · IPHONE · AURORA · WINDOWS · MAC · LINUX</p>
</div>
<div class="frame"><div class="surface"><svg class="board" viewBox="0 0 640 330"><g class="chalk">${hero}</g><g class="words">${word(95, 228, "Computer")}${word(455, 292, "TLS 1.3", true)}${word(576, 228, "Phone")}</g></svg></div></div>
</html>`;
}

(async () => {
  const out = path.join(dir, "static", "og");
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch();
  const tab = await browser.newPage({ viewport: { width: 1200, height: 630 } });
  for (const lang of langs) {
    const file = path.join(out, lang.code + ".html");
    fs.writeFileSync(file, page(lang)); // a file, so the page may load the fonts and textures beside it
    await tab.goto("file://" + file);
    await tab.evaluate(() => document.fonts.ready);
    await tab.screenshot({ path: path.join(out, lang.code + ".jpg"), type: "jpeg", quality: 86 });
    fs.unlinkSync(file);
  }
  await browser.close();
})();
