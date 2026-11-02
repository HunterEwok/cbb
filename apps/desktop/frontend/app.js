// SPDX-License-Identifier: AGPL-3.0-only
// The tray app's window: the group's devices as tiles, a list or orbits
// around this computer, a device's details beside them, send and fetch
// (docs/apps.md, "The tray app"). It asks the Go side (desk.go) for the
// state every few seconds; every action goes through the Go side too.

import { Call } from "/wails/runtime.js";
import { colors, radius, spacing } from "./tokens.js";

const call = (method, ...args) => Call.ByName("main.Desk." + method, ...args);
const $ = (id) => document.getElementById(id);

let state = null;
let selected = null;
// Arrange mode, the collection whose page is open, the tile being dragged
// (docs/apps.md, "Collections and the order of the tiles"), and Home's
// search and filter once there are many devices.
let arranging = false;
let opened = null;
let dragging = null;
let query = "";
let filter = null;
let tr = {};
let lang = "";

// t translates an English text; %s and %d take the arguments in order.
function t(s, ...args) {
  let out = tr[s] ?? s;
  for (const a of args) out = out.replace(/%[sd]/, String(a));
  return out;
}

async function loadLanguage(l) {
  if (l === lang) return;
  lang = l;
  tr = {};
  if (l !== "en") {
    try {
      tr = await (await fetch(`l10n/${l}.json`)).json();
    } catch (e) {
      console.error("l10n", e);
    }
  }
  document.documentElement.lang = l;
  for (const el of document.querySelectorAll("[data-t]")) {
    el.dataset.en ??= el.textContent;
    el.textContent = t(el.dataset.en);
  }
  for (const el of document.querySelectorAll("[data-t-title]")) {
    el.title = t(el.dataset.tTitle);
    el.setAttribute("aria-label", el.title);
  }
}

// The colours: the chosen accent on the dark or light base, as the phones.
const darkQuery = matchMedia("(prefers-color-scheme: dark)");

function applyTheme() {
  const s = state?.settings ?? {};
  const pair = colors.find((c) => c.name === s.color) ?? colors[0];
  const dark = s.appearance === "dark" || (s.appearance !== "light" && darkQuery.matches);
  const p = dark ? pair.dark : pair.light;
  const root = document.documentElement.style;
  const alpha = (hex, a) => hex + Math.round(a * 255).toString(16).padStart(2, "0");
  root.setProperty("--background", p.background);
  root.setProperty("--surface", p.surface);
  root.setProperty("--text", p.text);
  root.setProperty("--text-dim", p.textDim);
  root.setProperty("--accent", p.accent);
  root.setProperty("--on-accent", p.onAccent);
  root.setProperty("--danger", p.danger);
  root.setProperty("--glass", dark ? alpha(p.surface, 0.78) : "#FFFFFFDB");
  root.setProperty("--soft", alpha(p.accent, dark ? 0.16 : 0.1));
  root.setProperty("--line", alpha(p.text, dark ? 0.12 : 0.1));
  root.setProperty("color-scheme", dark ? "dark" : "light");
  for (const [k, v] of Object.entries(radius)) root.setProperty(`--radius-${k}`, v + "px");
  for (const [k, v] of Object.entries(spacing)) root.setProperty(`--spacing-${k}`, v + "px");
}
darkQuery.addEventListener("change", applyTheme);

// What a device is: its form from its hello, else its role and system.
const kinds = {
  laptop: "Laptop", desktop: "Computer", phone: "Phone", tablet: "Tablet", tv: "TV", board: "Board",
  server: "Server", router: "Router", console: "Game console", watch: "Watch", retro: "Retro computer", other: "Device",
};

export function kindOf(d) {
  if (d.form && kinds[d.form]) return d.form;
  if (d.role === "phone" || d.role === "shortcut") return "phone";
  if (d.role === "lite") return "board";
  if (d.role === "watch") return "watch";
  if (d.os === "macos") return "laptop";
  if (d.os === "ios" || d.os === "android") return "phone";
  return "desktop";
}

const systems = {
  linux: "Linux", windows: "Windows", macos: "macOS", ios: "iOS", android: "Android", watchos: "watchOS", wearos: "Wear OS",
};

export function systemWithVersion(d) {
  const s = systems[d.os];
  if (!s) return d.os_version ?? "";
  if (!d.os_version) return s;
  return d.os === "linux" ? d.os_version : `${s} ${d.os_version}`;
}

// The kinds' outlines on a grid of 24, as the Android app draws them.
const shapes = {
  laptop: '<rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2 19h20"/>',
  desktop: '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M12 16v4M8 20h8"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M10.5 18.5h3"/>',
  tablet: '<rect x="4.5" y="2.5" width="15" height="19" rx="2"/><path d="M10.5 18.5h3"/>',
  tv: '<rect x="2.5" y="5" width="19" height="12" rx="1.5"/><path d="M8 20.5h8M9 2l3 3 3-3"/>',
  board: '<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.5" y="9.5" width="5" height="5" rx=".8"/>' +
    '<path d="M9 2.5V6M12 2.5V6M15 2.5V6M9 18v3.5M12 18v3.5M15 18v3.5M2.5 9H6M2.5 12H6M2.5 15H6M18 9h3.5M18 12h3.5M18 15h3.5"/>',
  server: '<rect x="4" y="3.5" width="16" height="7" rx="1.5"/><rect x="4" y="13.5" width="16" height="7" rx="1.5"/>' +
    '<circle cx="8" cy="7" r="1" fill="currentColor"/><circle cx="8" cy="17" r="1" fill="currentColor"/>',
  router: '<rect x="3" y="12" width="18" height="8" rx="1.5"/><path d="M7 12L5 4M17 12l2-8"/>' +
    '<circle cx="7.5" cy="16" r="1" fill="currentColor"/><circle cx="11" cy="16" r="1" fill="currentColor"/>',
  console: '<rect x="2.5" y="7" width="19" height="11" rx="5"/><path d="M7 10.5v4M5 12.5h4"/>' +
    '<circle cx="15.5" cy="11" r="1" fill="currentColor"/><circle cx="17.5" cy="13.5" r="1" fill="currentColor"/>',
  watch: '<rect x="7" y="6" width="10" height="12" rx="3"/><path d="M9 6l.5-3.5M15 6l-.5-3.5M9 18l.5 3.5M15 18l-.5 3.5"/>',
  retro: '<rect x="2" y="7" width="20" height="10" rx="1.5"/><path d="M7 14h10"/>' +
    [6, 9, 12, 15, 18].map((x) => `<circle cx="${x}" cy="10.5" r=".8" fill="currentColor"/>`).join(""),
  other: '<rect x="4" y="7" width="16" height="13" rx="1.5"/><path d="M4 11h16M9 3.5L4 7M15 3.5l5 3.5M9 3.5h6"/>',
};

// The buttons' icons, drawn as the devices' glyphs: a text symbol sits where
// its font puts it, which is off the button's centre in the fallback fonts
// Windows draws such symbols with.
const icons = {
  tiles: '<rect x="4" y="4" width="6.5" height="6.5" rx="1.5"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.5"/>' +
    '<rect x="4" y="13.5" width="6.5" height="6.5" rx="1.5"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.5"/>',
  list: '<path d="M5 6.5h14M5 12h14M5 17.5h14"/>',
  orbit: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="2.5"/>',
  arrange: '<path d="M8 19V5M4.5 8.5L8 5l3.5 3.5M16 5v14M12.5 15.5L16 19l3.5-3.5"/>',
  add: '<path d="M12 5v14M5 12h14"/>',
  settings: '<path d="M10.61 5.14L10.85 2.47L13.15 2.47L13.39 5.14L15.87 6.17L17.93 4.45L19.55 6.07L17.83 8.13L18.86 10.61' +
    'L21.53 10.85L21.53 13.15L18.86 13.39L17.83 15.87L19.55 17.93L17.93 19.55L15.87 17.83L13.39 18.86L13.15 21.53L10.85 21.53' +
    'L10.61 18.86L8.13 17.83L6.07 19.55L4.45 17.93L6.17 15.87L5.14 13.39L2.47 13.15L2.47 10.85L5.14 10.61L6.17 8.13L4.45 6.07' +
    'L6.07 4.45L8.13 6.17Z"/><circle cx="12" cy="12" r="3"/>',
  back: '<path d="M14.5 5.5L8 12l6.5 6.5"/>',
  close: '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
  more: ['6', '12', '18'].map((y) => `<circle cx="12" cy="${y}" r="1.2" fill="currentColor"/>`).join(""),
};

const icon = (name, size = 18) => `<svg class="icon-svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" ` +
  `stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name]}</svg>`;

for (const el of document.querySelectorAll("[data-icon]")) el.innerHTML = icon(el.dataset.icon);

function glyph(d, size = 44) {
  const on = d.online || d.self;
  return `<span class="glyph${on ? " on" : ""}" style="width:${size}px;height:${size}px" aria-hidden="true">` +
    `<svg width="${size * 0.56}" height="${size * 0.56}" viewBox="0 0 24 24" fill="none" stroke="currentColor" ` +
    `stroke-width="1.8" stroke-linecap="round">${shapes[kindOf(d)]}</svg></span>`;
}

// The sync modes (docs/design.md, "Sync modes"), in the order they show.
const modes = ["own", "shared", "receive", "send"];
const modeName = (m) => ({ own: t("Own clipboard"), shared: t("Shared"), receive: t("Receive only"), send: t("Send only") })[m] ?? m;

// modeButtons is a row of the four modes; id names the device, "" this
// computer.
function modeButtons(current, id) {
  return modes.map((m) => `<button type="button" data-mode="${m}" data-mode-for="${esc(id)}" aria-checked="${m === current}" ` +
    `${state.busy ? "disabled" : ""}>${esc(modeName(m))}</button>`).join("");
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const dot = (on) => `<span class="dot${on ? " on" : ""}"></span>`;

// render draws the whole window from the state.
function render() {
  const s = state;
  const others = s.devices.filter((d) => !d.self);
  const inGroup = !s.problem && s.status && s.status.group && !s.status.removed;
  // This computer counts too, online as it is the one in front of the user.
  const online = s.devices.filter((d) => d.online || d.self).length;
  $("headline").textContent = s.problem ? t("The service does not answer")
    : !inGroup ? t("This computer is in no group yet") : t("%d of %d online", online, s.devices.length);
  $("tag").textContent = inGroup ? s.status.group : "";
  renderAway(inGroup ? s.status.away : undefined, inGroup);
  renderAlerts(inGroup ? s.status : undefined);
  for (const b of document.querySelectorAll("[data-layout]")) b.setAttribute("aria-checked", String(b.dataset.layout === s.settings.layout));
  $("bar").hidden = !inGroup;
  $("send").disabled = $("fetch").disabled = $("update").disabled = s.busy;
  // The newest release the group passed around, when this computer runs an older one.
  $("update").hidden = !s.status?.update;
  $("update").textContent = s.status?.update ? t("Update to %s", s.status.update) : "";
  $("message").textContent = s.message ?? "";

  // The details first: the orbits fit the room they leave.
  renderDetail();
  const box = $("devices");
  box.classList.toggle("fixed", inGroup && others.length > 0 && s.settings.layout === "orbit");
  if (s.problem) {
    box.innerHTML = `<div class="notice"><div class="big">⚠</div><h2>${esc(t("The service does not answer"))}</h2><p class="dim">${esc(s.problem)}</p></div>`;
  } else if (!inGroup) {
    box.innerHTML = `<div class="notice"><div class="big">⧉</div><h2>${esc(t("This computer is in no group yet"))}</h2>` +
      `<p class="dim">${esc(t("Run cbb pair in a terminal and scan its QR code with the phone app, or make a group of computers with cbb new."))}</p></div>`;
  } else if (others.length === 0) {
    box.innerHTML = `<div class="notice"><div class="big">＋</div><h2>${esc(t("No other devices yet"))}</h2><p class="dim">${esc(t("Add one with the + button."))}</p></div>`;
  } else if (s.settings.layout === "orbit" && !arranging && !searching() && !opened) {
    // The orbit keeps the group's order.
    renderOrbit(box, others);
  } else {
    renderArranged(box, others);
  }
  $("arrange").setAttribute("aria-pressed", String(arranging));
  $("arrange").hidden = !inGroup || others.length === 0;
}

// The devices as tiles or a list: in the user's order with the
// collections, a collection's page, or flat while a search or a filter is
// on (more than 12 devices).
// What the group's records stop and what ends it, from cbb status
// (docs/protocol.md, section 10, "Stopping the exchange"): on the group's
// root, cbb resolve for two histories and removing an admin for the others.
function renderAlerts(st) {
  const box = $("alerts");
  const lines = st ? alertLines(st) : [];
  box.hidden = lines.length === 0;
  const root = state.devices.find((x) => x.self)?.root;
  box.innerHTML = "";
  for (const l of lines) {
    const p = document.createElement("p");
    p.className = l.newer ? "alert newer" : "alert";
    p.textContent = "⚠ " + l.text;
    box.append(p);
    if (!l.resolve && l.remove.length === 0) continue;
    if (!root) {
      const d = document.createElement("p");
      d.className = "dim";
      d.textContent = t("The group's root decides.");
      box.append(d);
      continue;
    }
    const row = document.createElement("div");
    row.className = "buttons";
    if (l.resolve) {
      const b = document.createElement("button");
      b.className = "glass";
      b.textContent = t("Void both histories");
      b.disabled = state.busy;
      b.onclick = async () => {
        if (await ask(t("Void both histories?"), t("Records signed with a stolen key are gone too; the device whose key it was signs its own again by itself."), t("Void both histories"))) await act("Resolve");
      };
      row.append(b);
    }
    for (const name of l.remove) {
      const b = document.createElement("button");
      b.className = "glass danger";
      b.textContent = t("Remove %s", name);
      b.disabled = state.busy;
      b.onclick = async () => {
        if (await ask(t("Remove %s?", name), t("It will no longer sync with your devices. To add it again, pair it again."), t("Remove"))) await act("Remove", name);
      };
      row.append(b);
    }
    box.append(row);
  }
}

// A wait in days, hours or minutes.
function roughly(ms) {
  const h = Math.floor(ms / 3600000);
  if (h >= 48) return t("%d d", Math.floor(h / 24));
  if (h >= 2) return t("%d h", h);
  return t("%d min", Math.max(1, Math.floor(ms / 60000)));
}

// The alerts of a status: a sentence each, whether cbb resolve ends it, and
// the devices whose removal does.
function alertLines(st) {
  const out = [];
  if (st.stop === "full") out.push({ text: t("The group is stopped: its devices exchange only their records, no clipboard, until the group's root decides."), remove: [] });
  if (st.stop === "secrets") out.push({ text: t("The group sends no secrets until its root decides."), remove: [] });
  for (const c of st.conflicts ?? []) {
    const who = c.devices?.length ? c.devices.join(", ") : t("devices unknown here");
    if (c.kind === "two_histories") out.push({ text: t("%s signed two histories with one key, as a stolen key or a restore from a backup would.", who), resolve: true, remove: [] });
    if (c.kind === "admins") out.push({ text: t("Admins removed or froze each other without seeing it: %s. The root removes one of them.", who), remove: c.devices ?? [] });
    if (c.kind === "claims") out.push({ text: t("Two claims to take the group over: %s. The root cancels one or both by removing its admin.", who), remove: c.devices ?? [] });
  }
  for (const c of st.claims ?? []) {
    if (c.state === "pending") {
      out.push({ text: c.left_ms > 0
        ? t("%s claims the group, to take it over from its root: it takes effect in %s, unless the root removes it.", c.by, roughly(c.left_ms))
        : t("%s claims the group, to take it over from its root, unless the root removes it.", c.by), remove: [c.by] });
    } else if (c.state === "competing" || c.state === "disputed") {
      out.push({ text: t("%s claims the group, and the group is stopped until its root decides.", c.by), remove: [c.by] });
    }
  }
  if (st.newer > 0) out.push({ text: t("The group holds %d records of a later version: update Clipboard Bridge to read them.", st.newer), newer: true, remove: [] });
  return out;
}

function renderArranged(box, others) {
  const list = state.settings.layout === "list";
  const byId = new Map(others.map((d) => [d.id, d]));
  let head = "";
  if (others.length > 12) {
    head += `<div class="search"><input class="field" id="search" type="search" placeholder="${esc(t("Search devices"))}" ` +
      `aria-label="${esc(t("Search devices"))}" value="${esc(query)}">` +
      [["online", t("Online")], ["attention", t("Needs attention")]].map(([f, label]) =>
        `<button class="chip" data-filter="${f}" aria-pressed="${filter === f}">${esc(label)}</button>`).join("") + `</div>`;
  }
  if (arranging) {
    head += `<div class="card arrange-bar"><span class="dim small">${esc(t("Drag to arrange. Drop a device on a collection to put it in. Alt and the arrow keys move the focused tile."))}</span>` +
      (state.custom && !opened ? `<button class="glass" id="arrange-reset">${esc(t("Back to the group's order"))}</button>` : "") +
      `<button class="accent" id="arrange-done">${esc(t("Done"))}</button></div>`;
  }
  let body;
  if (searching()) {
    const q = query.trim().toLowerCase();
    const found = state.devices.filter((d) => (!q || d.name.toLowerCase().includes(q) || systemWithVersion(d).toLowerCase().includes(q)) &&
      (filter !== "online" || d.online) && (filter !== "attention" || d.frozen));
    body = found.length === 0 ? `<p class="dim">${esc(t("No devices match."))}</p>`
      : list ? `<div class="list">${found.map((d) => deviceRow(d)).join("")}</div>`
        : `<div class="tiles">${found.map((d) => deviceTile(d)).join("")}</div>`;
  } else if (opened) {
    const c = collectionOf(opened);
    if (!c) {
      // A collection that a move emptied goes away, and so does its page.
      opened = null;
      return renderArranged(box, others);
    }
    const ds = c.devices.map((id) => byId.get(id)).filter(Boolean);
    const level = "c:" + c.id;
    head = `<div class="collection-head"><button class="icon" id="collection-back" title="${esc(t("Back"))}" aria-label="${esc(t("Back"))}">${icon("back")}</button>` +
      `<h2>${esc(c.name)}</h2><button class="glass" data-menu="c:${esc(c.id)}" data-level="top">${esc(t("Menu"))}</button></div>` + head;
    body = ds.length === 0 ? `<p class="dim">${esc(t("Drag devices here, or add them with Move to collection in a device's menu."))}</p>`
      : list ? `<div class="list">${ds.map((d) => deviceRow(d, level)).join("")}</div>`
        : `<div class="tiles">${ds.map((d) => deviceTile(d, level)).join("")}</div>`;
  } else {
    const items = (state.arranged ?? []).filter((it) => it.collection || byId.has(it.device));
    // This computer first, as on the phones; it stays out of the arrangement.
    const me = state.devices.find((d) => d.self);
    if (list) {
      body = `<div class="list">${me ? deviceRow(me) : ""}${items.map((it) => {
        if (!it.collection) return deviceRow(byId.get(it.device), "top");
        const c = it.collection, ds = c.devices.map((id) => byId.get(id)).filter(Boolean);
        return collectionRow(c, ds) + ds.map((d) => deviceRow(d, "c:" + c.id, true)).join("");
      }).join("")}</div>`;
    } else {
      body = `<div class="tiles">${me ? deviceTile(me) : ""}${items.map((it) => it.collection
        ? collectionTile(it.collection, it.collection.devices.map((id) => byId.get(id)).filter(Boolean))
        : deviceTile(byId.get(it.device), "top")).join("")}</div>`;
    }
  }
  // The search keeps the focus and the cursor across a redraw.
  const typing = document.activeElement?.id === "search";
  box.innerHTML = head + body;
  if (typing) {
    const input = $("search");
    input.focus();
    input.setSelectionRange(query.length, query.length);
  }
}

const searching = () => state.devices.filter((d) => !d.self).length > 12 && (query.trim() !== "" || filter !== null);
const collectionOf = (id) => (state.arranged ?? []).find((it) => it.collection?.id === id)?.collection;

// cell wraps a tile or a row: in Arrange mode it can be dragged and has a
// button for its menu; level is the order it moves in ("top", or "c:" and
// a collection's ID), absent where nothing moves.
function cell(ref, level, name, inner) {
  if (!level) return inner;
  const more = arranging ? `<button class="more" data-menu="${esc(ref)}" data-level="${esc(level)}" ` +
    `title="${esc(t("Menu: %s", name))}" aria-label="${esc(t("Menu: %s", name))}">${icon("more", 16)}</button>` : "";
  return `<div class="cell${arranging ? " arranging" : ""}" data-ref="${esc(ref)}" data-level="${esc(level)}"` +
    `${arranging ? ' draggable="true"' : ""}>${inner}${more}</div>`;
}

function deviceTile(d, level) {
  return cell("d:" + d.id, level, d.name, `<button class="tile${d.id === selected ? " selected" : ""}" data-id="${esc(d.id)}">` +
    `<span class="top">${glyph(d)}${dot(d.online || d.self)}</span><span class="name">${esc(d.name)}</span>` +
    `<span class="dim small">${esc([systems[d.os], d.self && t("This computer")].filter(Boolean).join(" · "))}</span></button>`);
}

function deviceRow(d, level, inside) {
  return cell("d:" + d.id, level, d.name, `<button class="row${d.id === selected ? " selected" : ""}${inside ? " inside" : ""}" data-id="${esc(d.id)}">${glyph(d, 32)}` +
    `<span class="name">${esc(d.name)}</span><span class="dim">${esc([systemWithVersion(d), d.self && t("This computer")].filter(Boolean).join(" · "))}</span>${dot(d.online || d.self)}</button>`);
}

// A collection as a tile: up to four of its devices' icons, its name and
// how many are online, with a mark when one of them needs attention.
function collectionTile(c, ds) {
  const online = ds.filter((d) => d.online).length, attention = ds.some((d) => d.frozen);
  const icons = [0, 1, 2, 3].map((i) => ds[i] ? glyph(ds[i], 20) : `<span class="glyph-gap"></span>`).join("");
  const label = attention ? t("collection, %d of %d online, needs attention", online, ds.length) : t("collection, %d of %d online", online, ds.length);
  return cell("c:" + c.id, "top", c.name, `<button class="tile collection" data-open="${esc(c.id)}" aria-label="${esc(c.name + ", " + label)}">` +
    `<span class="top"><span class="minis">${icons}</span>${attention ? '<span class="attention">!</span>' : ""}</span>` +
    `<span class="name">${esc(c.name)}</span><span class="dim small">${esc(ds.length ? t("%d of %d online", online, ds.length) : t("Drag devices here"))}</span></button>`);
}

// A collection in the list: a header with its name and how many are online.
function collectionRow(c, ds) {
  const online = ds.filter((d) => d.online).length;
  return cell("c:" + c.id, "top", c.name, `<button class="row section" data-open="${esc(c.id)}"><span class="name">${esc(c.name)}</span>` +
    `${ds.some((d) => d.frozen) ? '<span class="attention">!</span>' : ""}<span class="dim">${esc(t("%d of %d online", online, ds.length))}</span></button>`);
}

// The refs of a level, in order.
function levelRefs(level) {
  if (level === "top") return (state.arranged ?? []).map((it) => it.collection ? "c:" + it.collection.id : "d:" + it.device);
  return (collectionOf(level.slice(2))?.devices ?? []).map((id) => "d:" + id);
}

const refJSON = (ref) => ref.startsWith("c:") ? { collection: ref.slice(2) } : { device: ref.slice(2) };

// move puts ref before before (a ref, or null for the end of its level).
const move = (ref, before) => arrange({ op: "move", item: refJSON(ref), before: before ? refJSON(before) : null });

async function arrange(op) {
  try {
    await call("Arrange", op);
  } catch (e) {
    console.error("arrange", e);
  }
  await refresh();
}

// moveBy moves the tile by steps within its level: -1 earlier, 1 later,
// -Infinity to the start, Infinity to the end.
function moveBy(ref, level, steps) {
  const refs = levelRefs(level), i = refs.indexOf(ref);
  if (i < 0) return;
  if (steps === -Infinity) return i > 0 && move(ref, refs[0]);
  if (steps === Infinity) return i + 1 < refs.length && move(ref, null);
  if (steps < 0) return i > 0 && move(ref, refs[i - 1]);
  return i + 1 < refs.length && move(ref, refs[i + 2] ?? null);
}

// A tile's menu: every change a drag makes, and Move to collection.
function openMenu(ref, level) {
  const refs = levelRefs(level), i = refs.indexOf(ref);
  const items = [];
  if (!arranging) items.push(["arrange", t("Arrange")]);
  if (ref.startsWith("d:")) {
    const id = ref.slice(2);
    for (const it of state.arranged ?? []) {
      if (it.collection && !it.collection.devices.includes(id)) items.push([JSON.stringify({ op: "into", device: id, collection: it.collection.id }), t("Move to %s", it.collection.name)]);
    }
    items.push(["new", t("New collection…")]);
    if ((state.arranged ?? []).some((it) => it.collection?.devices.includes(id))) items.push([JSON.stringify({ op: "out", device: id }), t("Take out of collection")]);
  } else {
    items.push(["rename", t("Rename collection…")]);
    items.push([JSON.stringify({ op: "ungroup", collection: ref.slice(2) }), t("Ungroup")]);
  }
  if (i > 0) items.push(["start", t("Move to start")], ["earlier", t("Move earlier")]);
  if (i >= 0 && i + 1 < refs.length) items.push(["later", t("Move later")], ["end", t("Move to end")]);
  const dlg = $("tile-menu");
  $("tile-menu-items").innerHTML = items.map(([v, label]) => `<button value="${esc(v)}" class="glass">${esc(label)}</button>`).join("");
  dlg.returnValue = "";
  dlg.onclose = () => menuChoice(dlg.returnValue, ref, level);
  dlg.showModal();
}

async function menuChoice(v, ref, level) {
  switch (v) {
    case "": case "cancel": return;
    case "arrange": arranging = true; return render();
    case "start": return moveBy(ref, level, -Infinity);
    case "earlier": return moveBy(ref, level, -1);
    case "later": return moveBy(ref, level, 1);
    case "end": return moveBy(ref, level, Infinity);
    case "new": {
      const name = await ask(t("New collection"), t("The collection is kept on this computer only."), t("Save"), "");
      if (name && name.trim()) await arrange({ op: "new", name: name.trim(), devices: [ref.slice(2)] });
      return;
    }
    case "rename": {
      const c = collectionOf(ref.slice(2));
      const name = await ask(t("Rename collection"), t("The collection is kept on this computer only."), t("Save"), c?.name ?? "");
      if (name && name.trim()) await arrange({ op: "rename", collection: ref.slice(2), name: name.trim() });
      return;
    }
  }
  await arrange(JSON.parse(v));
}

// The drag: a device dropped on a collection goes into it, and a tile
// dropped on another of its level takes its place.
document.addEventListener("dragstart", (e) => {
  const c = e.target.closest?.(".cell[draggable]");
  if (!c) return;
  dragging = { ref: c.dataset.ref, level: c.dataset.level };
  e.dataTransfer.effectAllowed = "move";
  e.dataTransfer.setData("text/plain", "");
  c.classList.add("dragging");
});
document.addEventListener("dragover", (e) => {
  const c = e.target.closest?.(".cell");
  if (!dragging || !c || c.dataset.ref === dragging.ref) return;
  e.preventDefault();
  for (const o of document.querySelectorAll(".cell.over")) if (o !== c) o.classList.remove("over");
  c.classList.add("over");
});
document.addEventListener("dragend", () => {
  dragging = null;
  for (const o of document.querySelectorAll(".cell.over, .cell.dragging")) o.classList.remove("over", "dragging");
});
document.addEventListener("drop", async (e) => {
  const c = e.target.closest?.(".cell");
  const d = dragging;
  dragging = null;
  if (!d || !c || c.dataset.ref === d.ref) return;
  e.preventDefault();
  const target = c.dataset.ref;
  if (d.ref.startsWith("d:") && target.startsWith("c:")) return arrange({ op: "into", device: d.ref.slice(2), collection: target.slice(2) });
  if (c.dataset.level !== d.level) return;
  const refs = levelRefs(d.level), from = refs.indexOf(d.ref), to = refs.indexOf(target);
  if (from < 0 || to < 0) return;
  await move(d.ref, from < to ? refs[to + 1] ?? null : target);
});
document.addEventListener("contextmenu", (e) => {
  const c = e.target.closest?.(".cell");
  if (!c) return;
  e.preventDefault();
  openMenu(c.dataset.ref, c.dataset.level);
});

function renderAway(away, inGroup) {
  $("away-switch").hidden = !inGroup;
  $("away").checked = !!away;
  $("away").disabled = state.busy;
  const badge = $("away-badge");
  badge.hidden = !away;
  if (!away) return;
  const bad = !away.hub && away.error;
  badge.textContent = away.hub ? t("hub") : away.through ? t("through the tunnel") : bad ? t("hub unreachable") : t("at home");
  badge.classList.toggle("bad", !!bad);
  badge.title = away.error ?? "";
}

// The orbits: up to six devices on the inner one, the rest on the outer,
// this computer at the centre with the send button.
export function spots(count, radii, cx, cy) {
  if (count === 0) return [];
  const rings = radii.length === 1 ? [[radii[0], count, 0]] : [[radii[0], 6, 0], [radii[1], count - 6, 0.5]];
  const out = [];
  for (const [r, n, turn] of rings) {
    for (let i = 0; i < n; i++) {
      const a = ((i + turn) / n) * 2 * Math.PI - Math.PI / 2;
      out.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]);
    }
  }
  return out;
}

function renderOrbit(box, others) {
  const w = box.clientWidth, h = box.clientHeight;
  const side = Math.min(w, h), cx = w / 2, cy = h / 2;
  const radii = others.length > 6 ? [side * 0.28, side * 0.43] : [side * 0.36];
  const at = spots(others.length, radii, cx, cy);
  const rings = radii.map((r) => `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--line)"/>`).join("");
  const lines = others.map((d, i) => d.online
    ? `<line x1="${cx}" y1="${cy}" x2="${at[i][0]}" y2="${at[i][1]}" stroke="var(--accent)" stroke-opacity=".35" stroke-width="1.5" stroke-dasharray="4 6"/>` : "").join("");
  box.innerHTML = `<div class="orbit"><svg class="rings">${rings}${lines}</svg>` +
    `<button class="hub" id="orbit-send" style="left:${cx}px;top:${cy}px" ${state.busy ? "disabled" : ""}>${icon("arrange", 22)}<span>${esc(t("Send"))}</span></button>` +
    others.map((d, i) => `<button class="node${d.id === selected ? " selected" : ""}" data-id="${esc(d.id)}" style="left:${at[i][0]}px;top:${at[i][1]}px">` +
      `${glyph(d, 48)}<span class="name">${esc(d.name)}</span></button>`).join("") + `</div>`;
}

// The details beside the devices, as the phones' summary, then what an
// admin computer may do with it.
function renderDetail() {
  const pane = $("detail");
  const d = state.devices.find((x) => x.id === selected);
  if (!d) {
    selected = null;
    pane.hidden = true;
    return;
  }
  pane.hidden = false;
  const kind = kindOf(d);
  const lines = [[t("Type"), t(kinds[kind])]];
  const sys = systemWithVersion(d);
  if (sys) lines.push([t("Operating system"), sys]);
  if (d.version) lines.push(["Clipboard Bridge", d.version, true]);
  if (d.mac) lines.push([t("MAC address"), d.mac, true]);
  else if (kind === "phone" || kind === "tablet") lines.push([t("MAC address"), t("hidden by the system")]);
  lines.push([t("Role"), t({ phone: "Phone app", lite: "Lite member", shortcut: "Shortcut" }[d.role] ?? "Full member")]);
  const standing = d.self ? (d.admin ? t("This computer · admin") : t("This computer"))
    : d.frozen ? t("frozen") : d.root ? t("root") : d.admin ? t("admin") : "";
  if (standing) lines.push([t("In the group"), standing]);
  if (d.mode) lines.push([t("Sync mode"), modeName(d.mode)]);
  if (!d.online && d.last_seen_ms) lines.push([t("Last seen"), new Date(d.last_seen_ms).toLocaleString(lang)]);
  lines.push([t("Device ID"), d.id, true]);

  const me = state.devices.find((x) => x.self);
  const actions = [];
  if (me?.admin) {
    actions.push(["rename", t("Rename")]);
    if (d.frozen && me.root) actions.push(["unfreeze", t("Unfreeze")]);
    if (!d.self && d.admin && !d.root && !d.frozen && d.role === "full") actions.push(["freeze", t("Freeze"), true]);
    if (me.root && !d.admin && !d.frozen && d.role === "full") actions.push(["admin", t("Make it an admin")]);
    if (!d.self) actions.push(["remove", t("Remove"), true]);
  }
  pane.innerHTML = `<div class="detail-head">${glyph(d, 56)}<div><div class="name">${esc(d.name)}</div>` +
    `<div>${dot(d.online)} <span class="${d.online ? "" : "dim"}">${esc(d.online ? t("online") : t("offline"))}</span></div></div>` +
    `<button class="icon close" id="close" title="${esc(t("Close"))}" aria-label="${esc(t("Close"))}">${icon("close")}</button></div>` +
    `<div class="card">${lines.map(([k, v, mono]) => `<div class="line"><span class="dim">${esc(k)}</span><span class="value${mono ? " mono" : ""}">${esc(v)}</span></div>`).join("")}</div>` +
    // An admin sets the mode of a computer that is online; the phones and
    // lite members have no modes yet and refuse.
    (me?.admin && !d.self && d.online && d.role === "full"
      ? `<div class="card"><div class="dim small">${esc(t("Sync mode"))}</div><div class="segmented">${modeButtons(d.mode, d.id)}</div></div>` : "") +
    (me?.admin
      ? `<div class="card actions">${actions.map(([a, label, danger]) => `<button data-action="${a}"${danger ? ' class="danger"' : ""} ${state.busy ? "disabled" : ""}>${esc(label)}</button>`).join("")}</div>`
      : `<p class="dim small">${esc(t("This computer is no admin of the group: the phone or an admin computer adds and removes devices."))}</p>`);
}

// ask shows the confirmation dialog; it resolves to the typed text for a
// field, true for a plain yes, or null.
function ask(title, text, ok, field) {
  return new Promise((resolve) => {
    const dlg = $("confirm");
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    $("confirm-ok").textContent = ok;
    const input = $("confirm-input");
    input.hidden = field === undefined;
    input.value = field ?? "";
    dlg.onclose = () => resolve(dlg.returnValue === "ok" ? (field === undefined ? true : input.value) : null);
    dlg.returnValue = "";
    dlg.showModal();
    if (field !== undefined) input.select();
  });
}

async function act(method, ...args) {
  state.busy = true;
  render();
  try {
    await call(method, ...args);
  } catch (e) {
    console.error(method, e);
  }
  await refresh();
}

async function deviceAction(action) {
  const d = state.devices.find((x) => x.id === selected);
  if (!d) return;
  switch (action) {
    case "rename": {
      const name = await ask(t("Rename %s", d.name), t("Every device of the group shows the new name."), t("Rename"), d.name);
      if (name && name.trim()) await act("Rename", d.id, name.trim());
      break;
    }
    case "remove":
      if (await ask(t("Remove %s?", d.name), t("It will no longer sync with your devices. To add it again, pair it again."), t("Remove"))) await act("Remove", d.id);
      break;
    case "admin":
      if (await ask(t("Make %s an admin?", d.name), t("It can then add and remove devices with cbb pair and cbb revoke. Its key is a file on the computer, so do this only for a computer you keep safe."), t("Make it an admin"))) await act("MakeAdmin", d.id);
      break;
    case "freeze":
      if (await ask(t("Freeze %s?", d.name), t("For a stolen admin computer: it changes nothing more and the others refuse it until the root unfreezes or removes it."), t("Freeze"))) await act("Freeze", d.id);
      break;
    case "unfreeze":
      if (await ask(t("Unfreeze %s?", d.name), t("Unfreeze it only if it is in safe hands; otherwise remove it."), t("Unfreeze"))) await act("Unfreeze", d.id);
      break;
  }
}

// saving holds the last save, so that quick changes reach the service one
// after another and the last choice is the one kept.
let saving = Promise.resolve();

function saveSettings(change) {
  state.settings = { ...state.settings, ...change };
  applyTheme();
  render();
  renderSettings();
  const s = state.settings;
  saving = saving.then(() => call("SaveSettings", s)).catch((e) => console.error("settings", e));
  return saving;
}

function renderSettings() {
  const s = state.settings;
  $("swatches").innerHTML = colors.map((c) => {
    const dark = s.appearance === "dark" || (s.appearance !== "light" && darkQuery.matches);
    return `<button type="button" data-color="${c.name}" aria-checked="${c.name === s.color}" style="background:${(dark ? c.dark : c.light).accent}" ` +
      `title="${esc(t(c.name[0].toUpperCase() + c.name.slice(1)))}"></button>`;
  }).join("");
  for (const b of document.querySelectorAll("[data-appearance]")) b.setAttribute("aria-checked", String(b.dataset.appearance === s.appearance));
  $("details").checked = s.details ?? state.show_details;
  const mode = state.status?.group && !state.status.removed ? state.status.mode : "";
  $("mode-settings").hidden = !mode;
  $("modes").innerHTML = mode ? modeButtons(mode, "") : "";
  $("version").textContent = state.version;
}

async function refresh() {
  try {
    state = await call("State");
  } catch (e) {
    console.error("state", e);
    return;
  }
  await loadLanguage(state.lang);
  applyTheme();
  render();
}

document.addEventListener("click", async (e) => {
  const el = e.target.closest("button, input");
  if (!el || !state) return;
  if (el.dataset.layout) return saveSettings({ layout: el.dataset.layout });
  if (el.dataset.color) return saveSettings({ color: el.dataset.color });
  if (el.dataset.appearance) return saveSettings({ appearance: el.dataset.appearance });
  if (el.dataset.action) return deviceAction(el.dataset.action);
  if (el.dataset.menu) return openMenu(el.dataset.menu, el.dataset.level);
  if (el.dataset.filter) {
    filter = filter === el.dataset.filter ? null : el.dataset.filter;
    if (searching()) arranging = false;
    return render();
  }
  // In Arrange mode a tap does not open a tile.
  if (arranging && el.closest(".cell")) return;
  if (el.dataset.open) {
    opened = el.dataset.open;
    return render();
  }
  if (el.dataset.mode) {
    await act("SetMode", el.dataset.modeFor, el.dataset.mode);
    return renderSettings();
  }
  if (el.dataset.id) {
    selected = el.dataset.id;
    return render();
  }
  switch (el.id) {
    case "close": selected = null; return render();
    case "arrange": arranging = !arranging; return render();
    case "arrange-done": arranging = false; return render();
    case "arrange-reset": return arrange({ op: "reset" });
    case "collection-back": opened = null; arranging = false; return render();
    case "send": case "orbit-send": return act("Send");
    case "fetch": return act("Fetch");
    case "update": return act("Update");
    case "add": return $("add-dialog").showModal();
    case "settings": renderSettings(); return $("settings-dialog").showModal();
  }
});

$("away").addEventListener("change", async (e) => {
  e.preventDefault();
  const on = e.target.checked;
  e.target.checked = !on;
  if (on && !(await ask(t("Turn sync away from home on?"),
    t("This computer then reaches the group's hub from the internet through the group's own WireGuard tunnel, the clipboard encrypted end to end. Its keys are files: encrypt the disk, keep the service's folder out of unencrypted backups, and remove the computer at once if it is lost."),
    t("Turn on")))) return;
  await act("SetAway", on);
});

$("details").addEventListener("change", (e) => saveSettings({ details: e.target.checked }));
document.addEventListener("keydown", (e) => {
  if (document.querySelector("dialog[open]")) return;
  // Alt and the arrow keys move the focused tile in Arrange mode; Home and
  // End with Alt to the start and the end.
  const c = document.activeElement?.closest?.(".cell");
  if (arranging && c && e.altKey) {
    const steps = { ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1, Home: -Infinity, End: Infinity }[e.key];
    if (steps !== undefined) {
      e.preventDefault();
      const ref = c.dataset.ref;
      Promise.resolve(moveBy(ref, c.dataset.level, steps)).then(() => document.querySelector(`.cell[data-ref="${CSS.escape(ref)}"] button`)?.focus());
      return;
    }
  }
  if (e.key === "Escape" && arranging) {
    arranging = false;
    render();
  } else if (e.key === "Escape" && selected) {
    selected = null;
    render();
  } else if (e.key === "Escape" && opened) {
    opened = null;
    render();
  }
});
document.addEventListener("input", (e) => {
  if (e.target.id !== "search") return;
  query = e.target.value;
  if (searching()) arranging = false;
  render();
});
addEventListener("resize", () => state && state.settings.layout === "orbit" && render());

refresh();
// Not while a dialog is open or a tile is being dragged, which a redraw would drop.
setInterval(() => !document.querySelector("dialog[open]") && !dragging && refresh(), 4000);
