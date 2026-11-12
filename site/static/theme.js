// SPDX-License-Identifier: AGPL-3.0-only
//
// Puts the reader's theme on <html> before the page is drawn, so a light
// page never flashes dark, and turns on the look they picked (the blueprint,
// or the chalkboard: one stylesheet or the other). It is all that runs before
// drawing; site.js, deferred, does the rest.
"use strict";
(function () {
  var choice = "";
  try { choice = localStorage.getItem("cbb-theme") || ""; } catch (e) { /* nothing kept */ }
  if (choice === "light" || choice === "dark") document.documentElement.setAttribute("data-theme", choice);
  var look = "";
  try { look = localStorage.getItem("cbb-look") || ""; } catch (e) { /* nothing kept */ }
  if (look === "board") {
    document.documentElement.setAttribute("data-look", "board");
    var ink = document.getElementById("look-ink"), board = document.getElementById("look-board");
    if (ink && board) { board.media = "all"; ink.media = "not all"; }
  }
})();
