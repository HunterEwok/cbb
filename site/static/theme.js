// SPDX-License-Identifier: AGPL-3.0-only
//
// Puts the reader's theme on <html> before the page is drawn, so a light
// page never flashes dark. It is all that runs before drawing; site.js,
// deferred, does the rest.
"use strict";
(function () {
  var choice = "";
  try { choice = localStorage.getItem("cbb-theme") || ""; } catch (e) { /* nothing kept */ }
  if (choice === "light" || choice === "dark") document.documentElement.setAttribute("data-theme", choice);
})();
