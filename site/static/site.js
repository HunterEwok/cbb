// SPDX-License-Identifier: AGPL-3.0-only
//
// The site's script, deferred: theme.js has put the reader's theme on
// <html> before the page was drawn. This wires the theme button, adds a
// copy button to each command, draws the chalk of each board as it first
// comes into view and then lets it move a little now and then, and, on the
// download page, points at the reader's own system. Without it the site
// works as before: the theme follows the system, the drawings are simply
// there and every way to download is shown.
"use strict";
(function () {
  var root = document.documentElement;
  var KEY = "cbb-theme"; // "light" or "dark"; nothing stored means "as the system"
  function stored() {
    try { return localStorage.getItem(KEY) || ""; } catch (e) { return ""; }
  }
  function apply(choice) {
    if (choice === "light" || choice === "dark") root.setAttribute("data-theme", choice);
    else root.removeAttribute("data-theme");
  }

  // The reader's system, from the browser: "android", "iphone", "windows",
  // "mac", "linux", or "" when it cannot tell.
  function system() {
    var ua = navigator.userAgent || "";
    var p = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
    if (/android/i.test(ua)) return "android";
    if (/iphone|ipad|ipod/i.test(ua) || (/mac/i.test(p) && navigator.maxTouchPoints > 1)) return "iphone";
    if (/win/i.test(p) || /windows/i.test(ua)) return "windows";
    if (/mac/i.test(p)) return "mac";
    if (/linux|x11|cros/i.test(p + ua)) return "linux";
    return "";
  }

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.querySelector(".theme");
    if (button) {
      var order = ["", "light", "dark"];
      var show = function (choice) {
        button.setAttribute("data-choice", choice || "auto");
        var label = button.getAttribute("data-" + (choice || "auto"));
        button.setAttribute("aria-label", label);
        button.title = label;
      };
      show(stored());
      button.hidden = false;
      button.addEventListener("click", function () {
        var next = order[(order.indexOf(stored()) + 1) % order.length];
        try {
          if (next) localStorage.setItem(KEY, next); else localStorage.removeItem(KEY);
        } catch (e) { /* a browser that keeps nothing still switches for this page */ }
        apply(next);
        show(next);
      });
    }

    // A button on each command that copies it.
    var main = document.querySelector("main");
    if (main && navigator.clipboard) {
      document.querySelectorAll("pre > code").forEach(function (code) {
        var copy = document.createElement("button");
        copy.type = "button";
        copy.className = "copy";
        copy.textContent = main.getAttribute("data-copy");
        copy.addEventListener("click", function () {
          navigator.clipboard.writeText(code.textContent).then(function () {
            copy.textContent = main.getAttribute("data-copied");
            setTimeout(function () { copy.textContent = main.getAttribute("data-copy"); }, 1800);
          });
        });
        code.parentNode.appendChild(copy);
      });
    }

    // Each board but the first, drawing, table or commands, is written in
    // chalk once, as it first comes into view.
    var lively = window.matchMedia && window.matchMedia("(prefers-reduced-motion: no-preference)").matches;
    // Until when the chalk's grain holds still: while a board is being
    // drawn and while the page scrolls, so that the browser does not filter
    // every board again at the same time and the motion stays smooth.
    var still = 0;
    var hold = function (ms) { still = Math.max(still, Date.now() + ms); };
    if ("IntersectionObserver" in window) {
      var boards = new IntersectionObserver(function (seen) {
        seen.forEach(function (e) {
          if (e.isIntersecting) {
            e.target.classList.add("drawn");
            boards.unobserve(e.target);
            hold(1100);
            if (lively) setTimeout(function (f) { f.classList.add("alive"); }, 1550, e.target);
          }
        });
      }, { threshold: 0.3 });
      document.querySelectorAll(".frame:not(.hero-board)").forEach(function (f) {
        boards.observe(f);
      });
      root.classList.add("draw");
    }

    // Then the chalk comes alive a little: each drawn board moves now and
    // then (the stylesheet says how), and the chalk's grain shifts a few
    // times a second while a board is on the screen, as in a hand-drawn
    // film. Not for those who ask for less motion.
    if (lively) {
      var hero = document.querySelector(".hero-board");
      if (hero) setTimeout(function () { hero.classList.add("alive"); }, 2250);
      hold(1700);
      window.addEventListener("scroll", function () { hold(250); }, { passive: true });
      var grain = document.querySelectorAll("#chalk feTurbulence, #chalk-words feTurbulence");
      var warp = document.querySelector("#chalk feDisplacementMap");
      var seen = 0, step = 0, shown = [];
      if ("IntersectionObserver" in window) {
        var watch = new IntersectionObserver(function (es) {
          es.forEach(function (e) {
            var i = shown.indexOf(e.target);
            if (e.isIntersecting && i < 0) shown.push(e.target);
            if (!e.isIntersecting && i >= 0) shown.splice(i, 1);
          });
          seen = shown.length;
        });
        document.querySelectorAll(".frame").forEach(function (f) { watch.observe(f); });
      }
      setInterval(function () {
        if (!seen || document.hidden || Date.now() < still) return;
        step = (step + 1) % 3;
        grain.forEach(function (t, i) { t.setAttribute("seed", [3, 7, 11][step] + i * 18); });
        if (warp) warp.setAttribute("scale", [1.4, 1.9, 1.6][step]);
      }, 220);
    }

    // The download page: the reader's own system first, with its own button.
    var os = system();
    var pick = os && document.querySelector('.pick [data-os~="' + os + '"]');
    if (pick) {
      pick.hidden = false;
      pick.parentNode.hidden = false;
      var part = document.querySelector('.card[data-os~="' + os + '"], .os[data-os~="' + os + '"]');
      if (part) {
        part.classList.add("mine");
        part.parentNode.insertBefore(part, part.parentNode.firstElementChild);
      }
    }
  });
})();
