/* ── WSTS landing page — release metadata loader ──────────────────────────
   Populates download link, version, filename, size, SHA-256 hash and the
   VirusTotal link from a single JSON manifest published with each release.
   Strict-CSP friendly: external file, no inline handlers, no eval.        */

(function () {
  "use strict";

  // Fields with a sensible fallback already baked into the HTML, so the page
  // is fully usable even if the manifest fetch fails.
  function applyManifest(m) {
    if (!m || typeof m !== "object") return;

    setText('[data-field="version"]', m.version);
    setText('[data-field="filename"]', m.filename);
    setText('[data-field="filesize"]', m.filesize);
    setText('[data-field="sha256"]', m.sha256);

    setHref('[data-field="download-link"]', m.download_url);
    setHref('[data-field="vt-link"]', m.virustotal_url);
  }

  function setText(selector, value) {
    if (value == null) return;
    document.querySelectorAll(selector).forEach(function (el) {
      el.textContent = String(value);
    });
  }

  function setHref(selector, value) {
    if (!value) return;
    // Only accept absolute https URLs or root-relative paths — defensive
    // against a tampered manifest injecting javascript: or data: URIs.
    var ok = /^https:\/\//i.test(value) || /^\//.test(value);
    if (!ok) return;
    document.querySelectorAll(selector).forEach(function (el) {
      el.setAttribute("href", value);
    });
  }

  // Manifest lives next to the page; refreshed by the build/deploy script.
  fetch("/downloads/release.json", { cache: "no-store" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(applyManifest)
    .catch(function () { /* keep baked-in fallbacks */ });
})();
