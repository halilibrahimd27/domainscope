/*
 * boot.js — tiny classic (non-module) script loaded synchronously in <head>.
 *
 * 1. Applies the saved theme and language to <html> before the first paint, so a
 *    manually chosen dark theme never flashes white (the CSP forbids inline scripts),
 *    and links the web app manifest of that language.
 * 2. If the ES-module app has not signalled readiness (html[data-app-ready]) after a
 *    while — very old browser, blocked script, failed download — replaces the loading
 *    indicator with a readable message instead of spinning forever.
 *
 * Must stay ES5-compatible and must never throw.
 */
(function () {
  'use strict';
  var root = document.documentElement;
  var settings = null;
  try {
    settings = JSON.parse(window.localStorage.getItem('ssds.settings') || 'null');
  } catch (e) {
    settings = null;
  }
  var theme = settings && settings.theme;
  if (theme === 'light' || theme === 'dark') root.setAttribute('data-theme', theme);

  var nav = (window.navigator && (navigator.languages && navigator.languages[0] || navigator.language)) || '';
  var lang = settings && (settings.lang === 'tr' || settings.lang === 'en')
    ? settings.lang
    : (String(nav).toLowerCase().indexOf('tr') === 0 ? 'tr' : 'en');
  root.setAttribute('lang', lang);
  // The installed app's name and shortcuts in the UI language (app.js keeps it in step later).
  var manifest = document.querySelector('link[rel="manifest"]');
  if (manifest && lang === 'tr') manifest.setAttribute('href', 'manifest.tr.webmanifest');

  var supportsModules = 'noModule' in document.createElement('script');

  function showFailure() {
    if (root.hasAttribute('data-app-ready')) return;
    var box = document.getElementById('boot-status');
    if (!box) return;
    while (box.firstChild) box.removeChild(box.firstChild);
    box.className = 'noscript';
    box.setAttribute('role', 'alert');
    var msg = lang === 'tr'
      ? (supportsModules
        ? 'Uygulama başlatılamadı. Sayfayı yenileyin; sorun sürerse güncel bir tarayıcı (Chrome, Edge, Firefox, Safari) kullanın ve eklentilerin betikleri engellemediğinden emin olun.'
        : 'Bu tarayıcı çok eski. Lütfen güncel bir tarayıcı (Chrome, Edge, Firefox, Safari) kullanın.')
      : (supportsModules
        ? 'The app could not start. Reload the page; if it keeps failing, use an up-to-date browser (Chrome, Edge, Firefox, Safari) and make sure no extension blocks scripts.'
        : 'This browser is too old. Please use an up-to-date browser (Chrome, Edge, Firefox, Safari).');
    box.appendChild(document.createTextNode(msg));
  }

  if (!supportsModules) {
    document.addEventListener('DOMContentLoaded', showFailure);
  } else {
    window.setTimeout(function () {
      if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', showFailure);
      else showFailure();
    }, 15000);
  }
})();
