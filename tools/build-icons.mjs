#!/usr/bin/env node
/**
 * build-icons.mjs — the PNG app icons of the web app manifest, drawn from favicon.svg.
 *
 * No dependencies: headless Chrome (tests/e2e/cdp.mjs) renders the SVG at each size and the PNG
 * comes from a screenshot. Maintainer tool, like build-wordlists.mjs: run it after changing
 * favicon.svg and commit icons/ (the site serves the files as they are).
 *
 *   icons/icon-192.png, icons/icon-512.png   the favicon as drawn (rounded square, transparent corners)
 *   icons/maskable-512.png                   full-bleed background, the mark inside the 80 % safe
 *                                            zone, for launchers that cut their own shape
 *   icons/apple-touch-icon.png               180 px, full bleed (iOS adds its own corners and has
 *                                            no transparency)
 *
 * Usage: node tools/build-icons.mjs [--browser chrome|edge]
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { launchBrowser } from '../tests/e2e/cdp.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(REPO, 'icons');

/**
 * The icons to draw: file name, pixel size, and whether the background fills the square
 * (`bleed`) with the mark scaled into the safe zone (`scale`).
 */
export const ICONS = Object.freeze([
  { file: 'icon-192.png', size: 192, bleed: false, scale: 1 },
  { file: 'icon-512.png', size: 512, bleed: false, scale: 1 },
  { file: 'maskable-512.png', size: 512, bleed: true, scale: 0.72 },
  { file: 'apple-touch-icon.png', size: 180, bleed: true, scale: 0.86 }
]);

/**
 * favicon.svg redrawn for one icon: a full-bleed variant drops the corner radius and shrinks the
 * mark around the centre so a circular or squircle mask never cuts it.
 * @param {string} svg favicon.svg source
 * @param {{ size: number, bleed: boolean, scale: number }} icon
 * @returns {string}
 */
export function iconSvg(svg, { size, bleed, scale }) {
  let out = svg.replace(/\swidth="\d+"/, ` width="${size}"`).replace(/\sheight="\d+"/, ` height="${size}"`);
  if (!bleed) return out;
  out = out.replace(/<rect([^>]*?)\srx="[^"]*"/, '<rect$1');
  const c = 16 * (1 - scale);
  return out.replace(/<g\s/, `<g transform="translate(${c} ${c}) scale(${scale})" `);
}

async function main(argv) {
  const i = argv.indexOf('--browser');
  const browser = await launchBrowser({ browser: i !== -1 ? argv[i + 1] : 'auto' });
  try {
    const svg = await readFile(path.join(REPO, 'favicon.svg'), 'utf8');
    await mkdir(OUT, { recursive: true });
    for (const icon of ICONS) {
      const page = await browser.newPage('about:blank', { width: icon.size, height: icon.size, deviceScaleFactor: 1 });
      await page.send('Emulation.setDefaultBackgroundColorOverride', { color: { r: 0, g: 0, b: 0, a: 0 } });
      const html = `<!doctype html><html><head><style>html,body{margin:0;background:transparent}svg{display:block}</style></head><body>${iconSvg(svg, icon)}</body></html>`;
      await page.goto(`data:text/html;base64,${Buffer.from(html).toString('base64')}`);
      const { data } = await page.send('Page.captureScreenshot', {
        format: 'png', clip: { x: 0, y: 0, width: icon.size, height: icon.size, scale: 1 }
      });
      await writeFile(path.join(OUT, icon.file), Buffer.from(data, 'base64'));
      await page.close();
      process.stdout.write(`icons/${icon.file} (${icon.size}×${icon.size})\n`);
    }
  } finally {
    await browser.close();
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`build-icons: ${err.message || err}\n`);
    process.exitCode = 1;
  });
}
