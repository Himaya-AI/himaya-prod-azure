#!/usr/bin/env node
/**
 * Headless validation of the Data Posture map's country-shading config.
 *
 * Locks in the jsvectormap@1.7 series.regions[] API we use in
 * frontend/src/app/(dashboard)/saas-security/page.tsx so a future
 * refactor can't silently break the country fills again.
 *
 * Background: turn 4 used a top-level `regions:` key which jsvectormap
 * silently drops, and pushed hex colors directly instead of going
 * through a `scale` map. Series.setValues always calls
 * scale.getValue(value), so without scale the fills never applied.
 * This script reproduces the exact config we ship and asserts that
 * known ISO-2 codes end up with the right hex fill.
 *
 * Run: cd frontend && npm i -D jsdom@26 && node ../scripts/validate_data_posture_map.mjs
 * Exit code 0 = pass, 1 = fail.
 */
import { JSDOM } from 'jsdom';

const dom = new JSDOM(
  '<!DOCTYPE html><html><body><div id="map" style="width:1200px;height:640px"></div></body></html>',
  { pretendToBeVisual: true },
);
global.window = dom.window;
global.document = dom.window.document;
global.HTMLElement = dom.window.HTMLElement;
global.Node = dom.window.Node;
global.Element = dom.window.Element;
global.SVGElement = dom.window.SVGElement;
global.SVGSVGElement = dom.window.SVGSVGElement;
global.requestAnimationFrame = (cb) => setTimeout(cb, 0);

const { default: jsVectorMap } = await import('jsvectormap');
// The world.js map file does `jsVectorMap.addMap(...)` at evaluation
// time, so jsVectorMap must be on globalThis before we import it.
global.jsVectorMap = jsVectorMap;
window.jsVectorMap = jsVectorMap;
await import('jsvectormap/dist/maps/world.js');

// Mirrors SENSITIVITY_COLOR in page.tsx.
const SENSITIVITY_COLOR = {
  highly_confidential: '#ef4444',
  confidential:        '#f59e0b',
  internal:            '#3b6ef6',
  public:              '#10b981',
  unknown:             '#3f3f46',
};

new jsVectorMap({
  selector: '#map',
  map: 'world',
  series: {
    regions: [{
      attribute: 'fill',
      values: {
        US: 'highly_confidential',
        GB: 'confidential',
        DE: 'confidential',
        IN: 'internal',
        BR: 'public',
      },
      scale: SENSITIVITY_COLOR,
    }],
  },
});

// jsvectormap renders synchronously but defers some style writes one
// tick; wait briefly so the path fills are applied.
await new Promise((r) => setTimeout(r, 200));

const els = document.querySelectorAll('#map path');
const got = {};
els.forEach((el) => {
  const code = el.getAttribute('data-code');
  if (!code) return;
  if (!['US', 'GB', 'DE', 'IN', 'BR'].includes(code)) return;
  got[code] = (el.style.fill || el.getAttribute('fill') || '').toLowerCase();
});

const expected = {
  US: SENSITIVITY_COLOR.highly_confidential.toLowerCase(),
  GB: SENSITIVITY_COLOR.confidential.toLowerCase(),
  DE: SENSITIVITY_COLOR.confidential.toLowerCase(),
  IN: SENSITIVITY_COLOR.internal.toLowerCase(),
  BR: SENSITIVITY_COLOR.public.toLowerCase(),
};

let ok = true;
console.log(`Total path elements: ${els.length}`);
for (const [code, want] of Object.entries(expected)) {
  const have = got[code] || '(unfilled)';
  const pass = have.includes(want.replace('#', ''));
  console.log(`${code}: ${have} ${pass ? 'OK' : `FAIL (want ${want})`}`);
  if (!pass) ok = false;
}

if (ok) {
  console.log('\n\u2705 PASS: Data Posture map country shading is wired correctly');
  process.exit(0);
} else {
  console.log('\n\u274c FAIL: country shading did NOT apply \u2014 check series.regions/scale wiring');
  process.exit(1);
}
