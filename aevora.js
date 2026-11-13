// (2026-11-14) Latar ÆVORA: awan badai keemasan, cincin emas berdetik, dan bara yang naik pelan.
// Dipasang sekali di belakang konten; tidak menyentuh data atau logika halaman.
(() => {
  "use strict";
  if (document.querySelector(".aev-sky")) return;
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const NS = "http://www.w3.org/2000/svg";

  const awan = (id, freq, oct, seed, matrix, mask) => `
    <svg class="awan ${id}" viewBox="0 0 1600 1000" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
      <defs>
        <filter id="f-${id}" x="0" y="0" width="100%" height="100%" color-interpolation-filters="sRGB">
          <feTurbulence type="fractalNoise" baseFrequency="${freq}" numOctaves="${oct}" seed="${seed}" result="n"/>
          <feColorMatrix in="n" type="matrix" values="${matrix}"/>
        </filter>
        ${mask}
      </defs>
      <rect width="1600" height="1000" filter="url(#f-${id})" ${mask ? `mask="url(#m-${id})"` : ""}/>
    </svg>`;

  // lapis 1: awan badai coklat gelap dengan tepi bercahaya emas
  const m1 = "0 0 0 0 0.36  0 0 0 0 0.22  0 0 0 0 0.09  2.8 0 0 0 -1.05";
  // lapis 1b: sorot emas di punggung awan
  const m1b = "0 0 0 0 1.0  0 0 0 0 0.74  0 0 0 0 0.36  4.2 0 0 0 -2.45";
  // lapis 2: awan krem terang di sisi kiri & kanan (seperti loading screen)
  const m2 = "0 0 0 0 1.0  0 0 0 0 0.93  0 0 0 0 0.80  3.4 0 0 0 -1.35";
  const mask2 = `
    <linearGradient id="g-lapis2" x1="0" x2="1" y1="0" y2="0">
      <stop offset="0" stop-color="#fff"/><stop offset="0.2" stop-color="#bbb"/><stop offset="0.36" stop-color="#000"/>
      <stop offset="0.64" stop-color="#000"/><stop offset="0.8" stop-color="#bbb"/><stop offset="1" stop-color="#fff"/>
    </linearGradient>
    <mask id="m-lapis2"><rect width="1600" height="1000" fill="url(#g-lapis2)"/></mask>`;

  // cincin emas dengan garis detik, mirip lingkaran di belakang avatar loading screen
  let detik = "";
  for (let i = 0; i < 120; i++) {
    const a = (i / 120) * Math.PI * 2, panjang = i % 10 === 0 ? 16 : (i % 5 === 0 ? 10 : 5);
    const r1 = 452, r2 = r1 + panjang;
    detik += `<line x1="${500 + Math.cos(a) * r1}" y1="${500 + Math.sin(a) * r1}" x2="${500 + Math.cos(a) * r2}" y2="${500 + Math.sin(a) * r2}"/>`;
  }
  let serpih = "";
  for (let i = 0; i < 46; i++) {
    const a = Math.random() * Math.PI * 2, r = 250 + Math.random() * 260, p = 4 + Math.random() * 10;
    serpih += `<line x1="${500 + Math.cos(a) * r}" y1="${500 + Math.sin(a) * r}" x2="${500 + Math.cos(a) * (r + p)}" y2="${500 + Math.sin(a) * (r + p)}" stroke-opacity="${(0.35 + Math.random() * 0.55).toFixed(2)}"/>`;
  }
  const cincin = `
    <div class="cincin"><svg viewBox="0 0 1000 1000" aria-hidden="true" fill="none" stroke="#e8be5c" stroke-linecap="round">
      <circle cx="500" cy="500" r="490" stroke-opacity=".28" stroke-width="1"/>
      <circle cx="500" cy="500" r="430" stroke-opacity=".55" stroke-width="1.2"/>
      <circle cx="500" cy="500" r="330" stroke-opacity=".22" stroke-width="1"/>
      <g class="putar" stroke-opacity=".6" stroke-width="1.4">${detik}</g>
      <g class="putarBalik" stroke-width="2">${serpih}</g>
    </svg></div>`;

  const sky = document.createElement("div");
  sky.className = "aev-sky";
  sky.setAttribute("aria-hidden", "true");
  sky.innerHTML =
    awan("lapis1", "0.0055 0.0095", 6, 7, m1, "") +
    awan("lapis1b", "0.0055 0.0095", 6, 7, m1b, "") +
    awan("lapis2", "0.0048 0.0085", 6, 23, m2, mask2) +
    cincin + '<div class="vignette"></div>';

  if (!reduce) {
    const n = window.innerWidth < 600 ? 14 : 28;
    for (let i = 0; i < n; i++) {
      const b = document.createElement("span");
      b.className = "bara";
      const s = 2 + Math.random() * 3;
      b.style.cssText = `left:${(Math.random() * 100).toFixed(1)}%;width:${s}px;height:${s}px;` +
        `animation-duration:${(14 + Math.random() * 18).toFixed(1)}s;animation-delay:${(-Math.random() * 30).toFixed(1)}s;` +
        `--dx:${(Math.random() * 120 - 60).toFixed(0)}px`;
      sky.appendChild(b);
    }
  }
  document.body.prepend(sky);
})();
