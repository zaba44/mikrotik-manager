/* Efekty wizualne portalu: konstelacja sieci w tle (canvas), spotlight + 3D tilt
   na kartach, animacja liczników KPI, przycisk "Kopiuj" na blokach kodu.
   Wszystko degraduje się czysto: bez JS strona działa, przy prefers-reduced-motion
   animacje są wyłączone. */
(function () {
  "use strict";

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---- konstelacja sieci w tle ---- */
  const canvas = document.getElementById("bg-net");
  if (canvas && !reduced) {
    const ctx = canvas.getContext("2d");
    const LINK_DIST = 150;
    let w, h, raf = null;
    const nodes = [];

    function spawn() {
      return {
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.22,
        vy: (Math.random() - 0.5) * 0.22,
        r: 1 + Math.random() * 1.4,
      };
    }

    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = window.innerWidth;
      h = window.innerHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const target = Math.min(90, Math.round((w * h) / 24000));
      while (nodes.length < target) nodes.push(spawn());
      nodes.length = target;
    }

    function step() {
      ctx.clearRect(0, 0, w, h);

      for (const n of nodes) {
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < -20) n.x = w + 20;
        else if (n.x > w + 20) n.x = -20;
        if (n.y < -20) n.y = h + 20;
        else if (n.y > h + 20) n.y = -20;
      }

      ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < LINK_DIST * LINK_DIST) {
            const alpha = 0.15 * (1 - Math.sqrt(d2) / LINK_DIST);
            ctx.strokeStyle = "rgba(110, 150, 255, " + alpha.toFixed(3) + ")";
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      ctx.fillStyle = "rgba(140, 190, 255, 0.55)";
      for (const n of nodes) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fill();
      }

      raf = requestAnimationFrame(step);
    }

    resize();
    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        cancelAnimationFrame(raf);
        raf = null;
      } else if (!raf) {
        raf = requestAnimationFrame(step);
      }
    });
    raf = requestAnimationFrame(step);
  }

  /* ---- spotlight (--mx/--my) + 3D tilt (--rx/--ry) na kartach ---- */
  function bindCards(root) {
    const scope = root.querySelectorAll ? root : document;
    scope.querySelectorAll(".glow-card, .tilt").forEach((card) => {
      if (card._fxBound) return;
      card._fxBound = true;

      card.addEventListener("pointermove", (e) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        if (card.classList.contains("glow-card")) {
          card.style.setProperty("--mx", x + "px");
          card.style.setProperty("--my", y + "px");
        }
        if (!reduced && card.classList.contains("tilt")) {
          const rx = (y / rect.height - 0.5) * -5;
          const ry = (x / rect.width - 0.5) * 5;
          card.style.setProperty("--rx", rx.toFixed(2) + "deg");
          card.style.setProperty("--ry", ry.toFixed(2) + "deg");
          card.style.setProperty("--lift", "-2px");
        }
      });

      card.addEventListener("pointerleave", () => {
        card.style.setProperty("--rx", "0deg");
        card.style.setProperty("--ry", "0deg");
        card.style.setProperty("--lift", "0");
      });
    });
  }

  /* ---- animacja liczników KPI ---- */
  function countUp() {
    if (reduced) return;
    document.querySelectorAll(".stat-value[data-count]").forEach((el) => {
      if (el._fxDone) return;
      el._fxDone = true;
      const target = parseInt(el.dataset.count, 10) || 0;
      const t0 = performance.now();
      const dur = 900;
      function tick(t) {
        const p = Math.min(1, (t - t0) / dur);
        el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
        if (p < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    });
  }

  /* ---- "Kopiuj" na blokach kodu (skrypty RouterOS do Winboksa) ---- */
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".copy-btn");
    if (!btn) return;
    const block = btn.closest(".code-block");
    // <pre> w skryptach RouterOS, <textarea> w edytowalnym configu WireGuard — przy tym
    // drugim liczy sie to, co uzytkownik wlasnie poprawil, czyli .value, nie textContent.
    const src = block && block.querySelector("pre, textarea");
    if (!src) return;
    const text = src.tagName === "TEXTAREA" ? src.value : src.textContent;
    navigator.clipboard.writeText(text).then(() => {
      const old = btn.textContent;
      btn.classList.add("copied");
      btn.textContent = "Skopiowano ✓";
      setTimeout(() => {
        btn.classList.remove("copied");
        btn.textContent = old;
      }, 1600);
    });
  });

  bindCards(document);
  countUp();

  /* HTMX podmienia fragmenty — dowiąż efekty na nowych elementach */
  document.body.addEventListener("htmx:afterSwap", (e) => bindCards(e.target));
})();
