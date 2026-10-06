/* Klientowe wyszukiwanie/filtrowanie list — bez round-tripu do backendu (flota to
   kilkadziesiąt urządzeń, filtrowanie w przeglądarce jest natychmiastowe).
   Użycie: <input data-filter="<selektor elementów>" [data-filter-empty="<selektor
   komunikatu pustego>"]>. Elementy niepasujące dostają display:none. */
(function () {
  "use strict";

  const inputs = [];

  function apply(input) {
    const sel = input.getAttribute("data-filter");
    if (!sel) return;
    const q = input.value.trim().toLowerCase();
    let visible = 0;
    document.querySelectorAll(sel).forEach((el) => {
      const match = !q || el.textContent.toLowerCase().indexOf(q) !== -1;
      el.style.display = match ? "" : "none";
      if (match) visible++;
    });
    const emptySel = input.getAttribute("data-filter-empty");
    if (emptySel) {
      const empty = document.querySelector(emptySel);
      if (empty) empty.style.display = q && visible === 0 ? "" : "none";
    }
  }

  function bind() {
    document.querySelectorAll("[data-filter]").forEach((input) => {
      if (input._filterBound) return;
      input._filterBound = true;
      inputs.push(input);
      input.addEventListener("input", () => apply(input));
    });
  }

  bind();

  /* HTMX podmienia fragmenty (np. lista lokalizacji) — dowiąż i przefiltruj ponownie */
  document.body.addEventListener("htmx:afterSwap", () => {
    bind();
    inputs.forEach(apply);
  });
})();
