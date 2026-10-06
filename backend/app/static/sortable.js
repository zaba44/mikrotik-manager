/* Sortowanie tabel po kliknieciu w naglowek: <table class="sortable"> + <th data-sort="text|number">.
   Komorka moze podac wartosc do sortowania w data-sort-value (np. bajty zamiast „1.2 GB").

   Dwie poprawki wzgledem pierwszej wersji, obie wyszly przy monitorze WireGuard
   (200+ wierszy, auto-odswiezanie co 15 s):
   * numer kolumny brany z th.cellIndex, a nie z pozycji wsrod naglowkow sortowalnych —
     wystarczyl jeden naglowek bez data-sort w srodku, zeby sortowalo po zlej kolumnie;
   * HTMX podmienia tabele w calosci, wiec obsluga klikniec idzie przez delegacje, a wybrane
     sortowanie jest zapamietywane i przywracane po podmianie — inaczej kazde odswiezenie
     wracaloby do kolejnosci z serwera. */
(function () {
  // id tabeli -> { col, dir } — tylko tabele z id moga pamietac sortowanie miedzy podmianami
  const remembered = {};

  function apply(table, th, dir) {
    const tbody = table.querySelector("tbody");
    if (!tbody) return;
    const col = th.cellIndex;
    const type = th.dataset.sort;

    table.querySelectorAll("th[data-sort]").forEach((h) => {
      delete h.dataset.sortDir;
      const arrow = h.querySelector(".sort-arrow");
      if (arrow) arrow.remove();
    });
    th.dataset.sortDir = dir;
    const arrow = document.createElement("span");
    arrow.className = "sort-arrow";
    arrow.textContent = dir === "asc" ? " ▲" : " ▼";
    th.appendChild(arrow);

    const cellValue = (row) => {
      const cell = row.children[col];
      if (!cell) return "";
      return cell.dataset.sortValue !== undefined ? cell.dataset.sortValue : cell.textContent.trim();
    };

    const rows = Array.from(tbody.querySelectorAll("tr"));
    rows.sort((a, b) => {
      const valA = cellValue(a);
      const valB = cellValue(b);
      let cmp;
      if (type === "number") {
        cmp = parseFloat(valA || 0) - parseFloat(valB || 0);
      } else {
        cmp = valA.localeCompare(valB, "pl", { sensitivity: "base", numeric: true });
      }
      return dir === "asc" ? cmp : -cmp;
    });
    rows.forEach((row) => tbody.appendChild(row));

    if (table.id) remembered[table.id] = { col: col, dir: dir };
  }

  document.addEventListener("click", (e) => {
    const th = e.target.closest("table.sortable th[data-sort]");
    if (!th) return;
    const table = th.closest("table");
    apply(table, th, th.dataset.sortDir === "asc" ? "desc" : "asc");
  });

  document.body.addEventListener("htmx:afterSwap", () => {
    Object.keys(remembered).forEach((id) => {
      const table = document.getElementById(id);
      if (!table) return;
      const state = remembered[id];
      const th = table.querySelector("thead tr").children[state.col];
      if (th && th.dataset.sort) apply(table, th, state.dir);
    });
  });
})();
