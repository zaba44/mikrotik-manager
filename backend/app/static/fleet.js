/* Strona Flota: zaznaczanie urzadzen w tabeli i potwierdzenie akcji z liczba urzadzen. */
(function () {
    var form = document.getElementById("fleet-form");
    if (!form) return;
    var count = document.getElementById("fleet-count");
    var select = document.getElementById("fleet-action");
    var hint = document.getElementById("fleet-action-hint");
    function boxes() { return Array.prototype.slice.call(form.querySelectorAll('input[name="device_ids"]')); }
    function checked() { return boxes().filter(function (b) { return b.checked; }); }
    function refresh() { count.textContent = "zaznaczono " + checked().length; }
    function visible(box) { return box.closest("tr").style.display !== "none"; }

    form.addEventListener("change", function (e) {
        if (e.target.name === "device_ids") refresh();
        if (e.target === select) {
            var opt = select.options[select.selectedIndex];
            hint.textContent = opt && opt.value ? opt.title : "";
        }
    });
    form.querySelector("[data-fleet-all]").addEventListener("click", function () {
        boxes().forEach(function (b) { if (visible(b)) b.checked = true; });
        refresh();
    });
    form.querySelector("[data-fleet-none]").addEventListener("click", function () {
        boxes().forEach(function (b) { b.checked = false; });
        refresh();
    });
    document.querySelectorAll("[data-fleet-pick]").forEach(function (btn) {
        btn.addEventListener("click", function () {
            var ids = btn.getAttribute("data-fleet-pick").split(",");
            boxes().forEach(function (b) { b.checked = ids.indexOf(b.value) !== -1; });
            refresh();
            form.scrollIntoView({ behavior: "smooth" });
        });
    });
    form.addEventListener("submit", function (e) {
        var n = checked().length, opt = select.options[select.selectedIndex];
        if (!n || !opt || !opt.value) {
            e.preventDefault();
            hint.textContent = !n ? "Zaznacz przynajmniej jedno urządzenie." : "Wybierz akcję.";
            return;
        }
        var text = opt.getAttribute("data-confirm-text") + " — liczba urządzeń: " + n + "?";
        if (!window.confirm(text)) e.preventDefault();
    });
    refresh();
})();
