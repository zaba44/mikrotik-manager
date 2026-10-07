/* Podglad aktualizacji portalu na zywo (Ustawienia -> O portalu).
 *
 * W trakcie aktualizacji backend jest odtwarzany, wiec przez kilkanascie sekund zapytania
 * koncza sie bledem — to oczekiwane, ponawiamy. Koniec rozpoznajemy po tym, ze ODPOWIADA
 * juz backend z nowym numerem wersji (sam stan uslugi aktualizacji to za malo: mowi tylko,
 * ze kontenery wstaly). Potem przeladowanie strony, zeby pokazac nowa wersje w calosci. */
(function () {
    var box = document.getElementById("update-progress");
    if (!box || box.dataset.state !== "running") return;
    var log = document.getElementById("update-log");
    var head = document.getElementById("update-headline");
    var target = box.dataset.target;
    var misses = 0;

    function tick() {
        fetch("/settings/about/status", {credentials: "same-origin", cache: "no-store"})
            .then(function (r) {
                if (r.redirected || !r.ok) throw new Error("http " + r.status);
                return r.json();
            })
            .then(function (s) {
                misses = 0;
                var u = s.updater;
                if (u && u.log) { log.textContent = u.log.join("\n"); log.scrollTop = log.scrollHeight; }
                if (s.portal_version === target) {
                    head.textContent = "Zaktualizowano do " + target + ". Przeładowuję stronę…";
                    setTimeout(function () { location.reload(); }, 2500);
                    return;
                }
                if (u && u.state === "failed") {
                    head.textContent = "Aktualizacja do " + target + " nie powiodła się: " + (u.error || "?");
                    return;
                }
                setTimeout(tick, 3000);
            })
            .catch(function () {
                misses += 1;
                head.textContent = "Aktualizacja do " + target + " trwa — portal się restartuje (" + misses + ")…";
                setTimeout(tick, 3000);
            });
    }
    setTimeout(tick, 2000);
})();
