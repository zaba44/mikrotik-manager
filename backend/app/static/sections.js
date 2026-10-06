/* Rozwijane sekcje strony urzadzenia.
 *
 * Strona urzadzenia rosla z kazda faza (status, kondycja, kopie, aktualizacje, syslog,
 * powiadomienia, dzierzawy, adresy...) i przestala miescic sie na ekranie. Zwijamy ja,
 * ale samo zwijanie zamienia przewijanie na klikanie na oslep — dlatego naglowki zwinietych
 * sekcji nosza podsumowanie, a stan otwarcia jest zapamietywany.
 *
 * Uzywamy natywnych <details>/<summary>: dzialaja bez JS, obsluguja klawiature i czytniki
 * ekranu za darmo. Ten plik dokłada tylko trzy rzeczy, ktorych natywnie nie ma.
 */
(function () {
    var KEY = "mtm.sec.";

    /* 1. Przyciski i formularze w naglowku nie moga zwijac sekcji.
     *
     * <details> reaguje na klikniecie, ktore DOBIJE do <summary> — wystarczy wiec zatrzymac
     * propagacje na kontrolce. Swiadomie NIE uzywamy preventDefault(): ono anulowaloby tez
     * wlasciwe dzialanie przycisku (wyslanie formularza), bo to ta sama akcja domyslna. */
    function guard(root) {
        root.querySelectorAll("summary button, summary a, summary form, summary input, summary select")
            .forEach(function (el) {
                if (el.dataset.secGuarded) return;
                el.dataset.secGuarded = "1";
                el.addEventListener("click", function (e) { e.stopPropagation(); });
            });
    }

    /* 2. Zawartosc pobierana dopiero przy rozwinieciu.
     *
     * Fragmenty czekaja na zdarzenie `sec-open` (hx-trigger="sec-open once") zamiast na
     * `load`. Bez tego wejscie na strone odpalalo kilkanascie zapytan REST do routera naraz.
     * Nie uzywamy htmx-owego `revealed`, bo ono opiera sie na przewijaniu — otwarcie sekcji
     * bez ruszenia strony moglo go nie wyzwolic. */
    function wake(details) {
        if (!window.htmx) return;
        details.querySelectorAll("[hx-trigger~='sec-open']").forEach(function (el) {
            if (el.dataset.secWoken) return;
            el.dataset.secWoken = "1";
            // htmx.process() jest idempotentne, a gwarantuje, ze element ma juz podpiete
            // nasluchiwanie — bez tego wyzwolone zdarzenie trafialoby w prozne miejsce.
            window.htmx.process(el);
            window.htmx.trigger(el, "sec-open");
        });
    }

    function remember(details) {
        try { localStorage.setItem(KEY + details.dataset.sec, details.open ? "1" : "0"); } catch (e) { }
    }

    /* 3. Stan zapamietany miedzy wizytami: kto zawsze rozwija kopie zapasowe, ma je
     *    rozwiniete takze na kolejnym urzadzeniu. Atrybut `open` w szablonie jest wylacznie
     *    wartoscia POCZATKOWA — obowiazuje przy pierwszej wizycie. */
    function init() {
        var all = document.querySelectorAll("details.sec[data-sec]");
        if (!all.length) return;

        all.forEach(function (d) {
            var saved = null;
            try { saved = localStorage.getItem(KEY + d.dataset.sec); } catch (e) { }
            if (saved === "1") d.open = true;
            else if (saved === "0") d.open = false;

            guard(d);
            if (d.open) wake(d);
            d.addEventListener("toggle", function () {
                remember(d);
                if (d.open) wake(d);
            });
        });

        document.querySelectorAll("[data-sections-all]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var open = btn.dataset.sectionsAll === "open";
                document.querySelectorAll("details.sec[data-sec]").forEach(function (d) {
                    d.open = open;   // zdarzenie `toggle` zajmie sie zapisem i doładowaniem
                });
            });
        });
    }

    /* Kolejnosc ma tu znaczenie i kosztowala pierwsza wersje dzialania: skrypt ladowany
     * z `defer` wykonuje sie, gdy readyState to juz "interactive", ale PRZED zdarzeniem
     * DOMContentLoaded — a htmx dopiero na nim przetwarza dokument. Uruchomienie init()
     * od razu wyzwalalo `sec-open` zanim htmx cokolwiek nasluchiwal, wiec sekcje stały na
     * „Ładowanie…" do czasu recznego kliniecia „Odswiez".
     * htmx rejestruje swoj nasluch wczesniej (skrypt synchroniczny w <head>), wiec przy
     * tej samej fazie jego handler wykona sie przed naszym. */
    if (document.readyState === "complete") {
        init();
    } else {
        document.addEventListener("DOMContentLoaded", init);
    }

    // Fragmenty HTMX potrafia wstawic nowe kontrolki do naglowka — po kazdej podmianie
    // trzeba je objac ochrona z punktu 1.
    document.body && document.body.addEventListener("htmx:afterSwap", function (e) {
        var host = e.target.closest ? e.target.closest("details.sec") : null;
        if (host) guard(host);
    });
})();
