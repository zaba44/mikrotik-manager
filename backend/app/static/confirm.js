/* Potwierdzenie przed wyslaniem formularza: <form data-confirm="Tekst pytania">.
 *
 * Tekst idzie jako DANE (atrybut), nie jako kod. Dawniej byl wklejany w onsubmit:
 * confirm('Usunac {{ device.name }}?') — a przegladarka dekoduje encje HTML w atrybucie
 * PRZED wykonaniem handlera, wiec nazwa z apostrofem (O'Brien) psula skrypt, a spreparowana
 * nazwa urzadzenia albo uzytkownika BTH z routera wykonywala wlasny JavaScript
 * (wytkniete w drugiej recenzji). Escapowanie Jinja nie chroni kontekstu JS.
 *
 * Nasluch w fazie przechwytywania na dokumencie: dziala dla zwyklych formularzy i dla
 * formularzy htmx (zatrzymanie propagacji nie dopuszcza do obslugi htmx), takze dla
 * fragmentow doladowanych pozniej. */
document.addEventListener("submit", function (e) {
    var form = e.target;
    var msg = form && form.getAttribute && form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
        e.preventDefault();
        e.stopImmediatePropagation();
    }
}, true);
