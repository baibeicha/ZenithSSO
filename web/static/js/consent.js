document.addEventListener("DOMContentLoaded", function () {
    const params = new URLSearchParams(window.location.search);

    const clientName = params.get('client_id');
    const appNameEl = document.getElementById('app-name');
    if (clientName && appNameEl) appNameEl.innerText = clientName;

    const scopesStr = params.get('scope') || '';
    const scopesList = document.getElementById('scopes-list');

    if (scopesList) {
        if (scopesStr) {
            const scopes = scopesStr.split(' ');
            scopes.forEach(s => {
                if (s) {
                    const li = document.createElement('li');
                    li.innerText = s;
                    scopesList.appendChild(li);
                }
            });
        } else {
            scopesList.innerHTML = "<li>Базовый профиль</li>";
        }
    }
});
