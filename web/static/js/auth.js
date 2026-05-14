document.addEventListener("DOMContentLoaded", function() {
    const params = new URLSearchParams(window.location.search);
    const form = document.querySelector('form');
    const hiddenFieldsContainer = document.getElementById('hidden_oauth_params');

    if (form && hiddenFieldsContainer) {
        params.forEach((value, key) => {
            if (key !== 'error') {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = key;
                input.value = value;
                hiddenFieldsContainer.appendChild(input);
            }
        });

        form.action = form.action + "?" + params.toString();
    }

    if (params.has('error')) {
        const errorDiv = document.getElementById('error-msg');
        if (errorDiv) {
            errorDiv.style.display = 'block';
            if (params.get('error') === 'invalid_credentials') {
                errorDiv.innerText = "Неверный логин или пароль";
            } else {
                errorDiv.innerText = params.get('error');
            }
        }
    }
});