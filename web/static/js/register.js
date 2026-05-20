document.addEventListener("DOMContentLoaded", function () {
    const loginLink = document.getElementById('login-link');
    if (window.location.search && loginLink) {
        loginLink.href = "/api/v1/authorize" + window.location.search;
    }

    const regForm = document.getElementById('register-form');
    if (regForm) {
        regForm.addEventListener('submit', async function (e) {
            e.preventDefault();

            const errorDiv = document.getElementById('error-msg');
            const successDiv = document.getElementById('success-msg');
            const submitBtn = this.querySelector('button[type="submit"]');

            if (errorDiv) errorDiv.style.display = 'none';
            if (successDiv) successDiv.style.display = 'none';
            if (submitBtn) submitBtn.disabled = true;

            const username = document.getElementById('username') ? document.getElementById('username').value : '';
            const email = document.getElementById('email') ? document.getElementById('email').value : '';
            const password = document.getElementById('password') ? document.getElementById('password').value : '';

            try {
                const response = await fetch('/api/v1/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({username, email, password})
                });

                const data = await response.json();

                if (!response.ok || data.error) {
                    if (errorDiv) {
                        errorDiv.innerText = data.error || 'Ошибка при регистрации. Попробуйте еще раз.';
                        errorDiv.style.display = 'block';
                    }
                    if (submitBtn) submitBtn.disabled = false;
                } else {
                    if (successDiv) {
                        successDiv.innerText = 'Успешная регистрация! Перенаправляем...';
                        successDiv.style.display = 'block';
                    }

                    setTimeout(() => {
                        window.location.href = loginLink ? loginLink.href : '/login';
                    }, 1500);
                }
            } catch (err) {
                if (errorDiv) {
                    errorDiv.innerText = 'Ошибка сети. Проверьте подключение к интернету.';
                    errorDiv.style.display = 'block';
                }
                if (submitBtn) submitBtn.disabled = false;
            }
        });
    }
});
