document.addEventListener("DOMContentLoaded", function () {
    const registerLink = document.getElementById('register-link');
    if (window.location.search && registerLink) {
        registerLink.href = "/api/v1/register" + window.location.search;
    }
});
