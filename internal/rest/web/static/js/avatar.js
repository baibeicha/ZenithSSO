document.addEventListener("DOMContentLoaded", function() {
    const avatarContainer = document.querySelector('.avatar-container');
    const avatarOverlay = document.querySelector('.avatar-overlay');
    const inputContainer = document.getElementById('avatar-input-container');
    const avatarInput = document.getElementById('avatar_url_input');

    if (!avatarContainer) return;

    avatarContainer.addEventListener('mouseenter', () => {
        avatarOverlay.style.opacity = '1';
    });

    avatarContainer.addEventListener('mouseleave', () => {
        avatarOverlay.style.opacity = '0';
    });

    avatarContainer.addEventListener('click', () => {
        if (inputContainer.style.display === 'none') {
            inputContainer.style.display = 'block';
            avatarInput.focus();
        } else {
            inputContainer.style.display = 'none';
        }
    });

    avatarInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            document.getElementById('avatar_url').value = avatarInput.value;
            document.getElementById('avatar-form').submit();
        }
    });

    const mainForm = document.querySelector('form[action="/settings"]:not(#avatar-form)');
    if (mainForm) {
        mainForm.addEventListener('submit', function() {
            if (avatarInput.value) {
                document.getElementById('avatar_url').value = avatarInput.value;
            }
        });
    }
});
