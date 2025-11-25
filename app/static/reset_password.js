async function refreshCaptcha() {
    try {
        const response = await fetch('/users/captcha');
        if (!response.ok) {
            throw new Error('Ошибка при получении CAPTCHA');
        }

        const data = await response.json();
        const image = document.getElementById('captchaImage');
        const captchaIdInput = document.getElementById('captchaId');
        if (image && captchaIdInput) {
            image.src = data.image;
            captchaIdInput.value = data.captcha_id;
        }
    } catch (error) {
        console.error('Ошибка при обновлении CAPTCHA:', error);
        const message = document.getElementById('message');
        if (message) {
            message.textContent = 'Ошибка при загрузке CAPTCHA. Попробуйте обновить страницу.';
            message.style.color = 'red';
        }
    }
}

function togglePassword(fieldId, button) {
    const field = document.getElementById(fieldId);
    if (!field) return;

    if (field.type === 'password') {
        field.type = 'text';
        button.textContent = '🙈';
    } else {
        field.type = 'password';
        button.textContent = '👁';
    }
}

function clearAfterDelay(element, delay = 15000) {
    if (!element) return;

    if (element._clearTimeout) {
        clearTimeout(element._clearTimeout);
    }

    element._clearTimeout = setTimeout(() => {
        element.textContent = '';
    }, delay);
}

document.addEventListener('DOMContentLoaded', () => {
    refreshCaptcha();

    const resetButton = document.getElementById('resetButton');
    const message = document.getElementById('message');
    const loading = document.getElementById('loading');

    if (!resetButton || !message || !loading) return;

    resetButton.addEventListener('click', async () => {
        const password1 = (document.getElementById('password1') || {}).value || '';
        const password2 = (document.getElementById('password2') || {}).value || '';
        const captchaText = (document.getElementById('captchaText') || {}).value || '';
        const captchaId = (document.getElementById('captchaId') || {}).value || '';
        const resetToken = (document.getElementById('resetToken') || {}).value || '';

        message.textContent = '';
        message.style.color = 'red';

        if (!password1 || !password2 || !captchaText) {
            message.textContent = 'Пожалуйста, заполните все поля.';
            clearAfterDelay(message);
            return;
        }
        if (password1 !== password2) {
            message.textContent = 'Пароли не совпадают.';
            clearAfterDelay(message);
            return;
        }
        if (password1.length < 8) {
            message.textContent = 'Длина пароля должна быть больше 8 символов.';
            clearAfterDelay(message);
            return;
        }
        if (!/[A-Za-z0-9]/.test(password1) || !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password1)) {
            message.textContent = 'Пароль должен содержать прописные, заглавные буквы, цифры и специальные символы.';
            clearAfterDelay(message);
            return;
        }

        loading.style.display = 'block';
        resetButton.disabled = true;

        const payload = {
            password: password1,
            captcha_id: captchaId,
            captcha_text: captchaText,
            reset_token: resetToken || null
        };

        try {
            const response = await fetch('/users/reset-password', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json().catch(() => ({}));

            if (response.ok) {
                message.textContent = data.message || 'Пароль изменён успешно!';
                message.style.color = 'green';
                clearAfterDelay(message);
                setTimeout(() => {
                    window.location.href = '/';
                }, 2000);
            } else {
                message.textContent = data.detail || 'Ошибка при изменении пароля. Попробуйте снова.';
                message.style.color = 'red';
                clearAfterDelay(message);
                refreshCaptcha();
            }
        } catch (error) {
            console.error('Ошибка при изменении пароля:', error);
            message.textContent = 'Ошибка сети. Попробуйте снова позже.';
            message.style.color = 'red';
            clearAfterDelay(message);
            refreshCaptcha();
        } finally {
            loading.style.display = 'none';
            resetButton.disabled = false;
        }
    });
});
