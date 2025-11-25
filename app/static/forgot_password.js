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

    const refreshButton = document.getElementById('refreshCaptchaButton');
    if (refreshButton) {
        refreshButton.addEventListener('click', () => {
            refreshCaptcha();
        });
    }

    const button = document.getElementById('forgotButton');
    const message = document.getElementById('message');
    const loading = document.getElementById('loading');

    if (!button) return;

    button.addEventListener('click', async () => {
        const emailInput = document.getElementById('email');
        const captchaTextInput = document.getElementById('captchaText');
        const captchaIdInput = document.getElementById('captchaId');

        if (!message || !loading || !emailInput || !captchaTextInput || !captchaIdInput) {
            return;
        }

        const email = emailInput.value.trim();
        const captchaText = captchaTextInput.value.trim();
        const captchaId = captchaIdInput.value;

        message.textContent = '';
        message.style.color = 'red';

        if (!email || !captchaText) {
            message.textContent = 'Пожалуйста, заполните все поля.';
            clearAfterDelay(message);
            return;
        }

        loading.style.display = 'block';
        button.disabled = true;

        try {
            const response = await fetch('/users/forgot-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: email,
                    captcha_id: captchaId,
                    captcha_text: captchaText
                })
            });

            const data = await response.json().catch(() => ({}));

            if (response.ok) {
                message.textContent = data.message || 'Если такой email зарегистрирован, мы отправили на него ссылку для сброса пароля.';
                message.style.color = 'green';
            } else {
                message.textContent = data.detail || 'Ошибка при запросе сброса пароля. Попробуйте снова.';
                message.style.color = 'red';
                refreshCaptcha();
            }

            clearAfterDelay(message);
        } catch (error) {
            console.error('Ошибка при запросе сброса пароля:', error);
            message.textContent = 'Ошибка сети. Попробуйте снова позже.';
            message.style.color = 'red';
            clearAfterDelay(message);
            refreshCaptcha();
        } finally {
            loading.style.display = 'none';
            button.disabled = false;
        }
    });
});
