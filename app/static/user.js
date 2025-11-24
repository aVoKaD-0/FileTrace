document.querySelector('#registerForm form').addEventListener('submit', async function(event) {
    event.preventDefault();

    const formData = new FormData(this);
    const data = Object.fromEntries(formData.entries());

    document.getElementById('loadingIcon').style.display = 'block';
    
    // Скрываем предыдущие сообщения об ошибках CAPTCHA
    document.getElementById('registerCaptchaError').style.display = 'none';

    try {
        const password = document.getElementById('password').value;
        const message = document.getElementById('message');
        const captchaText = document.getElementById('captchaText').value;
        let flag = 0;
        
        if (!password || !captchaText) {
            message.textContent = 'Пожалуйста, заполните все поля.';
            message.style.color = 'red';
            flag = 1;
        }
        if (password.length < 8) {
            message.textContent = 'Длина пароля должна быть больше 8 символов.';
            message.style.color = 'red';
            flag = 1;
        }
        if (!/[A-Za-z0-9]/.test(password) || !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?]/.test(password)) {
            message.textContent = 'Пароль должен содержать прописные, заглавные буквы, цифры и специальные символы.';
            message.style.color = 'red';
            flag = 1;
        }
        
        if (flag === 1) {
            clearAfterDelay(message);
            document.getElementById('loadingIcon').style.display = 'none';
            return;
        }

        // Добавляем данные CAPTCHA
        data.captcha_id = document.getElementById('registerCaptchaId').value;
        data.captcha_text = captchaText;

        const response = await fetch('/users/registration', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        const responseData = await response.json();

        if (response.ok) {
            console.log('Регистрация успешна');
            message.textContent = responseData.message || 'Регистрация успешна. Проверьте вашу почту для подтверждения.';
            message.style.color = 'green';
            clearAfterDelay(message);
            this.reset();
            refreshCaptcha('register'); // Обновляем капчу после успешной регистрации
            window.location.href = '/users/confirm-email';
        } else {
            console.log('Ошибка при регистрации:', responseData);
            
            // Проверяем, связана ли ошибка с CAPTCHA
            if (responseData.detail && responseData.detail.includes('Неверный код с картинки')) {
                // Показываем ошибку CAPTCHA прямо под полем
                const captchaError = document.getElementById('registerCaptchaError');
                captchaError.style.display = 'block';
                clearAfterDelay(captchaError, 15000, true);
                
                // Очищаем поле ввода CAPTCHA
                document.getElementById('captchaText').value = '';
                
                // Обновляем изображение CAPTCHA
                refreshCaptcha('register');
            } else {
                // Обычная ошибка - показываем общее сообщение
                message.textContent = responseData.detail || 'Ошибка при регистрации';
                message.style.color = 'red';
                clearAfterDelay(message);
                refreshCaptcha('register'); // Обновляем капчу после ошибки
            }
        }
    } catch (error) {
        console.error('Ошибка:', error);
        const message = document.getElementById('message');
        message.textContent = 'Произошла ошибка при отправке данных';
        message.style.color = 'red';
        clearAfterDelay(message);
        refreshCaptcha('register'); // Обновляем капчу после ошибки
    } finally {
        document.getElementById('loadingIcon').style.display = 'none';
    }
});

document.querySelector('#loginForm form').addEventListener('submit', async function(event) {
    event.preventDefault();

    const formData = new FormData(this);
    const data = Object.fromEntries(formData.entries());

    document.getElementById('loadingIcon').style.display = 'block';
    
    // Скрываем предыдущие сообщения об ошибках CAPTCHA
    document.getElementById('loginCaptchaError').style.display = 'none';

    try {
        // Проверяем, показывается ли CAPTCHA для входа
        const loginCaptchaContainer = document.getElementById('loginCaptchaContainer');
        if (loginCaptchaContainer.style.display !== 'none') {
            // Если CAPTCHA показывается, добавляем её данные в запрос
            data.captcha_id = document.getElementById('loginCaptchaId').value;
            data.captcha_text = document.getElementById('loginCaptchaText').value;
        }

        const response = await fetch('/users/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            window.location.href = '/analysis';
        } else {
            const error = await response.json();
            
            // Если требуется CAPTCHA для следующей попытки
            if (error.require_captcha) {
                // Показываем блок CAPTCHA
                loginCaptchaContainer.style.display = 'block';
                // Загружаем новую CAPTCHA
                refreshCaptcha('login');
            }
            
            // Проверяем, связана ли ошибка с CAPTCHA
            if (error.detail && error.detail.includes('Неверный код с картинки')) {
                // Показываем ошибку CAPTCHA прямо под полем
                const captchaError = document.getElementById('loginCaptchaError');
                captchaError.style.display = 'block';
                clearAfterDelay(captchaError, 15000, true);
                
                // Очищаем поле ввода CAPTCHA
                document.getElementById('loginCaptchaText').value = '';
                
                // Обновляем изображение CAPTCHA
                refreshCaptcha('login');
            } else {
                // Обычная ошибка - показываем в alert
                alert('Ошибка: ' + error.detail);
            }
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('Произошла ошибка при отправке данных');
    } finally {
        document.getElementById('loadingIcon').style.display = 'none';
    }
});

function changeTitle(title) {
    document.title = title;
    document.getElementById('pageTitle').innerText = title;
}

document.getElementById('registerTab').addEventListener('click', function() {
    document.getElementById('registerForm').style.display = 'block';
    document.getElementById('loginForm').style.display = 'none';
    changeTitle('Регистрация');
    refreshCaptcha('register');
});

document.getElementById('loginTab').addEventListener('click', function() {
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('loginForm').style.display = 'block';
    changeTitle('Вход');
    if (document.getElementById('loginCaptchaContainer').style.display !== 'none') {
        refreshCaptcha('login');
    }
});

function togglePassword(fieldId, button) {
    const field = document.getElementById(fieldId);
    if (field.type === "password") {
        field.type = "text";
        button.textContent = "🙈"; // Изменяем иконку на закрытый глаз
    } else {
        field.type = "password";
        button.textContent = "👁"; // Изменяем иконку на открытый глаз
    }
}

function clearAfterDelay(element, delay = 15000, hideElement = false) {
    if (!element) return;

    if (element._clearTimeout) {
        clearTimeout(element._clearTimeout);
    }

    element._clearTimeout = setTimeout(() => {
        element.textContent = '';

        if (hideElement) {
            element.style.display = 'none';
        }
    }, delay);
}

// Функция для получения и отображения новой CAPTCHA
async function refreshCaptcha(formType) {
    try {
        const response = await fetch('/users/captcha');
        if (!response.ok) {
            throw new Error('Ошибка при получении CAPTCHA');
        }
        
        const data = await response.json();
        
        if (formType === 'register') {
            document.getElementById('registerCaptchaImage').src = data.image;
            document.getElementById('registerCaptchaId').value = data.captcha_id;
        } else if (formType === 'login') {
            document.getElementById('loginCaptchaImage').src = data.image;
            document.getElementById('loginCaptchaId').value = data.captcha_id;
        }
    } catch (error) {
        console.error('Ошибка при обновлении CAPTCHA:', error);
    }
}

// Загрузка CAPTCHA при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
    // Загружаем CAPTCHA для формы регистрации
    refreshCaptcha('register');
    
    // Изменяем обработчики вкладок, чтобы загружать CAPTCHA при переключении
    document.getElementById('registerTab').addEventListener('click', function() {
        document.getElementById('registerForm').style.display = 'block';
        document.getElementById('loginForm').style.display = 'none';
        changeTitle('Регистрация');
        refreshCaptcha('register');
    });

    document.getElementById('loginTab').addEventListener('click', function() {
        document.getElementById('registerForm').style.display = 'none';
        document.getElementById('loginForm').style.display = 'block';
        changeTitle('Вход');
        // Загружаем CAPTCHA для формы входа только если она видима
        if (document.getElementById('loginCaptchaContainer').style.display !== 'none') {
            refreshCaptcha('login');
        }
    });
});