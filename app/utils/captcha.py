import os
import time
import uuid
import random
import base64
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
from typing import Dict

class CaptchaGenerator:
    # Класс для генерации и проверки CAPTCHA
    # Используется для защиты форм от автоматического заполнения ботами
    # Хранит сгенерированные капчи в памяти с временными метками

    def __init__(self):
        # Инициализация генератора CAPTCHA
        # Создает хранилище для капч и устанавливает срок действия
        self.captchas = {}  # словарь для хранения сгенерированных капч
        self.captcha_expiration = 600  # срок действия капчи в секундах (10 минут)
        
        # Настройка путей к шрифтам для отображения текста
        self.font_path = os.path.join(os.path.dirname(__file__), 'fonts')
        if not os.path.exists(self.font_path):
            os.makedirs(self.font_path, exist_ok=True)
            
        # Проверка наличия файла шрифта
        self.font_file = os.path.join(self.font_path, 'arial.ttf')
        if not os.path.exists(self.font_file):
            # Использовать шрифт по умолчанию из системы
            self.font_file = None

    def generate_captcha(self) -> Dict[str, str]:
        # Генерирует новую CAPTCHA и возвращает идентификатор и изображение
        # Возвращает: словарь с captcha_id и изображением в base64
        
        # Генерируем более простой код капчи (5 символов, только БОЛЬШИЕ БУКВЫ и цифры, исключая похожие)
        # Исключаем похожие символы: 0, O, 1, I, 5, S, 8, B
        allowed_chars = '2346791ACDEFGHJKLMNPQRTUVWXYZ'
        captcha_code = ''.join(random.choices(allowed_chars, k=5))
        
        # Генерируем уникальный идентификатор для хранения
        captcha_id = str(uuid.uuid4())
        
        # Сохраняем код и время создания для последующей проверки
        self.captchas[captcha_id] = {
            'code': captcha_code,
            'created_at': time.time()
        }
        
        # Очистка устаревших капч для экономии памяти
        self._cleanup_expired_captchas()
        
        # Создаем изображение капчи
        image_base64 = self._generate_captcha_image(captcha_code)
        
        return {
            'captcha_id': captcha_id,
            'image': image_base64
        }

    def verify_captcha(self, captcha_id: str, user_input: str) -> bool:
        # Проверяет введенный пользователем код CAPTCHA
        # Args:
        #   captcha_id: Идентификатор CAPTCHA
        #   user_input: Введенный пользователем код
        # Returns:
        #   bool: True, если код верный и не истек срок действия, иначе False
        
        # Проверка на пустые входные данные
        if not captcha_id or not user_input:
            return False
        
        # Получаем данные капчи по идентификатору
        captcha_data = self.captchas.get(captcha_id)
        if not captcha_data:
            return False
        
        # Проверяем срок действия капчи
        if time.time() - captcha_data['created_at'] > self.captcha_expiration:
            # Удаляем устаревшую капчу
            del self.captchas[captcha_id]
            return False
        
        # Сравниваем код (без учета регистра, конвертируем пользовательский ввод в верхний регистр)
        is_valid = user_input.upper() == captcha_data['code']
        
        # Удаляем капчу после проверки (одноразовое использование)
        del self.captchas[captcha_id]
        
        return is_valid

    def _cleanup_expired_captchas(self) -> None:
        # Удаляет устаревшие CAPTCHA из хранилища
        # Вызывается периодически при генерации новых капч
        
        current_time = time.time()
        expired_ids = [
            captcha_id for captcha_id, data in self.captchas.items()
            if current_time - data['created_at'] > self.captcha_expiration
        ]
        
        for captcha_id in expired_ids:
            del self.captchas[captcha_id]

    def _generate_captcha_image(self, code: str) -> str:
        # Создает изображение с CAPTCHA кодом
        # Args:
        #   code: Код CAPTCHA для отображения
        # Returns:
        #   str: Изображение в формате base64
        
        # Увеличиваем размер изображения, чтобы буквы не выходили за границы
        width, height = 250, 100
        # Используем белый фон для лучшей читаемости
        image = Image.new('RGB', (width, height), color=(255, 255, 255))
        draw = ImageDraw.Draw(image)
        
        # Ограничиваем количество линий для лучшей читаемости
        line_colors = [
            (200, 0, 0),     # Красный
            (0, 0, 200),     # Синий
            (0, 100, 0),     # Зеленый
            (100, 0, 100),   # Фиолетовый
            (200, 150, 0),   # Оранжевый
        ]
        
        # Добавляем меньше линий и делаем их светлее для улучшения читаемости
        for _ in range(8):
            x1 = random.randint(0, width - 1)
            y1 = random.randint(0, height - 1)
            x2 = random.randint(0, width - 1)
            y2 = random.randint(0, height - 1)
            line_color = random.choice(line_colors)
            line_opacity = random.randint(40, 90)  # Более прозрачные линии
            actual_color = (
                min(255, line_color[0] + random.randint(-10, 10)),
                min(255, line_color[1] + random.randint(-10, 10)),
                min(255, line_color[2] + random.randint(-10, 10))
            )
            # Тонкие линии для меньшего визуального шума
            line_width = 1
            draw.line((x1, y1, x2, y2), fill=(*actual_color, line_opacity), width=line_width)
        
        # Устанавливаем шрифт для отображения символов
        try:
            font = ImageFont.truetype(self.font_file, 55) if self.font_file else ImageFont.load_default()
        except Exception:
            font = ImageFont.load_default()
        
        # Равномерно распределяем символы по ширине картинки с учетом отступов от краев
        padding = 30  # Отступ от края для предотвращения обрезки
        usable_width = width - 2 * padding
        spacing = usable_width / (len(code))
        
        # Рисуем символы с улучшенной читаемостью
        for i, char in enumerate(code):
            # Небольшое смещение по вертикали для случайности
            offset_y = random.randint(-5, 5)
            
            # Выбираем темные цвета для лучшей читаемости на белом фоне
            colors = [
                (0, 0, 0),       # Черный
                (0, 0, 150),     # Темно-синий
                (150, 0, 0),     # Темно-красный
                (0, 100, 0),     # Темно-зеленый
                (100, 0, 100)    # Фиолетовый
            ]
            color = random.choice(colors)
            
            # Небольшой угол наклона для затруднения автоматического распознавания
            # Уменьшаем угол наклона для лучшей читаемости
            angle = random.randint(-8, 8)
            
            # Создаем изображение для отдельного символа
            char_img = Image.new('RGBA', (60, 60), color=(255, 255, 255, 0))
            char_draw = ImageDraw.Draw(char_img)
            
            # Добавляем эффект обводки для лучшей читаемости (светлее)
            shadow_offsets = [(1, 1), (-1, -1)]
            for dx, dy in shadow_offsets:
                char_draw.text((30 + dx, 30 + dy), char, font=font, fill=(240, 240, 240))
            
            # Рисуем сам символ поверх обводки
            char_draw.text((30, 30), char, font=font, fill=color)
            
            # Поворачиваем изображение символа для дополнительной защиты
            rotated = char_img.rotate(angle, expand=1)
            
            # Вставляем символ в основное изображение с соблюдением расстояний
            pos_x = padding + int(i * spacing) + random.randint(-3, 3)
            pos_y = int(height / 2) + offset_y
            image.paste(rotated, (pos_x, pos_y), rotated)
        
        # Добавляем меньше шума для более читаемого текста
        for _ in range(70):
            x = random.randint(0, width - 1)
            y = random.randint(0, height - 1)
            draw.point((x, y), fill=(
                random.randint(180, 220),
                random.randint(180, 220),
                random.randint(180, 220)
            ))
        
        # Конвертируем изображение в base64 для передачи на клиент
        buffer = BytesIO()
        image.save(buffer, format='JPEG', quality=95)  # Высокое качество для читаемости
        img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
        
        return f"data:image/jpeg;base64,{img_str}"


# Создаем глобальный экземпляр для использования в приложении
captcha = CaptchaGenerator() 