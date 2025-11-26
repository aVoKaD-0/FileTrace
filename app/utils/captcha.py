import os
import time
import uuid
import random
import base64
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
from typing import Dict

class CaptchaGenerator:

    def __init__(self):
        self.captchas = {}
        self.captcha_expiration = 600
        
        self.font_path = os.path.join(os.path.dirname(__file__), 'fonts')
        if not os.path.exists(self.font_path):
            os.makedirs(self.font_path, exist_ok=True)
            
        self.font_file = os.path.join(self.font_path, 'arial.ttf')
        if not os.path.exists(self.font_file):
            self.font_file = None

    def generate_captcha(self) -> Dict[str, str]:
        
        allowed_chars = '2346791ACDEFGHJKLMNPQRTUVWXYZ'
        captcha_code = ''.join(random.choices(allowed_chars, k=5))
        
        captcha_id = str(uuid.uuid4())
        
        self.captchas[captcha_id] = {
            'code': captcha_code,
            'created_at': time.time()
        }
        
        self._cleanup_expired_captchas()
        
        image_base64 = self._generate_captcha_image(captcha_code)
        
        return {
            'captcha_id': captcha_id,
            'image': image_base64
        }

    def verify_captcha(self, captcha_id: str, user_input: str) -> bool:
        if not captcha_id or not user_input:
            return False
        
        captcha_data = self.captchas.get(captcha_id)
        if not captcha_data:
            return False
        
        if time.time() - captcha_data['created_at'] > self.captcha_expiration:
            del self.captchas[captcha_id]
            return False
        
        is_valid = user_input.upper() == captcha_data['code']
        
        del self.captchas[captcha_id]
        
        return is_valid

    def _cleanup_expired_captchas(self) -> None:
        
        current_time = time.time()
        expired_ids = [
            captcha_id for captcha_id, data in self.captchas.items()
            if current_time - data['created_at'] > self.captcha_expiration
        ]
        
        for captcha_id in expired_ids:
            del self.captchas[captcha_id]

    def _generate_captcha_image(self, code: str) -> str:
        
        width, height = 250, 100
        image = Image.new('RGB', (width, height), color=(255, 255, 255))
        draw = ImageDraw.Draw(image)
        
        line_colors = [
            (200, 0, 0),
            (0, 0, 200),
            (0, 100, 0),
            (100, 0, 100),
            (200, 150, 0),
        ]
        
        for _ in range(8):
            x1 = random.randint(0, width - 1)
            y1 = random.randint(0, height - 1)
            x2 = random.randint(0, width - 1)
            y2 = random.randint(0, height - 1)
            line_color = random.choice(line_colors)
            line_opacity = random.randint(40, 90)
            actual_color = (
                min(255, line_color[0] + random.randint(-10, 10)),
                min(255, line_color[1] + random.randint(-10, 10)),
                min(255, line_color[2] + random.randint(-10, 10))
            )
            line_width = 1
            draw.line((x1, y1, x2, y2), fill=(*actual_color, line_opacity), width=line_width)
        
        try:
            font = ImageFont.truetype(self.font_file, 55) if self.font_file else ImageFont.load_default()
        except Exception:
            font = ImageFont.load_default()
        
        padding = 30
        usable_width = width - 2 * padding
        spacing = usable_width / (len(code))
        
        for i, char in enumerate(code):
            offset_y = random.randint(-5, 5)
            
            colors = [
                (0, 0, 0),
                (0, 0, 150),
                (150, 0, 0),
                (0, 100, 0),
                (100, 0, 100)
            ]
            color = random.choice(colors)
            
            angle = random.randint(-8, 8)
            
            char_img = Image.new('RGBA', (60, 60), color=(255, 255, 255, 0))
            char_draw = ImageDraw.Draw(char_img)
            
            shadow_offsets = [(1, 1), (-1, -1)]
            for dx, dy in shadow_offsets:
                char_draw.text((30 + dx, 30 + dy), char, font=font, fill=(240, 240, 240))
            
            char_draw.text((30, 30), char, font=font, fill=color)
            
            rotated = char_img.rotate(angle, expand=1)
            
            pos_x = padding + int(i * spacing) + random.randint(-3, 3)
            pos_y = int(height / 2) + offset_y
            image.paste(rotated, (pos_x, pos_y), rotated)
        
        for _ in range(70):
            x = random.randint(0, width - 1)
            y = random.randint(0, height - 1)
            draw.point((x, y), fill=(
                random.randint(180, 220),
                random.randint(180, 220),
                random.randint(180, 220)
            ))
        
        buffer = BytesIO()
        image.save(buffer, format='JPEG', quality=95)
        img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
        
        return f"data:image/jpeg;base64,{img_str}"


captcha = CaptchaGenerator() 