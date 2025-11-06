import bcrypt

def get_password_hash(password: str):
    # Создает хеш пароля с использованием bcrypt
    # Параметры:
    #   password: Пароль в открытом виде
    # Возвращает:
    #   Строка с хешем пароля в кодировке utf-8
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    # Проверяет соответствие пароля его хешу
    # Параметры:
    #   plain_password: Пароль в открытом виде для проверки
    #   hashed_password: Хеш пароля из базы данных
    # Возвращает:
    #   Boolean: True если пароль соответствует хешу, иначе False
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))