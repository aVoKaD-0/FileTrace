# Импортируем все модели для регистрации в SQLAlchemy
from app.models.user import Users
from app.models.analysis import Analysis
from app.models.result import Results

# Объединяем все модели для удобного импорта
__all__ = ['Users', 'Analysis', 'Results']