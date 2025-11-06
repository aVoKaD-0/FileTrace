# Импортируем все модели для регистрации в SQLAlchemy
from app.domain.models.user import Users
from app.domain.models.analysis import Analysis
from app.domain.models.result import Results

# Объединяем все модели для удобного импорта
__all__ = ['Users', 'Analysis', 'Results'] 