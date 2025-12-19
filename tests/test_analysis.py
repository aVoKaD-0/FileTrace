from app.services.analysis_service import AnalysisService
import asyncio

async def test_analysis_service():
    analysis_service = AnalysisService("kumir2-2.1.0-rc11-install.exe", "93a1519c-58a2-4d0a-a1aa-351e97beb1b0", "bf75d48c-9b64-4037-973c-5cf250dd00aa")
    asyncio.create_task(analysis_service.analyze())
    await asyncio.gather(*asyncio.all_tasks())