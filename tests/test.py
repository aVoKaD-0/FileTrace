import asyncio
from app.services.analysis_service import AnalysisService

async def test_analysis_service():
    analysis_service = AnalysisService()
    await analysis_service.get_db()
    await analysis_service.analyze("93a1519c-58a2-4d0a-a1aa-351e97beb1b0", "4ukey_11739454314679240201.exe", "61454e7c-b20b-4b8d-9f56-cd48a7e4ca06")

if __name__ == "__main__":
    asyncio.run(test_analysis_service())