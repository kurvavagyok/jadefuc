"""
Optimize the JADE Ultimate database (VACUUM, REINDEX).
Run with: docker-compose exec backend python scripts/optimize_db.py
"""

import sys
import asyncio

sys.path.append("backend/app")
from app.core.database import db_manager

async def main():
    await db_manager.optimize_database()
    print("Database optimized.")

if __name__ == "__main__":
    asyncio.run(main())