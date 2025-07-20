"""
Script to check the health of the database connection in JADE Ultimate.
Run with: docker-compose exec backend python scripts/health_check.py
"""

import sys
import asyncio

sys.path.append("backend/app")
from app.core.database import check_database_health

async def main():
    healthy = await check_database_health()
    if healthy:
        print("Database is healthy.")
    else:
        print("Database health check failed.")

if __name__ == "__main__":
    asyncio.run(main())