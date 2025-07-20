"""
Initialize the JADE Ultimate database (create tables).
Run with: docker-compose exec backend python scripts/db_init.py
"""

import sys
import asyncio

sys.path.append("backend/app")
from app.core.database import create_tables

async def main():
    await create_tables()
    print("All tables created.")

if __name__ == "__main__":
    asyncio.run(main())