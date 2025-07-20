"""
Drop all tables (destroy the JADE Ultimate database schema).
Use only for development/testing!
Run with: docker-compose exec backend python scripts/db_drop.py
"""

import sys
import asyncio

sys.path.append("backend/app")
from app.core.database import drop_tables

async def main():
    await drop_tables()
    print("All tables dropped.")

if __name__ == "__main__":
    asyncio.run(main())