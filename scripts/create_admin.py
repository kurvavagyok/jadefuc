"""
Script to create an initial admin user for JADE Ultimate Security Platform.
Run with: docker-compose exec backend python scripts/create_admin.py
"""

import sys
import asyncio
import getpass

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

sys.path.append("backend/app")
from app.core.database import get_db, engine
from app.models.user import User, UserRole

async def main():
    username = input("Admin username: ")
    email = input("Admin email: ")
    password = getpass.getpass("Admin password: ")
    full_name = input("Full name (optional): ")

    async with get_db() as db:
        # Check if user exists
        result = await db.execute(select(User).filter(User.username == username))
        if result.scalar_one_or_none():
            print("User already exists.")
            return

        user = User(
            username=username,
            email=email,
            full_name=full_name,
            role=UserRole.admin,
            is_superuser=True,
            is_active=True
        )
        user.set_password(password)
        user.generate_api_key()
        db.add(user)
        await db.commit()
        print(f"Admin user '{username}' created.")

if __name__ == "__main__":
    asyncio.run(main())