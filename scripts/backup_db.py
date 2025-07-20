"""
Backup the JADE Ultimate database (PostgreSQL).
This script assumes pg_dump is installed and accessible.
Run with: docker-compose exec backend python scripts/backup_db.py /backup/path.sql
"""

import sys
import os

backup_path = sys.argv[1] if len(sys.argv) > 1 else None
if not backup_path:
    print("Usage: python backup_db.py /path/to/backup.sql")
    sys.exit(1)

os.system(f'pg_dump -U postgres -d jade_security -h db > "{backup_path}"')
print(f"Database backup created at {backup_path}")