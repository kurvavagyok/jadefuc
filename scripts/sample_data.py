"""
Script to create sample data for demo/testing the JADE Ultimate platform.
Run with: docker-compose exec backend python scripts/sample_data.py
"""

import asyncio
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from app.core.database import get_db
from app.models.user import User, UserRole
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.vulnerability import Vulnerability

async def main():
    async with get_db() as db:
        # Create a sample user
        user = User(
            username="demo",
            email="demo@jade.com",
            full_name="Demo User",
            is_active=True,
            role=UserRole.analyst,
        )
        user.set_password("demopass")
        user.generate_api_key()
        db.add(user)
        await db.commit()
        await db.refresh(user)

        # Create a sample scan
        scan = Scan(
            scan_id=uuid4().hex[:16],
            user_id=user.id,
            name="Sample Network Scan",
            scan_type=ScanType.network,
            target="10.10.10.0/24",
            status=ScanStatus.COMPLETED,
            started_at=datetime.now(timezone.utc) - timedelta(minutes=10),
            completed_at=datetime.now(timezone.utc),
            risk_score=17,
            total_findings=3,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        # Create sample vulnerabilities
        vuln1 = Vulnerability(
            scan_id=scan.id,
            title="Open SSH Port",
            description="SSH port 22 is open and accessible from the internet.",
            vulnerability_type="network",
            severity="medium",
            risk_score=5.0,
            host="10.10.10.5",
            port=22,
            service="ssh",
            remediation="Restrict SSH access via firewall."
        )
        vuln2 = Vulnerability(
            scan_id=scan.id,
            title="Default Credentials Detected",
            description="Device at 10.10.10.12 uses default admin credentials.",
            vulnerability_type="credential",
            severity="high",
            risk_score=8.0,
            host="10.10.10.12",
            port=80,
            service="http",
            remediation="Change default credentials."
        )
        vuln3 = Vulnerability(
            scan_id=scan.id,
            title="Outdated OpenSSL",
            description="OpenSSL 1.0.1 is outdated and vulnerable to Heartbleed.",
            vulnerability_type="software",
            severity="critical",
            risk_score=10.0,
            host="10.10.10.20",
            port=443,
            service="https",
            remediation="Update to latest OpenSSL."
        )
        db.add_all([vuln1, vuln2, vuln3])
        await db.commit()
        print("Sample data loaded.")

if __name__ == "__main__":
    asyncio.run(main())