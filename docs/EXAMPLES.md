# JADE Ultimate Security Platform – API Usage Examples

## Authentication

### Register

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@corp.com","password":"SuperSecret123!"}'
```

### Login

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"SuperSecret123!"}'
```

## Create a Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_JWT>" \
  -d '{"scan_type":"network","target":"10.0.0.0/24"}'
```

## List Scans

```bash
curl -X GET http://localhost:8000/api/v1/scans/ \
  -H "Authorization: Bearer <YOUR_JWT>"
```

## Get Vulnerabilities

```bash
curl -X GET http://localhost:8000/api/v1/vulnerabilities/ \
  -H "Authorization: Bearer <YOUR_JWT>"
```

## Trigger AI Analysis

```bash
curl -X POST http://localhost:8000/api/v1/ai/analyze \
  -H "Authorization: Bearer <YOUR_JWT>" \
  -d '{"scan_id":"abc123def456"}'
```

## Get Executive Report

```bash
curl -X GET "http://localhost:8000/api/v1/reports/abc123def456?report_type=executive" \
  -H "Authorization: Bearer <YOUR_JWT>"
```

---

## Example: Start a Web Scan and Get Results

```bash
curl -X POST http://localhost:8000/api/v1/scans/ \
  -H "Authorization: Bearer <YOUR_JWT>" \
  -H "Content-Type: application/json" \
  -d '{"scan_type":"web_application","target":"https://vulnerable.example.com"}'

# After scan completes, fetch details:
curl -X GET http://localhost:8000/api/v1/scans/<scan_id> \
  -H "Authorization: Bearer <YOUR_JWT>"

# List vulnerabilities for the scan:
curl -X GET http://localhost:8000/api/v1/scans/<scan_id>/vulnerabilities \
  -H "Authorization: Bearer <YOUR_JWT>"
```

---

## MFA Setup and Verification

```bash
curl -X POST http://localhost:8000/api/v1/auth/setup-mfa \
  -H "Authorization: Bearer <YOUR_JWT>"

# Scan returned QR code in your authenticator app, and then verify:
curl -X POST http://localhost:8000/api/v1/auth/verify-mfa \
  -H "Authorization: Bearer <YOUR_JWT>" \
  -d '{"token":"123456"}'
```

---

## Example Output

```json
{
  "scan_id": "abc123def456",
  "name": "Office Network",
  "scan_type": "network",
  "target": "192.168.1.0/24",
  "status": "completed",
  "risk_score": 14,
  "started_at": "2025-07-20T00:01:00Z",
  "completed_at": "2025-07-20T00:03:14Z"
}
```