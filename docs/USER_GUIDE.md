# JADE Ultimate Security Platform – User Guide

## 1. Logging In

- Go to the login page.
- Enter your username and password.
- If MFA is enabled on your account, enter the code from your authenticator app.

## 2. Starting a Scan

- Navigate to the "Scans" section.
- Click "New Scan", fill in target (e.g., `10.0.0.0/24` or `https://example.com`), select scan type (network, web, etc.).
- Click "Start Scan".
- The scan will run asynchronously; progress and results will appear in the list.

## 3. Analyzing Vulnerabilities

- View scan details to see vulnerabilities found.
- Each vulnerability includes severity, remediation steps, and AI risk assessment.

## 4. AI Analysis

- For completed scans, use the "AI Analysis" button to trigger LLM-powered insight.
- View the AI-generated technical/executive/compliance reports.

## 5. Reports

- Download executive, technical, or compliance reports from scan details or the Reports section.

## 6. Managing Users & MFA

- Register new users or invite team members.
- Set up MFA from your user profile for extra security.
- Track your sessions and audit logs under "Profile".

## 7. Compliance Dashboard

- The dashboard shows your scan coverage, open vulnerabilities, and compliance score.

## 8. API Usage

- All features are available via REST API (see [API.md](API.md) for endpoints and [EXAMPLES.md](EXAMPLES.md) for usage).

---

**Need help?**  
Contact your admin or open an issue on GitHub.