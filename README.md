# INVOEASE PRO — OWASP TOP 10 MANUAL SECURITY AUDIT REPORT
### Full-Stack Freelance GST Billing Platform & Manual Web VAPT Testbed

[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js Version](https://img.shields.io/badge/Node.js-v24+-green.svg)](https://nodejs.org/)
[![Database](https://img.shields.io/badge/Database-SQLite3-003B57.svg)](https://www.sqlite.org/)
[![Security Benchmark](https://img.shields.io/badge/Benchmark-OWASP%20Top%2010%3A2021-red.svg)](https://owasp.org/www-project-top-ten/)
[![Download Full VAPT Report](https://img.shields.io/badge/Download%20Audit%20Report-Excel%20.XLSX-1D6F42.svg)](./InvoEase_OWASP_Top10_VAPT_Report.xlsx)

---

## 📌 Executive Assessment Overview

> **Project Mandate & Engineering Background:**  
> **InvoEase Pro** was architected and developed in close collaboration with **AI** to serve as an authentic, production-grade **Freelance GST Billing Platform** while simultaneously functioning as a dedicated, realistic target for **manual Web Application Penetration Testing (VAPT)** covering the complete **OWASP Top 10: 2021** taxonomy.

### Assessment Metadata (Report Front Sheet)

| Field | Detail | Field | Detail |
|---|---|---|---|
| **Target Application** | InvoEase Pro (Billing Engine) | **Assessment Date** | October 15, 2026 |
| **Base URL** | `http://localhost:3000` | **Auditor / Tooling** | Antigravity Security Suite |
| **Assessment Type** | Manual Grey-Box Web VAPT | **Methodology** | OWASP WSTG v4.2 / OWASP Top 10 |
| **Overall Pre-Fix Risk** | 🔴 **HIGH (Vulnerable in Lab Mode)** | **Post-Fix Posture** | 🛡️ **SECURE (Remediated in Hardened Mode)** |

---

## 📊 Risk Distribution Metrics

```
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│   CRITICAL: 0   │     HIGH: 3     │    MEDIUM: 4    │  LOW / INFO: 3  │    TOTAL: 10    │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

---

## 📋 Executive Vulnerability Summary Matrix

*This table represents the official front sheet (`Executive_Summary`) of the assessment report. For technical proofs-of-concept (PoC), root cause analyses, and step-by-step reproduction instructions, refer to **Sheet 2** of the [Interactive VAPT Excel Report](./InvoEase_OWASP_Top10_VAPT_Report.xlsx).*

| Finding ID | OWASP Category | Vulnerability Finding Name | Affected Asset / Endpoint | Severity | CVSS v3.1 | Lab Mode State | Secure Mode State |
|:---:|---|---|---|:---:|:---:|:---:|:---:|
| **SEC-A01** | **A01:2021 – Broken Access Control** | Insecure Direct Object References (IDOR) & Privilege Escalation | `GET /api/invoices/:id`<br>`GET /api/admin/users` | 🔴 **HIGH** | 8.5 | ⚠️ Vulnerable | 🛡️ Remediated |
| **SEC-A02** | **A02:2021 – Cryptographic Failures** | Sensitive Cookie Missing `HttpOnly` & `SameSite` Attributes | `POST /api/auth/login` | 🟡 **MEDIUM** | 6.1 | ⚠️ Vulnerable | 🛡️ Remediated |
| **SEC-A03** | **A03:2021 – Injection** | SQL Injection in Search & Stored XSS in Notes | `GET /api/invoices?search=`<br>`POST /api/invoices` | 🔴 **HIGH** | 8.8 | ⚠️ Vulnerable | 🛡️ Remediated |
| **SEC-A04** | **A04:2021 – Insecure Design** | Business Logic Flaw: Negative Qty & Price Tampering | `POST /api/invoices` | 🟡 **MEDIUM** | 6.5 | ⚠️ Vulnerable | 🛡️ Remediated |
| **SEC-A05** | **A05:2021 – Security Misconfiguration** | Environment Variable Leak & Missing CSP Headers | `GET /api/debug/environment` | 🟢 **LOW** | 4.3 | ⚠️ Vulnerable | 🛡️ Remediated |
| **SEC-A06** | **A06:2021 – Vulnerable Components** | Public Dependency Inventory Exposure | `GET /api/system/dependencies` | 🟢 **LOW** | 3.7 | ⚠️ Vulnerable | 🛡️ Remediated |
| **SEC-A07** | **A07:2021 – Auth Failures** | Account Enumeration via Errors & Missing Rate Limit | `POST /api/auth/login` | 🟡 **MEDIUM** | 6.5 | ⚠️ Vulnerable | 🛡️ Remediated |
| **SEC-A08** | **A08:2021 – Data Integrity Failures** | Unrestricted File Upload in Company Logo Branding | `POST /api/upload/logo` | 🟡 **MEDIUM** | 6.8 | ⚠️ Vulnerable | 🛡️ Remediated |
| **SEC-A09** | **A09:2021 – Logging Failures** | Insufficient Audit Logging of Authorization Failures | `GET /api/security/logs` | 🟢 **LOW** | 3.1 | ⚠️ Vulnerable | 🛡️ Remediated |
| **SEC-A10** | **A10:2021 – SSRF** | Blind Server-Side Request Forgery via Remote Logo URL | `POST /api/fetch-remote-logo` | 🔴 **HIGH** | 8.6 | ⚠️ Vulnerable | 🛡️ Remediated |

---

## 📥 Full Interactive VAPT Excel Report

The complete corporate workbook is stored directly in this repository:

👉 **[InvoEase_OWASP_Top10_VAPT_Report.xlsx](./InvoEase_OWASP_Top10_VAPT_Report.xlsx)**

### Workbook Structure:
- **Sheet 1 (`Executive_Summary`)**: Formal executive dashboard with severity distribution cards and hyperlinked audit references.
- **Sheet 2 (`Technical_Findings`)**: Detailed technical audit records for each vulnerability containing:
  - Technical Observations & Threat Impact
  - Step-by-Step Manual Reproduction Guide (HTTP requests & payloads)
  - Code-Level Root Cause Analysis
  - Verified Code Remediation & Hardened Defense

---

## 🛠️ Technical Specifications & Architecture

- **Backend Runtime**: Node.js (v24+) with Express 5.x
- **Data Layer**: SQLite3 (`invoease.db`) with multi-tenant mock data and security event audit logs
- **Authentication & Crypto**: Stateless JWT session tokens, Bcrypt password hashing (10 rounds)
- **Security Hardening**: `express-rate-limit`, strict Content-Security-Policy (CSP), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
- **Frontend Core**: Semantic HTML5, Vanilla JavaScript (ES6+), Vanilla CSS3 Design System (Dark/Light themes, Glassmorphism, CSS Custom Properties)
- **Document Rendering**: `html2canvas` + `jsPDF` for client-side printable A4 PDF export
- **Reporting Automation**: Python 3.13 + `openpyxl`

---

## 🚀 Quick Start & Local Execution

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/Codearch440/InvoEase.git
cd InvoEase

# Install dependencies
npm install

# Launch the platform
npm start
```
Access the application at: **`http://localhost:3000`**

### 2. Pre-Configured Test Accounts (Default Password: `Password123!`)
- **Alice (`alice_dev`)**: Standard Freelancer account (owns Invoices #1 & #3)
- **Bob (`bob_designer`)**: Secondary Freelancer account (owns confidential Invoice #2 — used for IDOR testing)
- **SuperAdmin (`superadmin`)**: Administrator account (used for privilege escalation testing)

### 3. Dual-Mode Switch
Use the **"⚡ Toggle Mode"** button in the top navigation bar to switch between:
- **`LAB MODE`**: Endpoints operate in an auditable state for manual vulnerability verification.
- **`SECURE MODE`**: Defenses, parameterized queries, authorization checks, and security headers are enforced.

---

## 📂 Repository Layout

```
InvoEase/
├── InvoEase_OWASP_Top10_VAPT_Report.xlsx # Official corporate VAPT Excel report (2 Sheets)
├── generate_vapt_report.py               # Python generator script for the Excel report
├── server.js                             # Express REST API & OWASP dual-mode controller
├── db.js                                 # SQLite schema & multi-tenant seed data
├── package.json                          # Project dependencies and startup scripts
├── public/                               # Client-side web application (SPA)
│   ├── index.html                        # Main UI layout, Dashboard & Modals
│   ├── style.css                         # Design system, themes & printable A4 CSS
│   ├── script.js                         # Dynamic state controller & OWASP testing console
│   └── uploads/                          # Invoice branding logo directory
└── README.md                             # Project documentation & Executive VAPT Report
```

---

## 📄 License
This project is licensed under the **ISC License**.
