import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

def build_vapt_report(output_file="InvoEase_OWASP_Top10_VAPT_Report.xlsx"):
    wb = openpyxl.Workbook()
    
    # -------------------------------------------------------------
    # Styling Palette: Sleek Corporate Executive Theme
    # -------------------------------------------------------------
    NAVY_HEADER = PatternFill(start_color="0F172A", end_color="0F172A", fill_type="solid")
    NAVY_SUBHEADER = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
    ACCENT_BLUE = PatternFill(start_color="2563EB", end_color="2563EB", fill_type="solid")
    ROW_ZEBRA_FILL = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
    WHITE_FILL = PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid")
    
    # Severity Badges (Text Color & Background)
    FILL_HIGH = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid")
    FONT_HIGH = Font(name="Calibri", size=10, bold=True, color="991B1B")

    FILL_MEDIUM = PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid")
    FONT_MEDIUM = Font(name="Calibri", size=10, bold=True, color="92400E")

    FILL_LOW = PatternFill(start_color="ECFDF5", end_color="ECFDF5", fill_type="solid")
    FONT_LOW = Font(name="Calibri", size=10, bold=True, color="065F46")

    # Font definitions
    FONT_TITLE = Font(name="Calibri", size=16, bold=True, color="FFFFFF")
    FONT_HEADER = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    FONT_SUBHEADER = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    FONT_METADATA_LABEL = Font(name="Calibri", size=10, bold=True, color="475569")
    FONT_METADATA_VAL = Font(name="Calibri", size=10, color="0F172A")
    FONT_REGULAR = Font(name="Calibri", size=10, color="1E293B")
    FONT_BOLD = Font(name="Calibri", size=10, bold=True, color="1E293B")
    FONT_CODE = Font(name="Consolas", size=9, color="0F172A")
    FONT_LINK = Font(name="Calibri", size=10, bold=True, color="2563EB", underline="single")
    
    # Borders
    THIN_BORDER_SIDE = Side(border_style="thin", color="E2E8F0")
    BORDER_ALL = Border(left=THIN_BORDER_SIDE, right=THIN_BORDER_SIDE, top=THIN_BORDER_SIDE, bottom=THIN_BORDER_SIDE)
    BORDER_BOTTOM_THICK = Border(bottom=Side(border_style="medium", color="0F172A"))

    # -------------------------------------------------------------
    # DATA DEFINITION: 10 VAPT Findings (OWASP Top 10: 2021)
    # -------------------------------------------------------------
    findings = [
        {
            "id": "SEC-A01",
            "owasp_code": "A01:2021",
            "owasp_title": "Broken Access Control",
            "vuln_title": "Insecure Direct Object Reference (IDOR) & Horizontal Privilege Escalation",
            "endpoint": "GET /api/invoices/:id | DELETE /api/invoices/:id",
            "severity": "HIGH",
            "cvss": 8.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "impact": "An authenticated user (e.g. Alice) can view, export, or delete invoices belonging to completely separate freelancers (e.g. Bob) simply by altering the numeric ID in the URL. Violates cross-tenant multi-user boundary.",
            "poc_steps": "1. Authenticate as 'alice_dev' (User ID: 1) via POST /api/auth/login.\n2. Execute GET /api/invoices/2 (which belongs to user 'bob_designer', User ID: 2).\n3. In Lab Mode, the server responds with HTTP 200 OK and returns Bob's confidential invoice data ('Private Client Secret Project', Grand Total: ₹41,300).\n4. Repeat with DELETE /api/invoices/2 to delete Bob's invoice without authorization.",
            "root_cause": "The backend controller queries 'SELECT * FROM invoices WHERE id = ?' without verifying whether the 'user_id' column on the retrieved record matches the authenticated 'req.user.id' extracted from the JWT token.",
            "remediation": "Enforce strict object-level authorization:\n1. Query database using both ID and user_id: 'WHERE id = ? AND user_id = ?'.\n2. For administrative access, verify 'req.user.role === \"admin\"'.\n3. Return HTTP 403 Forbidden on unauthorized access attempts."
        },
        {
            "id": "SEC-A02",
            "owasp_code": "A02:2021",
            "owasp_title": "Cryptographic Failures",
            "vuln_title": "Sensitive Session Cookie Missing HttpOnly & SameSite Attributes",
            "endpoint": "POST /api/auth/login (Set-Cookie: invoease_token)",
            "severity": "MEDIUM",
            "cvss": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "impact": "Session token stored in cookies is accessible to client-side scripts via 'document.cookie'. Any Cross-Site Scripting (XSS) vulnerability allows an attacker to exfiltrate the JWT session and take over the user account.",
            "poc_steps": "1. Log into InvoEase at http://localhost:3000.\n2. Open browser developer console (F12) -> Console.\n3. Execute 'document.cookie'.\n4. In Lab Mode, 'invoease_token=<jwt_value>' is immediately visible and readable via JavaScript.",
            "root_cause": "The Express cookie dispatcher fails to configure the 'httpOnly: true' and 'sameSite: \"strict\"' security flags when setting the session cookie.",
            "remediation": "Set security flags in Express response cookie:\nres.cookie('invoease_token', token, {\n  httpOnly: true,\n  secure: process.env.NODE_ENV === 'production',\n  sameSite: 'strict',\n  maxAge: 12 * 60 * 60 * 1000\n});"
        },
        {
            "id": "SEC-A03",
            "owasp_code": "A03:2021",
            "owasp_title": "Injection",
            "vuln_title": "SQL Injection in Dashboard Search & Stored XSS in Invoice Notes",
            "endpoint": "GET /api/invoices?search=... | POST /api/invoices (notes)",
            "severity": "HIGH",
            "cvss": 8.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "impact": "Unsanitized user search input is concatenated directly into SQL statements, allowing query logic manipulation and arbitrary data extraction. Furthermore, notes and descriptions render unescaped HTML, enabling Stored XSS.",
            "poc_steps": "SQLi Reproduction:\n1. On Dashboard, enter search query: ' OR 1=1 --\n2. In Lab Mode, the server query becomes: SELECT * FROM invoices WHERE (client_name LIKE '%' OR 1=1 --%'), returning all invoices across all users.\nXSS Reproduction:\n1. In Invoice Builder, set Notes to: <b onmouseover=alert(1)>Hover Test</b>\n2. Note renders unescaped in live A4 preview.",
            "root_cause": "Dynamic query string concatenation in server.js ('query += ... WHERE client_name LIKE %' + search + '%') instead of prepared statements. Frontend uses unescaped innerHTML rather than textContent.",
            "remediation": "1. Use parameterized queries with SQLite '?' place-holders: db.all(query, [userId, searchPattern, searchPattern]).\n2. In frontend preview rendering, escape all user strings or assign through textContent rather than raw innerHTML."
        },
        {
            "id": "SEC-A04",
            "owasp_code": "A04:2021",
            "owasp_title": "Insecure Design",
            "vuln_title": "Business Logic Flaw: Negative Quantity & Price Parameter Tampering",
            "endpoint": "POST /api/invoices (Body: items, discount_rate)",
            "severity": "MEDIUM",
            "cvss": 6.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
            "impact": "The system accepts negative quantities (e.g. qty: -10) or arbitrary discounts exceeding 100% (e.g. discount: 150%), generating negative invoice balances and distorting financial reporting and tax liability metrics.",
            "poc_steps": "1. Send POST /api/invoices with payload:\n{\n  \"client_name\": \"Audit Corp\",\n  \"items\": [{\"desc\": \"Tampered Item\", \"qty\": -10, \"price\": 5000}],\n  \"discount_rate\": 150\n}\n2. In Lab Mode, invoice is accepted with Grand Total: -₹59,000, corrupting dashboard metrics.",
            "root_cause": "Lack of server-side domain constraint validation. The backend trusts client calculations and does not enforce mathematical invariants (quantity > 0, price >= 0, discount 0-100%).",
            "remediation": "Implement strict server-side boundary validation:\n1. Verify every line item has qty > 0 and price >= 0.\n2. Ensure discount_rate is bounded between 0 and 100.\n3. Recalculate all tax and total fields authoritatively on the backend."
        },
        {
            "id": "SEC-A05",
            "owasp_code": "A05:2021",
            "owasp_title": "Security Misconfiguration",
            "vuln_title": "Sensitive Environment Information Disclosure & Missing Hardening Headers",
            "endpoint": "GET /api/debug/environment | HTTP Response Headers",
            "severity": "LOW",
            "cvss": 4.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
            "impact": "Exposition of internal runtime configuration, memory metrics, and OS architecture. Additionally, responses lack standard security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options), exposing the application to clickjacking.",
            "poc_steps": "1. Send GET request to /api/debug/environment.\n2. In Lab Mode, the server responds with full JSON dump of Node version, platform, memory usage, and internal environment flags.\n3. Inspect response headers on index.html: X-Frame-Options is missing, allowing iframe embedding.",
            "root_cause": "Development debug endpoints deployed into production routing without access controls. Security response headers middleware absent.",
            "remediation": "1. Disable /api/debug/environment in production environments (return 404).\n2. Enforce standard security headers:\nres.setHeader('X-Frame-Options', 'DENY');\nres.setHeader('X-Content-Type-Options', 'nosniff');\nres.setHeader('Content-Security-Policy', \"default-src 'self' ...\");"
        },
        {
            "id": "SEC-A06",
            "owasp_code": "A06:2021",
            "owasp_title": "Vulnerable and Outdated Components",
            "vuln_title": "Public Dependency Inventory Exposure & Supply Chain Audit",
            "endpoint": "GET /api/system/dependencies",
            "severity": "LOW",
            "cvss": 3.7,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "impact": "An unauthenticated or low-privileged user can retrieve the exact versions of all npm dependencies in package.json, facilitating targeted reconnaissance against known CVEs.",
            "poc_steps": "1. Send GET /api/system/dependencies.\n2. Server returns JSON manifest listing 'bcryptjs', 'express', 'sqlite3', 'jsonwebtoken' and their version numbers without administrative authentication.",
            "root_cause": "The dependency metadata endpoint lacks administrative role verification.",
            "remediation": "1. Restrict /api/system/dependencies to authenticated users with role === 'admin'.\n2. Periodically run automated vulnerability scanning ('npm audit') and Dependabot in CI/CD pipeline."
        },
        {
            "id": "SEC-A07",
            "owasp_code": "A07:2021",
            "owasp_title": "Identification & Authentication Failures",
            "vuln_title": "Username Enumeration via Differential Error Messages & Missing Rate Limiting",
            "endpoint": "POST /api/auth/login",
            "severity": "MEDIUM",
            "cvss": 6.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "impact": "Authentication endpoint discloses whether an account exists based on distinct error messages ('User does not exist' vs 'Incorrect password'). Absence of rate-limiting enables automated brute-force attacks.",
            "poc_steps": "1. Submit login request for non-existent user 'fake_user_123' -> Response: HTTP 401 'User does not exist.'\n2. Submit login request for valid user 'alice_dev' with bad password -> Response: HTTP 401 'Incorrect password.'\n3. Observe that valid usernames can be systematically enumerated.",
            "root_cause": "Authentication controller branches error messages based on database lookup results rather than returning generic responses. Rate limiter is disabled in Lab Mode.",
            "remediation": "1. Return a unified generic error message: 'Invalid username or password.' regardless of failure cause.\n2. Apply 'express-rate-limit' to restrict consecutive failed attempts (e.g. max 5 requests per 5 minutes per IP)."
        },
        {
            "id": "SEC-A08",
            "owasp_code": "A08:2021",
            "owasp_title": "Software and Data Integrity Failures",
            "vuln_title": "Unrestricted File Upload in Company Logo Branding Feature",
            "endpoint": "POST /api/upload/logo",
            "severity": "MEDIUM",
            "cvss": 6.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
            "impact": "Users can upload non-image files (.html, .svg, .js) with arbitrary extensions into the public /uploads directory, potentially enabling Cross-Site Scripting or HTML injection when rendered by other users.",
            "poc_steps": "1. In Invoice Builder, use the logo file uploader.\n2. Select a file containing HTML/JavaScript (e.g. test.html).\n3. In Lab Mode, the file is saved directly to public/uploads/ and returned as a valid file URL.",
            "root_cause": "The multer file upload middleware does not validate MIME types or file extensions against a strict whitelist before committing files to disk.",
            "remediation": "Implement strict upload validation in Secure Mode:\n1. Whitelist only 'image/png', 'image/jpeg', 'image/webp'.\n2. Inspect both MIME type and file extension.\n3. Sanitize file names to randomized UUIDs and store outside the web root if possible."
        },
        {
            "id": "SEC-A09",
            "owasp_code": "A09:2021",
            "owasp_title": "Security Logging & Monitoring Failures",
            "vuln_title": "Insufficient Audit Logging of Authorization Failures & Critical Actions",
            "endpoint": "Audit Trail (/api/security/logs)",
            "severity": "LOW",
            "cvss": 3.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
            "impact": "Failed authentication spikes, unauthorized invoice deletions, and cross-account access attempts are not consistently logged with IP and timestamp metadata, preventing timely incident detection.",
            "poc_steps": "1. Trigger failed login attempts and unauthorized IDOR requests.\n2. In Lab Mode, examine /api/security/logs; critical unauthorized requests are omitted from audit storage.",
            "root_cause": "Security event logging functions are only selectively called or bypassed during controller failures.",
            "remediation": "Implement centralized structured logging:\nRecord timestamp, source IP, authenticated user ID, action name, status (SUCCESS/BLOCKED), and request context into 'audit_logs' table on all security-relevant endpoints."
        },
        {
            "id": "SEC-A10",
            "owasp_code": "A10:2021",
            "owasp_title": "Server-Side Request Forgery (SSRF)",
            "vuln_title": "Blind Server-Side Request Forgery via Remote Logo URL Fetcher",
            "endpoint": "POST /api/fetch-remote-logo",
            "severity": "HIGH",
            "cvss": 8.6,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
            "impact": "The server fetches arbitrary URLs provided by the client, allowing attackers to probe internal loopback services (127.0.0.1, localhost), scan internal network ports, or access cloud metadata services (169.254.169.254).",
            "poc_steps": "1. In Invoice Builder, use 'Fetch from URL' with payload:\n{\"url\": \"http://127.0.0.1:3000/api/security/mode\"}\n2. In Lab Mode, the server issues a GET request to its own internal port and returns the internal API response preview to the user.",
            "root_cause": "The backend issues HTTP requests directly using node's 'http' / 'https' modules without validating the target IP against private, loopback, or link-local address spaces.",
            "remediation": "Enforce strict SSRF protection in Secure Mode:\n1. Parse target hostname and verify protocol is strictly http or https.\n2. Resolve DNS and block loopback (127.0.0.0/8, ::1), RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and AWS/cloud metadata (169.254.169.254)."
        }
    ]

    # =============================================================
    # SHEET 1: EXECUTIVE SUMMARY & VULNERABILITY DASHBOARD
    # =============================================================
    ws1 = wb.active
    ws1.title = "Executive_Summary"
    ws1.views.sheetView[0].showGridLines = True

    # 1. Header Banner
    ws1.merge_cells("A1:I1")
    cell_title = ws1["A1"]
    cell_title.value = "INVOEASE PRO - OWASP TOP 10 MANUAL SECURITY AUDIT REPORT"
    cell_title.font = FONT_TITLE
    cell_title.fill = NAVY_HEADER
    cell_title.alignment = Alignment(horizontal="left", vertical="center", indent=1)
    ws1.row_dimensions[1].height = 40

    # 2. Metadata Box (Rows 3-5)
    meta_items = [
        ("Target System:", "InvoEase Pro (Freelance Billing & GST Invoicing Engine)", "Assessment Date:", "October 15, 2026"),
        ("Base URL:", "http://localhost:3000", "Auditor / Engine:", "Antigravity Security Suite"),
        ("Methodology:", "OWASP Web Security Testing Guide (WSTG v4.2) / OWASP Top 10: 2021", "Assessment Type:", "Manual Grey-Box Web Application Penetration Test")
    ]

    for i, row_data in enumerate(meta_items, start=3):
        ws1.row_dimensions[i].height = 20
        # Col A: Label
        ws1[f"A{i}"].value = row_data[0]
        ws1[f"A{i}"].font = FONT_METADATA_LABEL
        ws1[f"A{i}"].alignment = Alignment(vertical="center")
        # Col B-D: Value
        ws1.merge_cells(f"B{i}:D{i}")
        ws1[f"B{i}"].value = row_data[1]
        ws1[f"B{i}"].font = FONT_METADATA_VAL
        ws1[f"B{i}"].alignment = Alignment(vertical="center")
        # Col E: Label
        ws1[f"E{i}"].value = row_data[2]
        ws1[f"E{i}"].font = FONT_METADATA_LABEL
        ws1[f"E{i}"].alignment = Alignment(vertical="center")
        # Col F-H: Value
        ws1.merge_cells(f"F{i}:H{i}")
        ws1[f"F{i}"].value = row_data[3]
        ws1[f"F{i}"].font = FONT_METADATA_VAL
        ws1[f"F{i}"].alignment = Alignment(vertical="center")

    # 3. Severity Distribution KPI Summary (Row 7)
    ws1.row_dimensions[7].height = 28
    kpis = [
        ("A7", "B7", "CRITICAL: 0", PatternFill("solid", fgColor="FEE2E2"), Font(name="Calibri", size=11, bold=True, color="991B1B")),
        ("C7", "D7", "HIGH: 3", PatternFill("solid", fgColor="FEE2E2"), Font(name="Calibri", size=11, bold=True, color="991B1B")),
        ("E7", "F7", "MEDIUM: 4", PatternFill("solid", fgColor="FEF3C7"), Font(name="Calibri", size=11, bold=True, color="92400E")),
        ("G7", "H7", "LOW / INFO: 3", PatternFill("solid", fgColor="ECFDF5"), Font(name="Calibri", size=11, bold=True, color="065F46")),
        ("I7", "I7", "TOTAL: 10", PatternFill("solid", fgColor="E2E8F0"), Font(name="Calibri", size=11, bold=True, color="1E293B"))
    ]
    for start_c, end_c, text, fill, font in kpis:
        if start_c != end_c:
            ws1.merge_cells(f"{start_c}:{end_c}")
        cell = ws1[start_c]
        cell.value = text
        cell.fill = fill
        cell.font = font
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = BORDER_ALL

    # 4. Summary Table Header (Row 9)
    headers_s1 = [
        ("A9", "Finding ID"),
        ("B9", "OWASP Category"),
        ("C9", "Vulnerability Finding Name"),
        ("D9", "Affected Endpoint"),
        ("E9", "Severity"),
        ("F9", "CVSS v3.1"),
        ("G9", "Lab Mode (Auditable)"),
        ("H9", "Secure Mode (Hardened)"),
        ("I9", "Detailed Audit")
    ]
    ws1.row_dimensions[9].height = 26
    for pos, h_title in headers_s1:
        cell = ws1[pos]
        cell.value = h_title
        cell.font = FONT_HEADER
        cell.fill = NAVY_SUBHEADER
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = BORDER_ALL

    # 5. Populate Data Rows (Rows 10 to 19)
    for idx, f in enumerate(findings, start=10):
        ws1.row_dimensions[idx].height = 24
        is_zebra = (idx % 2 == 0)
        row_fill = ROW_ZEBRA_FILL if is_zebra else WHITE_FILL

        # Col A: ID
        cell_a = ws1[f"A{idx}"]
        cell_a.value = f["id"]
        cell_a.font = FONT_CODE
        cell_a.alignment = Alignment(horizontal="center", vertical="center")
        cell_a.fill = row_fill
        cell_a.border = BORDER_ALL

        # Col B: OWASP Code & Title
        cell_b = ws1[f"B{idx}"]
        cell_b.value = f"{f['owasp_code']} - {f['owasp_title']}"
        cell_b.font = FONT_BOLD
        cell_b.alignment = Alignment(horizontal="left", vertical="center")
        cell_b.fill = row_fill
        cell_b.border = BORDER_ALL

        # Col C: Vuln Title
        cell_c = ws1[f"C{idx}"]
        cell_c.value = f["vuln_title"]
        cell_c.font = FONT_REGULAR
        cell_c.alignment = Alignment(horizontal="left", vertical="center")
        cell_c.fill = row_fill
        cell_c.border = BORDER_ALL

        # Col D: Endpoint
        cell_d = ws1[f"D{idx}"]
        cell_d.value = f["endpoint"]
        cell_d.font = FONT_CODE
        cell_d.alignment = Alignment(horizontal="left", vertical="center")
        cell_d.fill = row_fill
        cell_d.border = BORDER_ALL

        # Col E: Severity (Color-coded)
        cell_e = ws1[f"E{idx}"]
        cell_e.value = f["severity"]
        cell_e.alignment = Alignment(horizontal="center", vertical="center")
        if f["severity"] == "HIGH":
            cell_e.fill = FILL_HIGH
            cell_e.font = FONT_HIGH
        elif f["severity"] == "MEDIUM":
            cell_e.fill = FILL_MEDIUM
            cell_e.font = FONT_MEDIUM
        else:
            cell_e.fill = FILL_LOW
            cell_e.font = FONT_LOW
        cell_e.border = BORDER_ALL

        # Col F: CVSS
        cell_f = ws1[f"F{idx}"]
        cell_f.value = f["cvss"]
        cell_f.font = FONT_BOLD
        cell_f.alignment = Alignment(horizontal="center", vertical="center")
        cell_f.fill = row_fill
        cell_f.border = BORDER_ALL

        # Col G: Lab Mode State
        cell_g = ws1[f"G{idx}"]
        cell_g.value = "Vulnerable (Active in Lab)"
        cell_g.font = Font(name="Calibri", size=10, bold=True, color="DC2626")
        cell_g.alignment = Alignment(horizontal="center", vertical="center")
        cell_g.fill = row_fill
        cell_g.border = BORDER_ALL

        # Col H: Secure Mode State
        cell_h = ws1[f"H{idx}"]
        cell_h.value = "Remediated (Hardened)"
        cell_h.font = Font(name="Calibri", size=10, bold=True, color="059669")
        cell_h.alignment = Alignment(horizontal="center", vertical="center")
        cell_h.fill = row_fill
        cell_h.border = BORDER_ALL

        # Col I: Interactive Hyperlink to Sheet 2
        target_s2_row = idx - 10 + 2
        cell_i = ws1[f"I{idx}"]
        cell_i.value = f'=HYPERLINK("#\'Technical_Findings\'!A{target_s2_row}", "View Finding >>")'
        cell_i.font = FONT_LINK
        cell_i.alignment = Alignment(horizontal="center", vertical="center")
        cell_i.fill = row_fill
        cell_i.border = BORDER_ALL

    # Column Widths for Sheet 1
    col_widths_s1 = {
        "A": 12,
        "B": 28,
        "C": 36,
        "D": 38,
        "E": 14,
        "F": 12,
        "G": 22,
        "H": 22,
        "I": 18
    }
    for col, width in col_widths_s1.items():
        ws1.column_dimensions[col].width = width

    # Freeze panes below header on Sheet 1
    ws1.freeze_panes = "A10"


    # =============================================================
    # SHEET 2: DETAILED TECHNICAL FINDINGS & REMEDIATION
    # =============================================================
    ws2 = wb.create_sheet(title="Technical_Findings")
    ws2.views.sheetView[0].showGridLines = True

    # 1. Header Row (Row 1)
    headers_s2 = [
        ("A1", "ID"),
        ("B1", "OWASP Category & Vulnerability Name"),
        ("C1", "Severity & CVSS Score"),
        ("D1", "Affected Endpoint & Method"),
        ("E1", "Vulnerability Impact & Observations"),
        ("F1", "Step-by-Step Manual Reproduction Guide"),
        ("G1", "Technical Root Cause"),
        ("H1", "Remediation & Secure Mode Fix"),
        ("I1", "Navigation")
    ]
    ws2.row_dimensions[1].height = 30
    for pos, h_title in headers_s2:
        cell = ws2[pos]
        cell.value = h_title
        cell.font = FONT_HEADER
        cell.fill = NAVY_HEADER
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = BORDER_ALL

    # 2. Populate Findings (Rows 2 to 11)
    for idx, f in enumerate(findings, start=2):
        ws2.row_dimensions[idx].height = 110
        is_zebra = (idx % 2 == 0)
        row_fill = ROW_ZEBRA_FILL if is_zebra else WHITE_FILL

        # Col A: ID (Anchor)
        cell_a = ws2[f"A{idx}"]
        cell_a.value = f["id"]
        cell_a.font = FONT_CODE
        cell_a.alignment = Alignment(horizontal="center", vertical="top")
        cell_a.fill = row_fill
        cell_a.border = BORDER_ALL

        # Col B: OWASP & Vuln Title
        cell_b = ws2[f"B{idx}"]
        cell_b.value = f"{f['owasp_code']} - {f['owasp_title']}\n\n{f['vuln_title']}"
        cell_b.font = FONT_BOLD
        cell_b.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        cell_b.fill = row_fill
        cell_b.border = BORDER_ALL

        # Col C: Severity Badge
        cell_c = ws2[f"C{idx}"]
        cell_c.value = f"{f['severity']}\n(CVSS: {f['cvss']})\n\n{f['cvss_vector']}"
        cell_c.alignment = Alignment(horizontal="center", vertical="top", wrap_text=True)
        if f["severity"] == "HIGH":
            cell_c.fill = FILL_HIGH
            cell_c.font = FONT_HIGH
        elif f["severity"] == "MEDIUM":
            cell_c.fill = FILL_MEDIUM
            cell_c.font = FONT_MEDIUM
        else:
            cell_c.fill = FILL_LOW
            cell_c.font = FONT_LOW
        cell_c.border = BORDER_ALL

        # Col D: Affected Endpoint
        cell_d = ws2[f"D{idx}"]
        cell_d.value = f["endpoint"]
        cell_d.font = FONT_CODE
        cell_d.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        cell_d.fill = row_fill
        cell_d.border = BORDER_ALL

        # Col E: Impact & Observation
        cell_e = ws2[f"E{idx}"]
        cell_e.value = f["impact"]
        cell_e.font = FONT_REGULAR
        cell_e.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        cell_e.fill = row_fill
        cell_e.border = BORDER_ALL

        # Col F: Reproduction Steps
        cell_f = ws2[f"F{idx}"]
        cell_f.value = f["poc_steps"]
        cell_f.font = FONT_REGULAR
        cell_f.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        cell_f.fill = row_fill
        cell_f.border = BORDER_ALL

        # Col G: Root Cause
        cell_g = ws2[f"G{idx}"]
        cell_g.value = f["root_cause"]
        cell_g.font = FONT_REGULAR
        cell_g.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        cell_g.fill = row_fill
        cell_g.border = BORDER_ALL

        # Col H: Remediation
        cell_h = ws2[f"H{idx}"]
        cell_h.value = f["remediation"]
        cell_h.font = FONT_REGULAR
        cell_h.alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)
        cell_h.fill = row_fill
        cell_h.border = BORDER_ALL

        # Col I: Back to Summary Link
        s1_source_row = idx - 2 + 10
        cell_i = ws2[f"I{idx}"]
        cell_i.value = f'=HYPERLINK("#\'Executive_Summary\'!A{s1_source_row}", "<< Back to Summary")'
        cell_i.font = FONT_LINK
        cell_i.alignment = Alignment(horizontal="center", vertical="top")
        cell_i.fill = row_fill
        cell_i.border = BORDER_ALL

    # Column Widths for Sheet 2
    col_widths_s2 = {
        "A": 12,
        "B": 28,
        "C": 20,
        "D": 28,
        "E": 38,
        "F": 46,
        "G": 34,
        "H": 40,
        "I": 18
    }
    for col, width in col_widths_s2.items():
        ws2.column_dimensions[col].width = width

    # Freeze top row on Sheet 2
    ws2.freeze_panes = "A2"

    # Save workbook
    wb.save(output_file)
    print(f"Report generated successfully: {output_file}")

if __name__ == "__main__":
    build_vapt_report()
