def create_finding(title, severity, evidence, source="SiteSentinel"):
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "source": source
    }


def check_security_headers(headers):
    findings = []

    # Normalize header names
    headers = {
        key.lower(): value
        for key, value in headers.items()
    }

    # --------------------------------
    # Content Security Policy
    # --------------------------------
    if "content-security-policy" not in headers:
        findings.append(
            create_finding(
                title="Content Security Policy Missing",
                severity="medium",
                evidence="Content-Security-Policy header was not found."
            )
        )

    # --------------------------------
    # HSTS
    # --------------------------------
    if "strict-transport-security" not in headers:
        findings.append(
            create_finding(
                title="HSTS Missing",
                severity="medium",
                evidence="Strict-Transport-Security header was not found."
            )
        )

    # --------------------------------
    # MIME sniffing protection
    # --------------------------------
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(
            create_finding(
                title="MIME Sniffing Protection Missing",
                severity="low",
                evidence="X-Content-Type-Options: nosniff was not found."
            )
        )

    # --------------------------------
    # Clickjacking protection
    # --------------------------------
    csp = headers.get("content-security-policy", "")
    x_frame = headers.get("x-frame-options", "")

    if not x_frame and "frame-ancestors" not in csp.lower():
        findings.append(
            create_finding(
                title="Clickjacking Protection Missing",
                severity="medium",
                evidence=(
                    "Neither X-Frame-Options nor a CSP "
                    "frame-ancestors directive was found."
                )
            )
        )

    # --------------------------------
    # Referrer Policy
    # --------------------------------
    if "referrer-policy" not in headers:
        findings.append(
            create_finding(
                title="Referrer Policy Missing",
                severity="low",
                evidence="Referrer-Policy header was not found."
            )
        )

    # --------------------------------
    # Permissions Policy
    # --------------------------------
    if "permissions-policy" not in headers:
        findings.append(
            create_finding(
                title="Permissions Policy Missing",
                severity="low",
                evidence="Permissions-Policy header was not found."
            )
        )

    # --------------------------------
    # Server information disclosure
    # --------------------------------
    if "server" in headers:
        findings.append(
            create_finding(
                title="Server Information Exposed",
                severity="info",
                evidence=f"Server header exposes: {headers['server']}"
            )
        )

    return findings


def check_cookie_security(cookies):
    findings = []

    for cookie in cookies:

        cookie_name = cookie.get("name", "Unknown")

        # Secure
        if not cookie.get("secure"):
            findings.append(
                create_finding(
                    title="Cookie Missing Secure Flag",
                    severity="medium",
                    evidence=(
                        f"Cookie '{cookie_name}' does not "
                        "use the Secure flag."
                    )
                )
            )

        # HttpOnly
        if not cookie.get("httponly"):
            findings.append(
                create_finding(
                    title="Cookie Missing HttpOnly Flag",
                    severity="medium",
                    evidence=(
                        f"Cookie '{cookie_name}' does not "
                        "use the HttpOnly flag."
                    )
                )
            )

        # SameSite
        if not cookie.get("samesite"):
            findings.append(
                create_finding(
                    title="Cookie Missing SameSite Attribute",
                    severity="low",
                    evidence=(
                        f"Cookie '{cookie_name}' does not "
                        "specify SameSite."
                    )
                )
            )

    return findings