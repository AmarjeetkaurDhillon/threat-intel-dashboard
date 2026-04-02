def summarise_cve(cve_id, description):
    description_lower = description.lower()

    if "remote code execution" in description_lower or "rce" in description_lower:
        attack_type = "Remote Code Execution"
        action = "Apply vendor patch immediately and restrict network access to affected service."
    elif "privilege escalation" in description_lower:
        attack_type = "Privilege Escalation"
        action = "Apply patch immediately and audit user privilege assignments."
    elif "sql injection" in description_lower:
        attack_type = "SQL Injection"
        action = "Apply patch and review all database input validation."
    elif "denial of service" in description_lower or "dos" in description_lower:
        attack_type = "Denial of Service"
        action = "Apply patch and implement rate limiting on affected endpoints."
    elif "authentication bypass" in description_lower:
        attack_type = "Authentication Bypass"
        action = "Apply patch immediately and enforce multi-factor authentication."
    elif "buffer overflow" in description_lower:
        attack_type = "Buffer Overflow"
        action = "Apply vendor patch and consider disabling affected service until patched."
    elif "command injection" in description_lower:
        attack_type = "Command Injection"
        action = "Apply patch immediately and restrict access to affected systems."
    elif "cross-site" in description_lower or "xss" in description_lower:
        attack_type = "Cross-Site Scripting"
        action = "Apply patch and implement Content Security Policy headers."
    elif "information disclosure" in description_lower:
        attack_type = "Information Disclosure"
        action = "Apply patch and audit exposed data and access controls."
    else:
        attack_type = "Security Vulnerability"
        action = "Apply vendor patch and monitor systems for suspicious activity."

    summary = (
        f"1. Summary: This {attack_type} vulnerability allows attackers to compromise affected systems. "
        f"2. Affected: All systems running the vulnerable software version without the latest security patch. "
        f"3. Action: {action}"
    )
    return summary
