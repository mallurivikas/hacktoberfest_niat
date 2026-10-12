"""
scanner1.py — Compatibility forwarder to unified scanner.py

Maintains backwards compatibility for any modules referencing scanner1.
"""

from scanner import scan, scan_url, run_security_scan, save_results

if __name__ == "__main__":
    import scanner
    target = input("Enter target URL: ").strip() or "https://example.com"
    scanner.scan(target)
