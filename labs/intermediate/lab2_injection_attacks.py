[...file contents before xss_payloads...]
        xss_payloads = [
            "alert('XSS')",
            '<img onerror="alert(1)"/>',
            '<svg onload="alert(\'XSS\')">',
            '\'\"><script>alert(1)</script>',
        ]
[...file contents after xss_payloads...]
