"""Scoring constants for the documented MailWatch Tower model."""

CATEGORY_CAPS: dict[str, int] = {
    "sender_auth": 25,
    "links": 35,
    "attachments": 25,
    "content": 30,
    "external_intel": 50,
}

CATEGORY_TITLES: dict[str, str] = {
    "sender_auth": "Sender & Authentication",
    "links": "Links & External Intelligence",
    "attachments": "Attachments",
    "content": "Content & Social Engineering",
    "external_intel": "External Intelligence",
    "user_feedback": "User Feedback / Overrides",
}

MALICIOUS_FEEDBACK_POINTS = 50
MALICIOUS_FEEDBACK_CAP = 50
TRUSTED_SENDER_REMAINING_HEURISTIC_REDUCTION = 0.20
SAFE_BROWSING_MATCH_POINTS = 50

VERDICT_COLORS: dict[str, str] = {
    "Safe": "#188038",
    "Low Risk": "#4FC3F7",
    "Suspicious": "#FBC02D",
    "High Risk": "#F57C00",
    "Dangerous": "#D93025",
}

RISKY_EXECUTABLE_EXTENSIONS = {"exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "jar", "msi", "com"}
MACRO_OFFICE_EXTENSIONS = {"docm", "xlsm", "pptm"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "support"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
KNOWN_BRANDS = {"google", "microsoft", "paypal", "amazon", "apple", "github", "upwind", "linkedin", "docusign", "dropbox"}
