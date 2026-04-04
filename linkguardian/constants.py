RATE_LIMIT = 4  # VirusTotal Free Tier: 4 requests per minute
TIME_WINDOW = 60  # Time window in seconds (1 minute)
URL_REGEX = r'\b(?:[a-z][\w.+-]+:(?:/{1,3}|[?+]?[a-z0-9%]))(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s\x60!()\[\]{};:\'\".,<>?«»“”‘’])'
IPV4_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
IPV6_REGEX = r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'
# Exclude Quttera engine due to false positives, and calculate totals
# Exclude CRDF, who returns 0.0.0.0 as Malicious
EXCLUDED_ANALYZERS = ["Quttera", "CRDF"]
VIRUS_TOTAL_API = "https://www.virustotal.com/api/v3"