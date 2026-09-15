from pathlib import Path

BASE_DIR = Path(__file__).parent
MODELS_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data"
SAMPLES_DIR = DATA_DIR / "sample_qr_codes"

MODELS_DIR.mkdir(exist_ok=True)
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

HUGGINGFACE_MODEL_ID = "pirocheto/phishing-url-detection"
HUGGINGFACE_MODEL_FILE = "sklearn_model.joblib"
LOCAL_MODEL_PATH = MODELS_DIR / "phishing_model.joblib"

URL_LENGTH_SUSPICIOUS = 75
ENTROPY_SUSPICIOUS = 4.5
REDIRECT_CHAIN_MAX = 10
REQUEST_TIMEOUT = 10
SANDBOX_PREVIEW_MAX_CHARS = 2000

THREAT_SCORE_LOW = 40
THREAT_SCORE_HIGH = 70

SUSPICIOUS_TOKENS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "banking", "credential", "auth", "suspend", "restrict",
    "unlock", "validate", "password", "billing", "paypal", "apple",
    "microsoft", "amazon", "netflix", "facebook", "instagram",
]

HOMOGLYPHS = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u03b1": "a",  # Greek α
    "\u03bf": "o",  # Greek ο
    "\u03c1": "p",  # Greek ρ
    "\u0251": "a",  # Latin ɑ
    "\u2160": "I",  # Roman numeral I
    "\u2161": "II", # Roman numeral II
    "\u2162": "III",# Roman numeral III
    "\u2163": "IV", # Roman numeral IV
    "\u2164": "V",  # Roman numeral V
    "\u2165": "VI", # Roman numeral VI
    "\u2166": "VII",# Roman numeral VII
    "\u2167": "VIII",# Roman numeral VIII
    "\u2168": "IX", # Roman numeral IX
    "\u2169": "X",  # Roman numeral X
}

SUSPICIOUS_SCHEMES = {
    "WIFI": "Auto-connect Wi-Fi network (credential exfiltration risk)",
    "SMSTO": "Pre-filled SMS message (social engineering)",
    "TEL": "Auto-dial phone number (vishing risk)",
    "MATMSG": "Email message payload",
    "BEGIN:VCARD": "Contact card injection",
    "BEGIN:VCALENDAR": "Calendar event injection",
}

QR_DECODE_CONFIDENCE_THRESHOLD = 0.6
