"""Generate sample QR codes for testing QRShield.

Run after setting up the conda environment:
    conda activate ./env
    python scripts/generate_samples.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import qrcode
except ImportError:
    print("Installing qrcode[pil]...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "qrcode[pil]"])
    import qrcode

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "sample_qr_codes"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLES = {
    "safe_url.png": "https://www.google.com",
    "phishing_url.png": "http://192.168.1.1/secure-login-verify-account-update.html",
    "wifi_payload.png": 'WIFI:T:WPA;S:FreePublicWiFi;P:password123;;',
    "shortener_url.png": "https://bit.ly/3xPhishing",
    "homograph_url.png": "https://pаypal.com/login",  # Cyrillic 'а'
    "sms_payload.png": "SMSTO:+15551234567:Click here to verify your account",
    "tel_payload.png": "TEL:+1-800-555-1234",
    "email_payload.png": "mailto:phisher@evil.com?subject=Urgent%20Verification&body=Click%20this%20link",
    "vcard_payload.png": "BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\nTEL:+1234567890\nEMAIL:john@example.com\nEND:VCARD",
    "text_payload.png": "Hello World - this is a plain text QR code",
}


def main():
    print(f"Generating {len(SAMPLES)} sample QR codes...")

    for filename, payload in SAMPLES.items():
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(payload)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        filepath = OUTPUT_DIR / filename
        img.save(str(filepath))
        print(f"  Created {filepath.name} ({len(payload)} bytes payload)")

    print(f"\nDone! QR codes saved to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
