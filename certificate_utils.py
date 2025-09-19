# certificate_utils.py

import json
import hashlib
import datetime
import base64
import qrcode
from io import BytesIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors # <-- ADDED for link color

def canonical_json_bytes(obj: dict) -> bytes:
    """Return deterministic JSON bytes for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')

def generate_certificate(device_info: dict, private_key):
    """Creates and signs a certificate, returning the data and filenames."""
    timestamp_str = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    json_file = f"CertiWipe-{timestamp_str}.json"
    pdf_file = f"CertiWipe-{timestamp_str}.pdf"

    cert_data = {
        "certificateId": f"CW-{int(datetime.datetime.utcnow().timestamp())}",
        "toolVersion": "CertiWipe v1.0 Pro",
        "timestampUTC": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "deviceInfo": device_info,
        "wipeStandard": "NIST SP 800-88 Rev. 1",
    }

    cert_bytes = canonical_json_bytes(cert_data)
    data_hash = hashlib.sha256(cert_bytes).digest()
    signature = private_key.sign(data_hash, padding.PKCS1v15(), hashes.SHA256())

    cert_data["verification"] = {
        "hash_sha256": data_hash.hex(),
        "signature_sha256_rsa_b64": base64.b64encode(signature).decode('ascii')
    }

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(cert_data, f, indent=4)

    # For now, the URL is hardcoded to localhost as requested
    verification_url = f"http://127.0.0.1:5000/verify/{cert_data['certificateId']}"
    save_pdf_from_json(cert_data, pdf_file, verification_url)
    
    return cert_data, json_file, pdf_file

def save_pdf_from_json(cert_data: dict, pdf_filename: str, verification_url: str):
    """Writes a PDF with the certificate text, a QR code, and a clickable link."""
    pretty_json = json.dumps(cert_data, indent=4)
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(1 * inch, 10.5 * inch, "Secure Data Sanitization Certificate")
    
    text = c.beginText(1 * inch, 10 * inch)
    text.setFont("Courier", 9)
    for line in pretty_json.splitlines():
        text.textLine(line)
    c.drawText(text)

    # --- QR CODE GENERATION ---
    qr_image = qrcode.make(verification_url)
    buffer = BytesIO()
    qr_image.save(buffer, format="PNG")
    buffer.seek(0)

    qr_reader = ImageReader(buffer)
    c.drawImage(qr_reader, 1 * inch, 1.5 * inch, width=1.2*inch, height=1.2*inch)
    c.setFont("Helvetica", 9)
    c.drawString(2.3 * inch, 2.2 * inch, "Scan QR code or click the link below")
    c.drawString(2.3 * inch, 2.0 * inch, "to verify this certificate online.")
    
    # --- CLICKABLE LINK GENERATION ---
    c.setFont("Helvetica-Oblique", 9)
    c.setFillColor(colors.blue) # Set color to blue for the link
    link_x = 2.3 * inch
    link_y = 1.8 * inch
    c.drawString(link_x, link_y, verification_url)
    
    # Calculate the area for the link
    text_width = c.stringWidth(verification_url, "Helvetica-Oblique", 9)
    link_rect = (link_x, link_y, link_x + text_width, link_y + 10) # 10 is font height approximation

    # Create the clickable link area
    c.linkURL(verification_url, link_rect, relative=1)
    # --- END OF LINK GENERATION ---

    c.save()

def verify_certificate(json_path: str, public_key):
    """Verifies a certificate JSON file. Returns (bool, message)."""
    # This function remains unchanged
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            cert = json.load(f)
        
        verif = cert.get("verification")
        if not verif or "hash_sha256" not in verif or "signature_sha256_rsa_b64" not in verif:
            return False, "Verification block is missing or incomplete."

        stored_hash = bytes.fromhex(verif["hash_sha256"])
        signature = base64.b64decode(verif["signature_sha256_rsa_b64"])

        cert_without_verif = dict(cert)
        del cert_without_verif["verification"]
        
        recomputed_hash = hashlib.sha256(canonical_json_bytes(cert_without_verif)).digest()

        if stored_hash != recomputed_hash:
            return False, "Hash mismatch! Certificate content has been altered."

        public_key.verify(signature, recomputed_hash, padding.PKCS1v15(), hashes.SHA256())
        return True, "Certificate is authentic and content is valid."

    except Exception as e:
        return False, f"An unexpected error occurred: {e}"
