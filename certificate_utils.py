# certificate_utils.py
#
# Handles certificate data generation, signing, PDF creation with QR codes, and verification.

import json
import hashlib
import datetime
import base64
import binascii
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
import qrcode

def _generate_pdf_with_qr(cert_data: dict, pdf_filename: str):
    """Writes a PDF certificate with JSON data and a scannable QR code."""
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.drawString(1 * inch, height - 1 * inch, "Secure Data Sanitization Certificate")

    pretty_json = json.dumps(cert_data, indent=4)
    text = c.beginText(1 * inch, height - 1.5 * inch)
    text.setFont("Courier", 9)
    for line in pretty_json.splitlines():
        text.textLine(line)
    c.drawText(text)

    # Generate QR code pointing to a hypothetical verification URL
    qr_data = (
        f"https://verify.example.com/?"
        f"cert_id={cert_data['certificateId']}&"
        f"sig={cert_data['verification']['signature_sha256_rsa_b64']}"
    )
    qr_img = qrcode.make(qr_data, box_size=15, border=2)
    qr_img_path = "temp_qr_for_pdf.png"
    qr_img.save(qr_img_path)

    c.drawImage(qr_img_path, 1 * inch, 1.5 * inch, width=1.5 * inch, height=1.5 * inch)
    c.setFont("Helvetica", 10)
    c.drawString(1 * inch, 1.3 * inch, "Scan to verify certificate integrity.")
    os.remove(qr_img_path) # Clean up temporary QR image

    c.save()

def generate_certificate(device_info: dict, private_key):
    """Creates, signs, and saves a certificate as JSON and PDF."""
    cert_data = {
        "certificateId": f"CW-{int(datetime.datetime.utcnow().timestamp())}",
        "toolVersion": "CertiWipe Pro v1.1",
        "timestampUTC": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "deviceInfo": device_info,
        "wipeStandard": "NIST SP 800-88 Rev. 1",
    }

    cert_bytes = json.dumps(cert_data, sort_keys=True).encode('utf-8')
    data_hash = hashlib.sha256(cert_bytes).digest()
    signature = private_key.sign(data_hash, padding.PKCS1v15(), hashes.SHA256())

    cert_data["verification"] = {
        "hash_sha256": data_hash.hex(),
        "signature_sha256_rsa_b64": base64.b64encode(signature).decode('ascii')
    }

    file_basename = f"CertiWipe-Certificate-{cert_data['certificateId']}"
    json_filename = f"{file_basename}.json"
    pdf_filename = f"{file_basename}.pdf"

    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump(cert_data, f, indent=4)
    
    _generate_pdf_with_qr(cert_data, pdf_filename)
    
    return json_filename, pdf_filename

def verify_certificate(json_path: str, public_key):
    """
    Verifies a certificate file.
    Returns a tuple: (is_valid: bool, message: str)
    """
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            cert = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return False, "File not found or is not a valid JSON document."

    verif_block = cert.get("verification")
    if not verif_block or "hash_sha256" not in verif_block or "signature_sha256_rsa_b64" not in verif_block:
        return False, "Certificate format is invalid: missing verification data."

    cert_without_verif = dict(cert)
    del cert_without_verif["verification"]

    recomputed_bytes = json.dumps(cert_without_verif, sort_keys=True).encode('utf-8')
    recomputed_hash = hashlib.sha256(recomputed_bytes).digest()

    stored_hash = bytes.fromhex(verif_block["hash_sha256"])
    if stored_hash != recomputed_hash:
        return False, "HASH MISMATCH: The certificate's content has been altered."
    
    try:
        signature = base64.b64decode(verif_block["signature_sha256_rsa_b64"])
        public_key.verify(signature, recomputed_hash, padding.PKCS1v15(), hashes.SHA256())
        return True, "VALID: The signature is cryptographically valid and content is authentic."
    except (InvalidSignature, ValueError, binascii.Error):
        return False, "SIGNATURE INVALID: The signature could not be verified."