# verification_server.py

import sqlite3
import json
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
DATABASE_FILE = 'certificates.db'

def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS wipes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT NOT NULL UNIQUE,
            device_info TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/api/register_wipe', methods=['POST'])
def register_wipe_api():
    cert_data = request.json
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO wipes (certificate_id, device_info, timestamp) VALUES (?, ?, ?)",
            (cert_data['certificateId'], json.dumps(cert_data['deviceInfo']), cert_data['timestampUTC'])
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Certificate registered."}), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/verify/<certificate_id>')
def verify_certificate_web(certificate_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT device_info, timestamp FROM wipes WHERE certificate_id = ?", (certificate_id,))
    record = cursor.fetchone()
    conn.close()

    if record:
        device_info = json.loads(record[0])
        html = f"""
        <html><body style='font-family: sans-serif; text-align: center; padding: 20px;'>
            <h1 style='color: #27ae60;'>✅ Certificate Verified</h1>
            <h2>ID: {certificate_id}</h2>
            <div style='border: 1px solid #ccc; padding: 15px; display: inline-block; text-align: left;'>
                <p><strong>Device:</strong> {device_info.get('deviceString', 'N/A')}</p>
                <p><strong>Method:</strong> {device_info.get('wipeMethod', 'N/A')}</p>
                <p><strong>Timestamp (UTC):</strong> {record[1]}</p>
            </div>
        </body></html>
        """
        return render_template_string(html)
    else:
        return "<h1 style='color: #c0392b;'>❌ Certificate Invalid or Not Found</h1>", 404

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)