"""
FileScanner - A simple local file upload + virus/heuristic scanner (Flask, single-file)

Features
- Web UI to upload a file and scan it.
- Tries local ClamAV (via python-clamd) if available for real virus signatures.
- If ClamAV isn't available, falls back to heuristic checks:
  - File hashes (MD5/SHA1/SHA256)
  - PE/ELF/MZ header checks
  - Detection of suspicious keywords (eval, exec, base64, powershell, CreateRemoteThread...)
  - Entropy calculation (high entropy may indicate packed/encrypted payload)
  - Suspicious extension vs content mismatch
- Returns a clear result page listing findings and recommended actions.

Notes
- For reliable detection use ClamAV (install clamav and python-clamd). This app will try to use it if present.
- This project is for educational purposes and should not replace a proper AV product.

How to run (Linux)
1. Create a venv and install dependencies:
   python3 -m venv venv
   source venv/bin/activate
   pip install flask python-magic
   # optional for ClamAV integration:
   pip install pyclamd

2. (Optional) Install and enable ClamAV:
   sudo apt update
   sudo apt install clamav clamav-daemon
   sudo systemctl stop clamav-freshclam
   sudo freshclam
   sudo systemctl start clamav-freshclam
   sudo systemctl start clamav-daemon

3. Run the app:
   export FLASK_APP=file_scanner.py
   flask run --host=0.0.0.0 --port=5000

Open http://localhost:5000 in your browser and upload a file.

LICENSE: MIT (educational)

"""

from flask import Flask, request, render_template_string, redirect, url_for
import os
import hashlib
import math
import base64

# optional imports
try:
    import pyclamd
    CLAMD_AVAILABLE = True
except Exception:
    CLAMD_AVAILABLE = False

# optional: file type detection
try:
    import magic
    MAGIC_AVAILABLE = True
except Exception:
    MAGIC_AVAILABLE = False

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB limit
app.config['UPLOAD_FOLDER'] = '/tmp/filescanner_uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Utility functions ---
def hash_file(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def file_entropy(path, block_size=1024):
    # Shannon entropy
    with open(path, 'rb') as f:
        data = f.read()
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for c in freq:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

SUSPICIOUS_KEYWORDS = [
    b'eval(', b'exec(', b'base64', b'PowerShell', b'CreateRemoteThread', b'VirtualAlloc',
    b'LoadLibrary', b'GetProcAddress', b'WinExec', b'ShellExecute', b'cmd.exe', b'/c ',
    b'Invoke-Expression', b'Add-Type', b'Obfuscate', b'xor '
]

SUSPICIOUS_EXTENSIONS = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.msi']

def quick_heuristic_scan(path, filename):
    findings = []
    md5, sha1, sha256 = hash_file(path)
    findings.append(('hashes', {
        'md5': md5, 'sha1': sha1, 'sha256': sha256
    }))

    ent = file_entropy(path)
    findings.append(('entropy', ent))

    # check headers
    with open(path, 'rb') as f:
        head = f.read(512)
    head_lower = head.lower()
    if head.startswith(b'MZ'):
        findings.append(('header', 'PE/MZ header detected (likely Windows executable)'))
    elif head.startswith(b'\x7fELF'):
        findings.append(('header', 'ELF header detected (likely Linux binary)'))
    elif head.startswith(b'PK'):
        findings.append(('header', 'PK zip/jar/office archive detected'))

    # check extension mismatch
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    if ext and ext not in ['.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.zip', '.tar', '.gz', '.bz2', '.7z', '.docx', '.xlsx', '.pptx', '.csv']:
        findings.append(('extension', f'Uncommon extension: {ext}'))

    # suspicious keywords scan (only on small/medium files to avoid big memory use)
    size = os.path.getsize(path)
    if size <= 10 * 1024 * 1024:  # 10 MB
        with open(path, 'rb') as f:
            data = f.read()
        matches = []
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in data.lower():
                matches.append(kw.decode('latin-1', errors='ignore'))
        if matches:
            findings.append(('suspicious_strings', matches))

    # high entropy indicates packing/encryption
    if ent > 7.5:
        findings.append(('packed', 'High entropy (>{:.1f}) — may be packed/encrypted'.format(7.5)))

    # extension vs header mismatch: executable extension but not executable header
    if ext in SUSPICIOUS_EXTENSIONS and not head.startswith(b'MZ'):
        findings.append(('mismatch', f'File has executable extension {ext} but header not MZ'))

    # file type detection via libmagic if available
    if MAGIC_AVAILABLE:
        try:
            typ = magic.from_file(path)
            findings.append(('magic', typ))
        except Exception:
            pass

    return findings

# ClamAV scanning helper
def clam_scan(path):
    try:
        cd = pyclamd.ClamdAgnostic()
        # try ping
        cd.ping()
        # scan file
        res = cd.scan_file(path)
        # res is None if no virus; otherwise {'/path': ('FOUND', 'MalwareName')}
        if not res:
            return ('clean', None)
        else:
            entry = list(res.values())[0]
            return ('infected', entry)
    except Exception as e:
        return ('error', str(e))

# --- Web UI ---
INDEX_HTML = '''
<!doctype html>
<title>FileScanner - Upload and Scan</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
<div class="container py-5">
  <h1 class="mb-4">FileScanner</h1>
  <p>Upload a file and the app will scan it. If you have ClamAV running, it will use it.
  Otherwise a heuristic scan will run.</p>

  <form method="post" action="/scan" enctype="multipart/form-data">
    <div class="mb-3">
      <label class="form-label">Choose file to scan</label>
      <input class="form-control" type="file" name="file" required>
    </div>
    <div class="mb-3">
      <label class="form-label">Optional: enter a reference or note</label>
      <input class="form-control" type="text" name="note" placeholder="e.g. suspicious-email-attachment">
    </div>
    <button class="btn btn-primary" type="submit">Upload & Scan</button>
  </form>

  <hr/>
  <h5>Notes</h5>
  <ul>
    <li>This is an educational scanner. For production use, integrate a proper AV vendor.</li>
    <li>To enable signature-based scanning, install ClamAV and python-clamd; the app will auto-detect it.</li>
  </ul>
</div>
'''

RESULT_HTML = '''
<!doctype html>
<title>Scan Result</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
<div class="container py-4">
  <a href="/" class="btn btn-link">&larr; Back</a>
  <h1>Scan Result</h1>
  <p><strong>File:</strong> {{ filename }}</p>
  <p><strong>Size:</strong> {{ size }} bytes</p>
  <p><strong>Scanner used:</strong> {{ scanner_used }}</p>

  {% if clam_result and clam_result[0] == 'infected' %}
    <div class="alert alert-danger">
      <strong>ClamAV detected:</strong> {{ clam_result[1] }}
    </div>
  {% endif %}

  {% if findings %}
    <h4>Findings</h4>
    <ul>
    {% for kind, val in findings %}
      <li><strong>{{ kind }}:</strong>
        {% if val is string %}
          {{ val }}
        {% else %}
          <pre style="white-space:pre-wrap">{{ val }}</pre>
        {% endif %}
      </li>
    {% endfor %}
    </ul>
  {% else %}
    <div class="alert alert-success">No heuristic findings.</div>
  {% endif %}

  <h4>Recommendations</h4>
  <ul>
    <li>If ClamAV reported a detection, quarantine or delete the file and investigate.</li>
    <li>If heuristic findings are present (high entropy, suspicious strings), treat the file as suspicious and analyze it in a sandbox or with online services like VirusTotal.</li>
    <li>Do not run the file on production systems.</li>
  </ul>

  <h5>Hashes</h5>
  <pre>{{ hashes }}</pre>

  <a class="btn btn-secondary" href="/">Scan another file</a>
</div>
'''

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return redirect(url_for('index'))
    f = request.files['file']
    if f.filename == '':
        return redirect(url_for('index'))
    safe_name = os.path.basename(f.filename)
    dst = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
    f.save(dst)

    # try ClamAV first
    scanner_used = 'Heuristic'
    clam_result = None
    if CLAMD_AVAILABLE:
        try:
            res = clam_scan(dst)
            if res[0] == 'infected':
                scanner_used = 'ClamAV'
                clam_result = res
            elif res[0] == 'clean':
                scanner_used = 'ClamAV (clean)'
            else:
                scanner_used = 'ClamAV (error)'
                clam_result = res
        except Exception as e:
            scanner_used = 'Heuristic (clam error)'

    findings = quick_heuristic_scan(dst, safe_name)

    # prepare hashes for display
    hashes = {}
    for k, v in findings:
        if k == 'hashes':
            hashes = v
            break

    # small security: remove uploaded file after scanning to avoid accumulation
    # (but keep for a short while if you want to analyze further; adjust as needed)
    # os.remove(dst)

    return render_template_string(RESULT_HTML,
                                  filename=safe_name,
                                  size=os.path.getsize(dst),
                                  scanner_used=scanner_used,
                                  clam_result=clam_result,
                                  findings=findings,
                                  hashes=hashes)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
