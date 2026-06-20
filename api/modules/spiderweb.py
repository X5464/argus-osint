from flask import Blueprint, request, jsonify, send_file
import socket
import requests
from concurrent.futures import ThreadPoolExecutor
import os
import platform
import io
import tempfile
import PyPDF2

from wordlists import get_wordlist_info, resolve_wordlist
from crack_jobs import get_job, start_pdf_crack, start_hash_crack

try:
    from modules.webcheck import enumerate_subdomains  # type: ignore
except ImportError:  # pragma: no cover
    from api.modules.webcheck import enumerate_subdomains  # type: ignore

spiderweb_bp = Blueprint('spiderweb', __name__)

# ===== SUBDOMAIN ENUMERATION =====
@spiderweb_bp.route('/subdomain', methods=['POST'])
def subdomain_scan():
    data = request.get_json() or {}
    domain = (data.get('domain') or '').strip()
    if not domain:
        return jsonify({'success': False, 'error': "The 'domain' field is required."}), 400

    limit = int(data.get('limit') or 100)
    check_live = data.get('check_live', True)

    payload = enumerate_subdomains(domain, limit=limit, check_live=check_live)
    success = bool(payload.get("ct_subdomains")) or not payload.get("error")

    return jsonify({
        'success': success,
        **payload,
        'total': payload.get('subdomain_count', 0),
    })

# ===== PORT SCANNER =====
@spiderweb_bp.route('/scan/ports', methods=['POST'])
def port_scan():
    data = request.get_json() or {}
    target_ip = data.get('ip', '').strip()
    if not target_ip:
        return jsonify({'success': False, 'error': "The 'ip' field is required."}), 400
    
    open_ports = []
    port_service = {
        21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 
        465: 'SMTP-SSL', 587: 'SMTP', 993: 'IMAP-SSL', 995: 'POP3-SSL',
        3306: 'MySQL', 5432: 'PostgreSQL', 5984: 'CouchDB', 
        6379: 'Redis', 8080: 'HTTP-Alt', 8888: 'Alt', 27017: 'MongoDB'
    }
    
    def scan_port(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service = port_service.get(port, 'Unknown')
                open_ports.append({
                    'port': port,
                    'service': service,
                    'status': 'OPEN'
                })
        except:
            pass
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        for port in range(1, 1025):
            executor.submit(scan_port, target_ip, port)
    
    return jsonify({
        'results': open_ports,
        'target': target_ip,
        'total_open': len(open_ports)
    })

# ===== PDF PROTECTION =====
@spiderweb_bp.route('/pdf/protect', methods=['POST'])
def protect_pdf():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    password = request.form.get('password', '')
    # Owner password is optional; defaults to the user password (backward compatible).
    owner_password = request.form.get('owner_password', '') or password

    if not password:
        return jsonify({'error': "A 'password' field is required."}), 400

    try:
        pdf_reader = PyPDF2.PdfReader(file)
        pdf_writer = PyPDF2.PdfWriter()

        for page_num in range(len(pdf_reader.pages)):
            pdf_writer.add_page(pdf_reader.pages[page_num])

        # Prefer modern AES-256 (pypdf / PyPDF2 3.x). Fall back gracefully to the
        # legacy RC4 path on older library versions so encryption never fails.
        try:
            pdf_writer.encrypt(
                user_password=password,
                owner_password=owner_password,
                algorithm="AES-256",
            )
        except Exception:
            # Older PyPDF2 (no algorithm kwarg) or missing AES backend
            # (cryptography) — fall back to the legacy RC4 encryption path.
            pdf_writer.encrypt(password)

        output = io.BytesIO()
        pdf_writer.write(output)
        output.seek(0)

        return send_file(
            output,
            mimetype='application/pdf',
            as_attachment=True,
            download_name='protected.pdf'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _resolve_uploaded_wordlist():
    """Resolve wordlist from form path string or uploaded file."""
    wordlist_path = (request.form.get('wordlist') or '').strip() or None
    upload = request.files.get('wordlist_file')

    if upload and upload.filename:
        suffix = os.path.splitext(upload.filename)[1] or '.txt'
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix='argus_wl_')
        upload.save(tmp.name)
        tmp.close()
        return tmp.name

    if wordlist_path:
        return resolve_wordlist(wordlist_path)

    return resolve_wordlist(None)


# ===== WORDLIST INFO =====
@spiderweb_bp.route('/wordlist/info', methods=['GET'])
def wordlist_info():
    path = request.args.get('path')
    summary = get_wordlist_info(path)
    if not summary['available']:
        return jsonify({'success': False, **summary}), 404
    return jsonify({'success': True, **summary})


# ===== PDF PASSWORD CRACKER =====
@spiderweb_bp.route('/pdf/crack', methods=['POST'])
def crack_pdf():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    try:
        wordlist_path = _resolve_uploaded_wordlist()
        wl = get_wordlist_info(wordlist_path)
    except FileNotFoundError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    try:
        pdf_bytes = file.read()
        job_id = start_pdf_crack(pdf_bytes, wordlist_path)
        return jsonify({
            'success': True,
            'job_id': job_id,
            'status': 'running',
            'wordlist': wl['name'],
            'entries': wl['line_count'],
            'total': wl['line_count'],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@spiderweb_bp.route('/pdf/crack/status/<job_id>', methods=['GET'])
def crack_pdf_status(job_id):
    job = get_job(job_id)
    if not job:
        return jsonify({'success': False, 'error': 'Job not found'}), 404

    payload = {
        'success': job['status'] == 'success',
        'job_id': job['job_id'],
        'status': job['status'],
        'tried': job['tried'],
        'total': job['total'],
        'rate': round(job['rate'], 1),
        'elapsed': job['elapsed'],
        'eta_seconds': job['eta_seconds'],
        'progress_line': job['progress_line'],
        'wordlist': job['wordlist'],
        'entries': job['total'],
    }
    if job.get('password'):
        payload['password'] = job['password']
    if job.get('message'):
        payload['message'] = job['message']
    if job.get('error'):
        payload['error'] = job['error']
    return jsonify(payload)


# ===== PASSWORD HASH CRACKER =====
@spiderweb_bp.route('/crack/hash', methods=['POST'])
def crack_hash():
    data = request.get_json() or {}
    hash_value = data.get('hash', '').strip().lower()
    hash_type = data.get('type', 'md5').strip().lower()
    if not hash_value:
        return jsonify({'success': False, 'error': "The 'hash' field is required."}), 400
    if hash_type not in ('md5', 'sha1', 'sha256', 'sha512'):
        return jsonify({'success': False, 'error': "Invalid hash type. Supported: md5, sha1, sha256, sha512."}), 400

    # Optional salt support. No salt reproduces the legacy behaviour.
    salt = (data.get('salt') or '').strip()
    salt_mode = (data.get('salt_mode') or 'append').strip().lower()
    if salt_mode not in ('prepend', 'append'):
        return jsonify({'success': False, 'error': "Invalid salt_mode. Supported: prepend, append."}), 400

    wordlist_path = (data.get('wordlist') or '').strip() or None

    try:
        wordlist_path = resolve_wordlist(wordlist_path)
        wl = get_wordlist_info(wordlist_path)
    except FileNotFoundError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    try:
        job_id = start_hash_crack(hash_value, hash_type, wordlist_path, salt=salt, salt_mode=salt_mode)
        return jsonify({
            'success': True,
            'job_id': job_id,
            'status': 'running',
            'wordlist': wl['name'],
            'entries': wl['line_count'],
            'total': wl['line_count'],
            'salted': bool(salt),
            'salt_mode': salt_mode if salt else None,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@spiderweb_bp.route('/crack/hash/status/<job_id>', methods=['GET'])
def crack_hash_status(job_id):
    job = get_job(job_id)
    if not job:
        return jsonify({'success': False, 'error': 'Job not found'}), 404

    payload = {
        'success': job['status'] == 'success',
        'job_id': job['job_id'],
        'status': job['status'],
        'tried': job['tried'],
        'total': job['total'],
        'rate': round(job['rate'], 1),
        'elapsed': job['elapsed'],
        'eta_seconds': job['eta_seconds'],
        'progress_line': job['progress_line'],
        'wordlist': job['wordlist'],
        'entries': job['total'],
    }
    if job.get('password'):
        payload['password'] = job['password']
    if job.get('hash_type'):
        payload['hash_type'] = job['hash_type']
    if job.get('message'):
        payload['message'] = job['message']
    if job.get('error'):
        payload['error'] = job['error']
    return jsonify(payload)

# ===== NETWORK DISCOVERY =====
@spiderweb_bp.route('/scan/network', methods=['POST'])
def network_scan():
    data = request.get_json() or {}
    cidr = data.get('cidr', '').strip()
    if not cidr:
        return jsonify({'success': False, 'error': "The 'cidr' field is required."}), 400
    
    results = []
    
    try:
        from ipaddress import IPv4Network
        network = IPv4Network(cidr, strict=False)
        
        # macOS uses -W <milliseconds>; Linux uses -W <seconds>
        _ping_timeout = "1000" if platform.system() == "Darwin" else "1"

        def ping_ip(ip):
            try:
                result = os.system(f"ping -c 1 -W {_ping_timeout} {ip} > /dev/null 2>&1")
                if result == 0:
                    try:
                        hostname = socket.gethostbyaddr(str(ip))[0]
                    except:
                        hostname = "Unknown"
                    
                    results.append({
                        'ip': str(ip),
                        'hostname': hostname,
                        'status': 'ACTIVE'
                    })
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            for ip in list(network.hosts())[:50]:
                executor.submit(ping_ip, ip)
        
        return jsonify({'results': results, 'total': len(results)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400
