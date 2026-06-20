from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import socket
import requests
from concurrent.futures import ThreadPoolExecutor
import os
import hashlib
import io
import PyPDF2

app = Flask(__name__)
CORS(app)

# ===== SUBDOMAIN ENUMERATION =====
@app.route('/api/subdomain', methods=['POST'])
def subdomain_scan():
    data = request.json
    domain = data.get('domain')
    
    subdomains = []
    common_subs = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'api', 'dev', 'staging', 'test']
    
    for sub in common_subs:
        try:
            full_domain = f"{sub}.{domain}"
            result = requests.get(f"http://{full_domain}", timeout=2)
            if result.status_code < 400:
                subdomains.append({
                    'url': full_domain,
                    'status': result.status_code,
                    'status_text': 'ACTIVE'
                })
        except:
            pass
    
    return jsonify({'results': subdomains, 'total': len(subdomains)})

# ===== PORT SCANNER =====
@app.route('/api/scan/ports', methods=['POST'])
def port_scan():
    data = request.json
    target_ip = data.get('ip', '127.0.0.1')
    
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
@app.route('/api/pdf/protect', methods=['POST'])
def protect_pdf():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    password = request.form.get('password', '')
    
    try:
        pdf_reader = PyPDF2.PdfReader(file)
        pdf_writer = PyPDF2.PdfWriter()
        
        for page_num in range(len(pdf_reader.pages)):
            pdf_writer.add_page(pdf_reader.pages[page_num])
        
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

# ===== PDF PASSWORD CRACKER =====
@app.route('/api/pdf/crack', methods=['POST'])
def crack_pdf():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    wordlist = [
        'password', 'pass', '12345678', 'qwerty', 'abc123', 'password123',
        '123456', 'admin', 'letmein', 'welcome', 'monkey', '1q2w3e4r',
        'dragon', 'master', 'sunshine', 'princess', 'qazwsx', '123456789',
        'password1', 'pass123', 'admin123', 'root', 'toor', 'test',
        'guest', 'info', 'hello', 'secret', 'demo', 'user','5464'
    ]
    
    try:
        file.seek(0)
        pdf_reader = PyPDF2.PdfReader(file)
        
        if not pdf_reader.is_encrypted:
            return jsonify({'success': False, 'message': 'PDF not encrypted'})
        
        for pwd in wordlist:
            try:
                if pdf_reader.decrypt(pwd):
                    return jsonify({'success': True, 'password': pwd})
            except:
                pass
        
        return jsonify({'success': False, 'message': 'Password not found'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== PASSWORD HASH CRACKER =====
@app.route('/api/crack/hash', methods=['POST'])
def crack_hash():
    data = request.json
    hash_value = data.get('hash', '').strip().lower()
    hash_type = data.get('type', 'md5')
    
    wordlist = [
        'password', 'pass', '12345678', 'qwerty', 'abc123', 'password123',
        'admin', 'root', 'test', 'user', 'guest', '123456', 'letmein',
        'welcome', 'monkey', 'dragon', 'master', 'sunshine', 'princess','5464'
    ]
    
    def hash_word(word, hash_type):
        if hash_type == 'md5':
            return hashlib.md5(word.encode()).hexdigest()
        elif hash_type == 'sha1':
            return hashlib.sha1(word.encode()).hexdigest()
        elif hash_type == 'sha256':
            return hashlib.sha256(word.encode()).hexdigest()
        return ''
    
    for word in wordlist:
        if hash_word(word, hash_type) == hash_value:
            return jsonify({
                'success': True,
                'password': word,
                'hash_type': hash_type
            })
    
    return jsonify({'success': False, 'message': 'Password not found in wordlist'})

# ===== NETWORK DISCOVERY =====
@app.route('/api/scan/network', methods=['POST'])
def network_scan():
    data = request.json
    cidr = data.get('cidr', '192.168.1.0/24')
    
    results = []
    
    try:
        from ipaddress import IPv4Network
        network = IPv4Network(cidr, strict=False)
        
        def ping_ip(ip):
            try:
                result = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
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

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'online'})

if __name__ == '__main__':
    print("🔥 CyberSuite Backend Running on http://localhost:8000")
    app.run(debug=True, port=8000, host='0.0.0.0')
