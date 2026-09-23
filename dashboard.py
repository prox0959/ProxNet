from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import threading

app = Flask(__name__)
# Secret key for sessions
app.config['SECRET_KEY'] = 'super-secret-key-proxnet'
# Initialize SocketIO for real-time updates
# TR: Gerçek zamanlı güncellemeler (WebSocket) için SocketIO kullanıyoruz.
socketio = SocketIO(app, cors_allowed_origins="*")

# Globals to hold references to our modules
_scanner = None
_detector = None
_last_scan_time = "Never"
_latest_devices = []

def init_app(scanner, detector):
    """
    Setup the Flask application with references to our scanner and detector.
    TR: Flask web uygulamasını tarayıcı ve dedektör ile başlatır.
    """
    global _scanner, _detector
    _scanner = scanner
    _detector = detector
    return app, socketio

@app.route('/')
def index():
    """
    Serve the main dashboard HTML page.
    TR: Ana kontrol paneli HTML sayfasını gösterir.
    """
    return render_template('dashboard.html')

@app.route('/api/devices')
def api_devices():
    """
    REST API to get the latest list of devices.
    TR: Cihaz listesini almak için API noktası.
    """
    return jsonify({"devices": _latest_devices, "last_scan": _last_scan_time})

@app.route('/api/threats')
def api_threats():
    """
    REST API to get the list of threats.
    TR: Tehdit listesini almak için API noktası.
    """
    threats = _detector.get_threats() if _detector else []
    return jsonify({"threats": threats})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    REST API to trigger a manual scan asynchronously.
    TR: Kullanıcı butona bastığında manuel tarama başlatır.
    """
    def run_scan():
        global _latest_devices, _last_scan_time
        import datetime
        if _scanner:
            _latest_devices = _scanner.scan_network()
            _last_scan_time = datetime.datetime.now().strftime("%H:%M:%S")
            # Notify all connected web clients
            # TR: Taramayı bitirince tüm web sayfalarına haber veriyoruz.
            socketio.emit('update_network', {
                'devices': _latest_devices, 
                'last_scan': _last_scan_time,
                'threats': _detector.get_threats() if _detector else []
            })
            
    # Run in background so request doesn't block
    threading.Thread(target=run_scan).start()
    return jsonify({"status": "Scan started"})

def start_dashboard(flask_app, sio, port=5000):
    """
    Start the Flask-SocketIO server.
    TR: Sunucuyu belirtilen portta ayağa kaldırır.
    """
    sio.run(flask_app, host='0.0.0.0', port=port, debug=False, use_reloader=False)
