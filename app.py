from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
from sqlalchemy import insert, select, desc
from app.models import  logs , threat_alerts
from log_parser import LogParser
from app.db import engine

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber-security-secret-key'

# 1. Initialize SocketIO (Handles the /logs namespace)
socketio = SocketIO(app, cors_allowed_origins="*")
parser = LogParser()

# --- ROUTES ---

@app.route('/')
def index():
    """Renders the main monitoring dashboard."""
    return render_template('index.html')

# --- A. WEBSOCKET ENDPOINT (/logs) ---
@socketio.on('connect', namespace='/logs')
def handle_connect():
    print("✓ Dashboard connected via WebSocket [/logs]")

# --- B. HTTP POST: /api/ingest/log ---
@app.route('/api/ingest/log', methods=['POST'])
def ingest_log():
    """
    Accepts incoming log data via HTTP POST.
    Parses, saves to DB, and broadcasts to WebSocket clients.
    """
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({"error": "No log message provided"}), 400

    db_session = Session()
    # 1. Parse the raw string
    parsed = parser.parse_auto(data['message'])

    try:
        # 2. Save to PostgreSQL using SQLAlchemy Core
        stmt = insert(logs).values(
            source_ip=parsed['source_ip'],
            destination_ip=parsed['destination_ip'],
            event_type=parsed['type'],
            severity=parsed['severity'],
            raw_message=parsed['msg'],
            parsed_data=parsed
        )
        result = db_session.execute(stmt)
        db_session.commit()

        # 3. WebSocket: Emit 'new_log'
        socketio.emit('new_log', parsed, namespace='/logs')

        # 4. WebSocket: Emit 'threat_alert' if severity is HIGH
        if parsed['severity'] == 'HIGH':
            socketio.emit('threat_alert', {
                "title": "THREAT DETECTED",
                "message": f"Critical {parsed['type']} from {parsed['source_ip']}",
                "severity": "HIGH"
            }, namespace='/logs')

        return jsonify({"status": "processed", "id": result.inserted_primary_key[0]}), 201

    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        Session.remove()

# --- C. HTTP GET: /api/logs/recent ---
@app.route('/api/logs/recent', methods=['GET'])
def get_recent_logs():
    """
    HTTP Fallback: Retrieves the last 50 logs.
    Useful for initial dashboard loading.
    """
    db_session = Session()
    try:
        stmt = select(logs).order_by(desc(logs.c.id)).limit(50)
        results = db_session.execute(stmt).fetchall()
        
        # Convert SQLAlchemy rows to JSON-serializable list
        log_list = []
        for r in results:
            log_list.append({
                "ip": r.source_ip,
                "type": r.event_type,
                "severity": r.severity,
                "msg": r.raw_message,
                "time": r.timestamp.strftime("%H:%M:%S") if r.timestamp else "N/A"
            })
        return jsonify(log_list)
    finally:
        Session.remove()

if __name__ == '__main__':
    # Use socketio.run instead of app.run
    socketio.run(app, debug=True, port=5000)