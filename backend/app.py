from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import json
import time
from datetime import datetime
from honeypot import HoneypotManager
from ai_engine import AIEngine
from database import Database
import queue
import threading

app = Flask(__name__)
CORS(app)

# Initialize components
db = Database()
ai_engine = AIEngine()
honeypot = HoneypotManager(ai_engine, db)

# Event queue for SSE
event_queue = queue.Queue()

# System state
system_state = {
    'is_running': False,
    'stats': {
        'threats_detected': 0,
        'attacks_blocked': 0,
        'confidence': 98
    }
}

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    return jsonify({
        'status': 'online' if system_state['is_running'] else 'offline',
        'stats': system_state['stats']
    })

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    """Start the honeypot monitoring"""
    if not system_state['is_running']:
        system_state['is_running'] = True
        
        # Start honeypot in a separate thread
        honeypot_thread = threading.Thread(target=honeypot.start, args=(event_queue,))
        honeypot_thread.daemon = True
        honeypot_thread.start()
        
        return jsonify({'message': 'Monitoring started', 'status': 'success'})
    
    return jsonify({'message': 'Already running', 'status': 'info'})

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    """Stop the honeypot monitoring"""
    if system_state['is_running']:
        system_state['is_running'] = False
        honeypot.stop()
        
        return jsonify({'message': 'Monitoring stopped', 'status': 'success'})
    
    return jsonify({'message': 'Not running', 'status': 'info'})

@app.route('/api/stream')
def stream():
    """Server-Sent Events stream for real-time updates"""
    def generate():
        while True:
            try:
                # Get event from queue with timeout
                event = event_queue.get(timeout=1)
                
                # Format as SSE
                event_type = event.get('type', 'log')
                data = json.dumps(event.get('data', {}))
                
                yield f"event: {event_type}\ndata: {data}\n\n"
                
            except queue.Empty:
                # Send keepalive
                yield ": keepalive\n\n"
                
            except GeneratorExit:
                break
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/patterns', methods=['GET'])
def get_patterns():
    """Get learned attack patterns"""
    patterns = db.get_attack_patterns()
    return jsonify(patterns)

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get attack logs"""
    limit = request.args.get('limit', 100, type=int)
    logs = db.get_logs(limit)
    return jsonify(logs)

@app.route('/api/train', methods=['POST'])
def trigger_training():
    """Trigger AI model retraining"""
    try:
        ai_engine.train_model()
        return jsonify({
            'message': 'Model training completed',
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'message': f'Training failed: {str(e)}',
            'status': 'error'
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    stats = db.get_statistics()
    system_state['stats'] = stats
    return jsonify(stats)

if __name__ == '__main__':
    print("=" * 50)
    print("Healthcare Security System - Backend")
    print("=" * 50)
    print(f"Starting server on http://localhost:5000")
    print(f"AI Model: {'Trained' if ai_engine.model_trained else 'Untrained'}")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
