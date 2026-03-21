import random
import time
import threading
from datetime import datetime

class HoneypotManager:
    """Manages the honeypot trap system"""
    
    def __init__(self, ai_engine, database):
        self.ai_engine = ai_engine
        self.db = database
        self.is_running = False
        self.thread = None
        
        # Fake vulnerable endpoints to attract attackers
        self.vulnerable_endpoints = [
            '/admin/login',
            '/api/users',
            '/upload',
            '/backup/database',
            '/config/settings',
            '/debug/console',
            '/api/patients',
            '/medical_records',
            '/payment/process',
            '/api/prescriptions'
        ]
        
        # Common attack patterns
        self.attack_patterns = {
            'sql_injection': [
                "' OR '1'='1",
                "'; DROP TABLE users--",
                "UNION SELECT * FROM users",
                "1' AND '1'='1"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(document.cookie)",
                "<iframe src='malicious.com'>"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32",
                "../../config/database.yml",
                "../backup/patients.db"
            ],
            'command_injection': [
                "; ls -la",
                "| cat /etc/passwd",
                "&& whoami",
                "`rm -rf /`"
            ],
            'ransomware': [
                ".encrypted",
                "DECRYPT_INSTRUCTIONS.txt",
                "ransom_note.html",
                "pay_bitcoin.txt"
            ]
        }
    
    def start(self, event_queue):
        """Start the honeypot monitoring"""
        self.is_running = True
        self.event_queue = event_queue
        self.monitor()
    
    def stop(self):
        """Stop the honeypot monitoring"""
        self.is_running = False
    
    def monitor(self):
        """Main monitoring loop"""
        print("Honeypot monitoring started...")
        
        while self.is_running:
            # Simulate incoming requests
            self.simulate_traffic()
            time.sleep(random.uniform(1, 3))
    
    def simulate_traffic(self):
        """Simulate incoming network traffic"""
        # Generate random traffic
        is_attack = random.random() < 0.3  # 30% chance of attack
        
        if is_attack:
            self.handle_attack()
        else:
            self.handle_normal_traffic()
    
    def handle_attack(self):
        """Process and log an attack attempt"""
        # Select random attack type
        attack_type = random.choice(list(self.attack_patterns.keys()))
        pattern = random.choice(self.attack_patterns[attack_type])
        endpoint = random.choice(self.vulnerable_endpoints)
        
        # Generate attack data
        attack_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': self.generate_ip(),
            'endpoint': endpoint,
            'attack_type': attack_type,
            'pattern': pattern,
            'method': random.choice(['GET', 'POST', 'PUT', 'DELETE']),
            'user_agent': self.generate_user_agent()
        }
        
        # Extract features for AI prediction
        features = self.extract_features(attack_data)
        
        # Use AI to predict if it's truly malicious
        prediction = self.ai_engine.predict(features)
        confidence = prediction['confidence']
        is_threat = prediction['is_threat']
        
        # Log the attack
        log_entry = {
            'timestamp': attack_data['timestamp'],
            'is_threat': is_threat,
            'message': f"Attack detected: {attack_type.upper()} on {endpoint} from {attack_data['source_ip']}",
            'attack_type': attack_type,
            'confidence': confidence,
            'source_ip': attack_data['source_ip'],
            'endpoint': endpoint
        }
        
        # Save to database
        self.db.log_attack(log_entry)
        
        # Send to frontend via SSE
        self.event_queue.put({
            'type': 'log',
            'data': log_entry
        })
        
        # Update stats
        stats = self.db.get_statistics()
        self.event_queue.put({
            'type': 'stats',
            'data': stats
        })
        
        # Learn from the pattern
        if is_threat:
            self.ai_engine.learn_pattern(features, attack_type)
            
            # Send pattern update
            self.event_queue.put({
                'type': 'pattern',
                'data': {
                    'name': attack_type.replace('_', ' ').title(),
                    'count': random.randint(1, 10),
                    'confidence': confidence,
                    'attack_type': attack_type
                }
            })
    
    def handle_normal_traffic(self):
        """Process normal traffic"""
        endpoint = random.choice(['/home', '/about', '/contact', '/api/status'])
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'is_threat': False,
            'message': f"Normal traffic to {endpoint} from {self.generate_ip()}",
            'attack_type': 'none',
            'confidence': 0.99,
            'source_ip': self.generate_ip(),
            'endpoint': endpoint
        }
        
        # Send to frontend
        self.event_queue.put({
            'type': 'log',
            'data': log_entry
        })
    
    def extract_features(self, attack_data):
        """Extract features from attack data for AI analysis"""
        features = {
            'endpoint_length': len(attack_data['endpoint']),
            'pattern_length': len(attack_data['pattern']),
            'has_special_chars': int(any(c in attack_data['pattern'] for c in ['<', '>', ';', '|', '&', '\'', '"'])),
            'has_sql_keywords': int(any(kw in attack_data['pattern'].upper() for kw in ['SELECT', 'UNION', 'DROP', 'INSERT'])),
            'has_script_tags': int('<script>' in attack_data['pattern'].lower() or 'javascript:' in attack_data['pattern'].lower()),
            'has_path_traversal': int('..' in attack_data['pattern']),
            'method_post': int(attack_data['method'] == 'POST'),
            'method_delete': int(attack_data['method'] == 'DELETE'),
            'suspicious_endpoint': int(any(sus in attack_data['endpoint'] for sus in ['admin', 'debug', 'backup', 'config']))
        }
        return features
    
    def generate_ip(self):
        """Generate a random IP address"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    
    def generate_user_agent(self):
        """Generate a random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'curl/7.68.0',
            'python-requests/2.28.0',
            'Postman/9.0',
            'sqlmap/1.6',
            'nikto/2.1.6'
        ]
        return random.choice(user_agents)
