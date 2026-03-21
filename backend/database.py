import json
import os
from datetime import datetime
from collections import defaultdict

class Database:
    """Simple JSON-based database for storing attack logs and patterns"""
    
    def __init__(self, db_file='data/attacks.json'):
        self.db_file = db_file
        self.data = {
            'logs': [],
            'patterns': {},
            'statistics': {
                'threats_detected': 0,
                'attacks_blocked': 0,
                'total_requests': 0
            }
        }
        self.load_data()
    
    def load_data(self):
        """Load data from JSON file"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    self.data = json.load(f)
                print(f"Database loaded: {len(self.data['logs'])} logs")
            except Exception as e:
                print(f"Error loading database: {e}")
                self.initialize_db()
        else:
            self.initialize_db()
    
    def initialize_db(self):
        """Initialize a new database"""
        os.makedirs(os.path.dirname(self.db_file) if os.path.dirname(self.db_file) else 'data', exist_ok=True)
        self.save_data()
        print("New database initialized")
    
    def save_data(self):
        """Save data to JSON file"""
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            print(f"Error saving database: {e}")
    
    def log_attack(self, log_entry):
        """Log an attack attempt"""
        # Add ID and timestamp if not present
        if 'id' not in log_entry:
            log_entry['id'] = len(self.data['logs']) + 1
        
        if 'timestamp' not in log_entry:
            log_entry['timestamp'] = datetime.now().isoformat()
        
        # Add to logs
        self.data['logs'].append(log_entry)
        
        # Update statistics
        self.data['statistics']['total_requests'] += 1
        if log_entry.get('is_threat', False):
            self.data['statistics']['threats_detected'] += 1
            self.data['statistics']['attacks_blocked'] += 1
            
            # Update pattern count
            attack_type = log_entry.get('attack_type', 'unknown')
            if attack_type not in self.data['patterns']:
                self.data['patterns'][attack_type] = {
                    'name': attack_type.replace('_', ' ').title(),
                    'count': 0,
                    'confidence': 0.0,
                    'attack_type': attack_type,
                    'first_seen': log_entry['timestamp'],
                    'last_seen': log_entry['timestamp']
                }
            
            self.data['patterns'][attack_type]['count'] += 1
            self.data['patterns'][attack_type]['last_seen'] = log_entry['timestamp']
            self.data['patterns'][attack_type]['confidence'] = log_entry.get('confidence', 0.9)
        
        # Keep only last 1000 logs to prevent file bloat
        if len(self.data['logs']) > 1000:
            self.data['logs'] = self.data['logs'][-1000:]
        
        # Save to disk periodically (every 10 logs)
        if len(self.data['logs']) % 10 == 0:
            self.save_data()
    
    def get_logs(self, limit=100):
        """Get recent attack logs"""
        return self.data['logs'][-limit:]
    
    def get_attack_patterns(self):
        """Get learned attack patterns"""
        return list(self.data['patterns'].values())
    
    def get_statistics(self):
        """Get system statistics"""
        # Calculate confidence based on detection rate
        total = self.data['statistics']['total_requests']
        if total > 0:
            detection_rate = self.data['statistics']['threats_detected'] / total
            confidence = min(95 + (detection_rate * 5), 99)
        else:
            confidence = 98
        
        return {
            'threats_detected': self.data['statistics']['threats_detected'],
            'attacks_blocked': self.data['statistics']['attacks_blocked'],
            'total_requests': self.data['statistics']['total_requests'],
            'confidence': int(confidence)
        }
    
    def get_pattern_by_type(self, attack_type):
        """Get specific attack pattern"""
        return self.data['patterns'].get(attack_type)
    
    def clear_logs(self):
        """Clear all logs (useful for testing)"""
        self.data['logs'] = []
        self.save_data()
    
    def reset_statistics(self):
        """Reset statistics"""
        self.data['statistics'] = {
            'threats_detected': 0,
            'attacks_blocked': 0,
            'total_requests': 0
        }
        self.save_data()
    
    def export_to_csv(self, output_file='data/attack_logs.csv'):
        """Export logs to CSV for analysis"""
        import csv
        
        if not self.data['logs']:
            print("No logs to export")
            return
        
        # Get all unique keys from logs
        fieldnames = set()
        for log in self.data['logs']:
            fieldnames.update(log.keys())
        
        fieldnames = sorted(list(fieldnames))
        
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.data['logs'])
            
            print(f"Logs exported to {output_file}")
        except Exception as e:
            print(f"Error exporting logs: {e}")
    
    def get_attack_summary(self):
        """Get summary of attacks by type"""
        summary = defaultdict(int)
        
        for log in self.data['logs']:
            if log.get('is_threat', False):
                attack_type = log.get('attack_type', 'unknown')
                summary[attack_type] += 1
        
        return dict(summary)
    
    def get_top_attackers(self, limit=10):
        """Get top attacking IP addresses"""
        ip_counts = defaultdict(int)
        
        for log in self.data['logs']:
            if log.get('is_threat', False):
                ip = log.get('source_ip', 'unknown')
                ip_counts[ip] += 1
        
        # Sort by count
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        
        return sorted_ips[:limit]
    
    def __del__(self):
        """Save data when object is destroyed"""
        self.save_data()
