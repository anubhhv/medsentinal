# Quick Start Guide

## Installation (5 minutes)

### Step 1: Run Setup Script

```bash
cd healthcare-security
chmod +x setup.sh
./setup.sh
```

This will:
- ✓ Check Python installation
- ✓ Create necessary directories
- ✓ Install all dependencies
- ✓ Train the AI model

### Step 2: Start Backend

```bash
cd backend
python3 app.py
```

You should see:
```
==================================================
Healthcare Security System - Backend
==================================================
Starting server on http://localhost:5000
AI Model: Trained
==================================================
 * Running on http://0.0.0.0:5000
```

### Step 3: Start Frontend (New Terminal)

```bash
cd frontend
python3 -m http.server 8000
```

### Step 4: Open Browser

Navigate to: **http://localhost:8000**

## Using the System

1. **Click "START MONITORING"** - System activates
2. **Watch the Dashboard** - Real-time threats appear
3. **View Statistics**:
   - Threats Detected
   - Attacks Blocked
   - AI Confidence
4. **Monitor Live Log** - See attacks as they happen
5. **Attack Patterns** - AI-learned attack signatures

## Testing the System

The honeypot automatically generates simulated traffic including:
- SQL injection attempts
- XSS attacks
- Path traversal
- Command injection
- Normal traffic

You'll see these in real-time on the dashboard.

## Stopping the System

Click **"STOP SYSTEM"** button or press Ctrl+C in backend terminal.

## Customization

### Change Detection Threshold

Edit `backend/ai_engine.py`:
```python
def rule_based_detection(self, features):
    threat_score = 0
    # Adjust weights here
    if features.get('has_sql_keywords', 0):
        threat_score += 0.4  # Change this value
```

### Add More Attack Types

Edit `backend/honeypot.py`:
```python
self.attack_patterns = {
    'your_attack_type': [
        "pattern1",
        "pattern2"
    ]
}
```

### Modify UI Colors

Edit `frontend/style.css`:
```css
--primary-color: #f4e87c;  /* Yellow */
--bg-color: #2d4a3e;       /* Dark green */
```

## Troubleshooting

**Backend won't start?**
```bash
pip3 install --upgrade flask flask-cors
```

**Frontend can't connect?**
- Check backend is running on port 5000
- Check browser console for CORS errors

**Model not found?**
```bash
cd backend
python3 train_model.py --samples 5000
```

## Next Steps

- Read full README.md for detailed documentation
- Customize attack patterns
- Train model with your own data
- Deploy to production server

---

**You're all set! 🎉**
