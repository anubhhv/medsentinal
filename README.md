# MedSentinel AI

AI-powered honeypot system that detects, analyzes, and learns from cyber attacks in real-time using machine learning and autonomous monitoring.

---

## 🚀 Features

* 🤖 **AI-Powered Threat Detection**: Learns attack patterns using ML models
* 🛡️ **Honeypot System**: Fake vulnerable endpoints to attract attackers
* ⚡ **Real-time Monitoring**: Live dashboard using Server-Sent Events (SSE)
* 🧠 **Adaptive Learning**: Continuously improves detection from new attacks
* 📊 **Live Analytics Dashboard**: Visualize threats, logs, and patterns
* 🎯 **Automatic Training**: Models are generated automatically during training
* 🧪 **Attack Simulation**: Test files are auto-created when simulation is triggered

---

## 🧠 Attack Types Detected

* SQL Injection
* Cross-Site Scripting (XSS)
* Path Traversal
* Command Injection
* Ransomware-like patterns

---

## 🏗️ Project Structure

```
medsentinel-ai/
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── backend/
│   ├── app.py
│   ├── honeypot.py
│   ├── ai_engine.py
│   ├── database.py
│   ├── train_model.py
│   └── requirements.txt
│
├── data/
│   └── attacks.json
│
├── models/                  # Auto-generated after training
│   ├── threat_detector.pkl
│   └── scaler.pkl
```

---

## ⚙️ Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/anubhhv/medsentinel-ai.git
   cd medsentinel-ai
   ```

2. Setup backend:

   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Train models:

   ```bash
   python train_model.py --samples 5000
   ```

4. Run backend:

   ```bash
   python app.py
   ```

5. Run frontend:

   ```bash
   cd ../frontend
   python -m http.server 8000
   ```

6. Open:

   ```
   http://localhost:8000
   ```

---

## 📈 Usage

* Start backend server
* Open frontend dashboard
* Click **START MONITORING**
* System begins:

  * Detecting threats in real time
  * Logging attacks
  * Learning new patterns

### 🧪 Simulation

* Trigger attack simulations from UI
* Test files are **automatically generated**
* System analyzes them as real threats

---

## 🤖 AI Model Training

* Training generates models automatically in `models/`
* Uses synthetic or custom datasets
* Supports:

  * Random Forest
  * Gradient Boosting
* Selects best model based on performance

---

## 🔌 API Endpoints

* `GET /api/status` → System status
* `POST /api/start` → Start monitoring
* `POST /api/stop` → Stop system
* `GET /api/stream` → Live SSE events
* `GET /api/logs` → Attack logs
* `GET /api/patterns` → Learned patterns
* `POST /api/train` → Retrain model

---

## ⚙️ How It Works

1. **Honeypot Layer**
   Fake endpoints attract malicious requests

2. **AI Detection Engine**
   ML model classifies requests as threat or normal

3. **Pattern Learning**
   System stores and learns from new attack behaviors

4. **Real-time Streaming**
   Dashboard updates instantly via SSE

---

## 🔐 Security Concepts

* Behavioral threat detection
* Zero-trust inspired monitoring
* Adaptive machine learning
* Real-time anomaly detection

---

## 📄 License

MIT License

---

## 🤝 Contributing

Pull requests are welcome. Follow clean code practices and document your changes.
