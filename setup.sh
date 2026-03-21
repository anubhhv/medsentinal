#!/bin/bash

# Healthcare Security System - Quick Setup Script

echo "=================================================="
echo "Healthcare Security System - Setup"
echo "=================================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $python_version"
echo ""

# Create directories
echo "Creating project directories..."
mkdir -p data
mkdir -p models
echo "✓ Directories created"
echo ""

# Install backend dependencies
echo "Installing Python dependencies..."
cd backend
python3 -m pip install -r requirements.txt
if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "✗ Failed to install dependencies"
    exit 1
fi
echo ""

# Train the AI model
echo "Training AI model (this may take a minute)..."
python3 train_model.py --samples 5000 --model compare
if [ $? -eq 0 ]; then
    echo "✓ Model trained successfully"
else
    echo "✗ Failed to train model"
    exit 1
fi
echo ""

cd ..

echo "=================================================="
echo "Setup Complete!"
echo "=================================================="
echo ""
echo "To start the system:"
echo ""
echo "1. Start backend:"
echo "   cd backend"
echo "   python3 app.py"
echo ""
echo "2. Start frontend (in a new terminal):"
echo "   cd frontend"
echo "   python3 -m http.server 8000"
echo ""
echo "3. Open browser to:"
echo "   http://localhost:8000"
echo ""
echo "=================================================="
