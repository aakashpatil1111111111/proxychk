#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "==> Updating apt..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip

echo "==> Creating virtualenv..."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "==> Installing systemd service..."
sudo cp proxy-checker.service /etc/systemd/system/proxy-checker.service
sudo sed -i "s|/opt/proxy-checker-bot|$(pwd)|g" /etc/systemd/system/proxy-checker.service
sudo systemctl daemon-reload
sudo systemctl enable proxy-checker
sudo systemctl restart proxy-checker

echo "==> Done!"
echo "Status:  sudo systemctl status proxy-checker"
echo "Logs:    sudo journalctl -u proxy-checker -f"
