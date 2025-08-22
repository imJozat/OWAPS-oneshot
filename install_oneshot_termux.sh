cat > install_oneshot_termux.sh <<'SH'
#!/data/data/com.termux/files/usr/bin/bash
set -e
echo "[*] Updating..."; pkg update -y && pkg upgrade -y
echo "[*] Installing Python..."; pkg install -y python
pip install --upgrade pip >/dev/null 2>&1 || true
pip install beautifulsoup4 >/dev/null 2>&1 || true
mkdir -p $HOME/.local/bin $HOME/.local/owasp_oneshot
cp "$PWD/owasp_oneshot.py" "$HOME/.local/owasp_oneshot/owasp_oneshot.py"
cat > $HOME/.local/bin/oneshot <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
python3 $HOME/.local/owasp_oneshot/owasp_oneshot.py "$@"
EOF
chmod +x $HOME/.local/bin/oneshot
if ! grep -q ".local/bin" $HOME/.bashrc 2>/dev/null; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> $HOME/.bashrc
fi
echo "[*] Done. Open new session or: source ~/.bashrc"
echo 'Usage: oneshot https://example.com --max-pages 40 --out $HOME/oneshot_reports'
SH
chmod +x install_oneshot_termux.sh
bash install_oneshot_termux.sh
