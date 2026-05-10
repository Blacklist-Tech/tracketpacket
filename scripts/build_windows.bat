@echo off
echo 📡 Building TracketPacket for Windows...
pip install pyinstaller
pyinstaller --onefile --noconsole ^
    --name tracketpacket ^
    --add-data "index.html;." ^
    --add-data "oui.tsv;." ^
    server.py
echo ✅ Build complete. Check the 'dist' folder.
pause
