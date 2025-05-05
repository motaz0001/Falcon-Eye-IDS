@echo off

start "" "Path to Pythonw" "api.py"

start "" "Path to pythonw" "FalconEye.py"

cd /d "\web"
start "" "Path to pythonw" -m http.server

exit