@echo off
PowerShell -Command "docker kill (docker ps -q | Select-Object -First 1)"
