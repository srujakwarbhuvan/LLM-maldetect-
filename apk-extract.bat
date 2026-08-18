@echo off
REM Wrapper to run apk-extract CLI reliably
call venv\Scripts\python.exe -m apk_extractor.cli.main %*
