@echo off
echo Activating AI Security Log Analyzer virtual environment...
call venv\Scripts\activate.bat
echo.
echo Environment activated! You can now run:
echo   python main.py init           # Initialize the system
echo   python main.py server         # Start API server
echo   python -m pytest tests/ -v    # Run tests
echo.