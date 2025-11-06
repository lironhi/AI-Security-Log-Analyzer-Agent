Write-Host "Activating AI Security Log Analyzer virtual environment..." -ForegroundColor Green
& .\venv\Scripts\Activate.ps1
Write-Host ""
Write-Host "Environment activated! You can now run:" -ForegroundColor Yellow
Write-Host "  python main.py init           # Initialize the system" -ForegroundColor Cyan
Write-Host "  python main.py server         # Start API server" -ForegroundColor Cyan
Write-Host "  python -m pytest tests/ -v    # Run tests" -ForegroundColor Cyan
Write-Host ""