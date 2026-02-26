$root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Start-ServiceWindow {
    param(
        [string]$Title,
        [string]$Command
    )

    Start-Process -FilePath "cmd.exe" -WorkingDirectory $root -ArgumentList "/k", "title $Title && $Command" | Out-Null
}

Write-Host "[1/3] Starting BBS signer on http://localhost:8085 ..."
Start-ServiceWindow -Title "SSI BBS Signer" -Command "cd /d `"$root\bbs-signer-service`" && set BBS_SIGNER_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173 && go run ."

Write-Host "[2/3] Starting Spring backend on http://localhost:8080 ..."
Start-ServiceWindow -Title "SSI Backend" -Command "cd /d `"$root`" && run-backend.cmd"

Write-Host "[3/3] Starting frontend on http://localhost:5173 ..."
Start-ServiceWindow -Title "SSI Frontend" -Command "cd /d `"$root\SSI-Frontend`" && if not exist node_modules npm install && npm run dev"

Write-Host ""
Write-Host "Services launched in separate windows."
Write-Host "Signer:   http://localhost:8085/healthz"
Write-Host "Backend:  http://localhost:8080"
Write-Host "Frontend: http://localhost:5173"
