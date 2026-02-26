@echo off
setlocal

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

echo [1/3] Starting BBS signer on http://localhost:8085 ...
start "SSI BBS Signer" cmd /k "cd /d %ROOT%\bbs-signer-service && go run ."

echo [2/3] Starting Spring backend on http://localhost:8080 ...
start "SSI Backend" cmd /k "cd /d %ROOT% && run-backend.cmd"

echo [3/3] Starting frontend on http://localhost:5173 ...
start "SSI Frontend" cmd /k "cd /d %ROOT%\SSI-Frontend && if not exist node_modules npm install && npm run dev"

echo.
echo Services launched in separate windows.
echo Signer:   http://localhost:8085/healthz
echo Backend:  http://localhost:8080
echo Frontend: http://localhost:5173

endlocal
