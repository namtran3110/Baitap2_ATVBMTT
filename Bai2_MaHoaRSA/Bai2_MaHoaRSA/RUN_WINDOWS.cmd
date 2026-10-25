@echo off
setlocal
cd /d "%~dp0"
where dotnet >nul 2>nul
if errorlevel 1 (
    echo Khong tim thay .NET SDK tren may.
    echo Hay cai .NET SDK va workload .NET desktop development trong Visual Studio.
    echo Sau do mo lai RUN_WINDOWS.cmd.
    pause
    exit /b 1
)
echo Dang khoi dong Bai 2 - RSA / SHA-256 / Chu ky so...
dotnet run --project "%~dp0Bai2_MaHoaRSA.csproj"
if errorlevel 1 (
    echo.
    echo Ung dung chua chay duoc. Hay kiem tra SDK, workload va thong bao build phia tren.
    pause
    exit /b 1
)
endlocal
