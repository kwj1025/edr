<#
.SYNOPSIS
    [더미 시나리오 04] 숨김 백그라운드 실행 시뮬레이터
    탐지 대상: -WindowStyle Hidden, -NoProfile, -NoExit, cmd /c
    예상 위험도: MEDIUM (risk_score >= 0.4)

.DESCRIPTION
    백그라운드에서 숨김 상태로 실행되는 PowerShell 프로세스 패턴을 기록합니다.
    fileless_detector.py 의 detect_background_powershell() 함수가 탐지합니다.
#>

Write-Host "[DUMMY-04] 숨김 백그라운드 실행 시뮬레이터 시작..." -ForegroundColor Yellow

# ─── 실제 백그라운드 숨김 프로세스 시뮬레이션 ──────────────────────────────
# 5초 후 자동 종료되는 안전한 백그라운드 PowerShell 프로세스 실행
# detect_background_powershell() 이 MainWindowTitle='' 조건으로 탐지함

Write-Host "[INFO] 백그라운드 숨김 프로세스 실행 중 (5초 후 자동 종료)..." -ForegroundColor Cyan

# -WindowStyle Hidden 으로 실행 → 탐지기가 MainWindowHandle=0 으로 감지
$bgProcess = Start-Process powershell.exe -ArgumentList @(
    "-NoProfile",
    "-NoExit",
    "-WindowStyle", "Hidden",
    "-Command", "Start-Sleep -Seconds 5; Write-Host 'DUMMY BACKGROUND PROCESS EXITING'"
) -PassThru

Write-Host "[INFO] 백그라운드 PID: $($bgProcess.Id)" -ForegroundColor Cyan
Write-Host "[INFO] WindowStyle: Hidden, NoProfile: True" -ForegroundColor Cyan
Write-Host "[INFO] 이 프로세스는 detect_background_powershell() 이 탐지합니다." -ForegroundColor Yellow

# cmd /c 패턴도 로그에 포함
$cmdChain = "cmd /c echo DUMMY_CMD_CHAIN_SIMULATION"
Write-Host "[INFO] cmd /c 체이닝 패턴 기록: $cmdChain" -ForegroundColor Cyan

Write-Host ""
Write-Host "[DUMMY-04] 완료 - 백그라운드 숨김 프로세스 실행됨. 대시보드 탐지 버튼을 누르세요." -ForegroundColor Green
Write-Host "           (5초 후 자동 종료됩니다)" -ForegroundColor DarkGray
