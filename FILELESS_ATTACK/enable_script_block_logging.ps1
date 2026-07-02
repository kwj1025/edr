<#
.SYNOPSIS
    PowerShell Script Block Logging (Event ID 4104) 활성화 스크립트
    
.DESCRIPTION
    fileless_detector.py 가 Event ID 4104 를 수집하려면
    Windows 레지스트리에서 Script Block Logging이 활성화되어 있어야 합니다.
    이 스크립트는 해당 설정을 활성화합니다.

.NOTES
    관리자 권한 필요
#>

Write-Host "[설정] PowerShell Script Block Logging 활성화 중..." -ForegroundColor Yellow

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

# 레지스트리 경로가 없으면 생성
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Host "[INFO] 레지스트리 경로 생성: $regPath" -ForegroundColor Cyan
}

# Script Block Logging 활성화
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Write-Host "[OK] EnableScriptBlockLogging = 1 설정 완료" -ForegroundColor Green

# 현재 설정 확인
$currentValue = Get-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
Write-Host "[확인] 현재 설정값: $($currentValue.EnableScriptBlockLogging)" -ForegroundColor Cyan

Write-Host ""
Write-Host "[완료] Script Block Logging 이 활성화되었습니다." -ForegroundColor Green
Write-Host "       이제 PowerShell 명령어가 Event ID 4104 로 기록됩니다." -ForegroundColor Green
Write-Host ""
Write-Host "       다음 단계: run_all_dummies.ps1 을 실행하세요." -ForegroundColor Yellow
