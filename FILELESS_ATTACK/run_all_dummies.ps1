<#
.SYNOPSIS
    모든 더미 시나리오를 순서대로 실행합니다.
    탐지 버튼을 누르기 전에 이 스크립트를 먼저 실행하세요.
#>

Write-Host "=" * 60
Write-Host "  EDR FILELESS 공격 더미 시뮬레이터 - 전체 실행"
Write-Host "  (모든 스크립트는 안전하며 실제 악성 행위 없음)"
Write-Host "=" * 60
Write-Host ""

$scripts = @(
    ".\01_download_exec.ps1",
    ".\02_encoded_command.ps1",
    ".\03_reflective_injection.ps1",
    ".\05_obfuscation_chain.ps1"
)

foreach ($script in $scripts) {
    Write-Host ""
    Write-Host "▶ 실행: $script" -ForegroundColor Yellow
    Write-Host ("-" * 50)
    & powershell.exe -ExecutionPolicy Bypass -File $script
    Write-Host ""
    Start-Sleep -Seconds 1
}

Write-Host ""
Write-Host "=" * 60
Write-Host "  [완료] 모든 더미 시나리오 실행 완료!"
Write-Host "  Event ID 4104 로그가 기록되었습니다."
Write-Host ""
Write-Host "  ▶ 다음 단계:"
Write-Host "     1. 브라우저에서 http://localhost:8501 접속"
Write-Host "     2. [Fileless 공격 탐지] 버튼 클릭"
Write-Host "     3. 탐지 결과 확인"
Write-Host "=" * 60

# 04번 (백그라운드 프로세스)은 별도로 안내
Write-Host ""
Write-Host "[참고] 백그라운드 프로세스 탐지 테스트는 별도 실행:" -ForegroundColor Cyan
Write-Host "       powershell -ExecutionPolicy Bypass -File .\04_hidden_background.ps1" -ForegroundColor DarkGray
