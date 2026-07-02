<#
.SYNOPSIS
    [더미 시나리오 02] Base64 인코딩 명령어 시뮬레이터
    탐지 대상: -EncodedCommand, FromBase64String, -NoProfile
    예상 위험도: HIGH (risk_score >= 0.7)

.DESCRIPTION
    실제 악성 행위 없이 인코딩된 명령어 패턴을 이벤트 로그에 기록합니다.
    실제 공격자들은 -EncodedCommand 플래그를 사용하여 탐지를 우회합니다.
#>

Write-Host "[DUMMY-02] Base64 인코딩 명령어 시뮬레이터 시작..." -ForegroundColor Yellow

# ─── 안전한 문자열을 Base64 인코딩 (실제 악성 코드 없음) ───────────────────
$safeMessage  = "Write-Host 'DUMMY: This is a simulated encoded payload for EDR testing only'"
$encodedBytes  = [System.Text.Encoding]::Unicode.GetBytes($safeMessage)
$encodedString = [Convert]::ToBase64String($encodedBytes)

Write-Host "[INFO] 인코딩된 페이로드 생성 (안전한 내용):" -ForegroundColor Cyan
Write-Host "       $encodedString" -ForegroundColor DarkGray

# ─── 탐지 패턴 포함 명령어 (실행은 안전한 문자열 출력) ────────────────────
# 아래 형태의 명령어가 Event ID 4104 로그에 기록됨
$simulatedEncodedCmd = "powershell.exe -NoProfile -EncodedCommand $encodedString"
Write-Host "[INFO] 시뮬레이션 명령어:" -ForegroundColor Cyan
Write-Host "       $simulatedEncodedCmd" -ForegroundColor DarkGray

# FromBase64String 패턴 포함 (탐지용 - 실제 실행은 안전)
$decodedFromBase64 = [System.Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String($encodedString)
)
Write-Host "[INFO] FromBase64String 복원 결과: $decodedFromBase64" -ForegroundColor Cyan

# 실제 인코딩된 명령 실행 (안전한 에코만 수행)
powershell.exe -NoProfile -EncodedCommand $encodedString

Write-Host ""
Write-Host "[DUMMY-02] 완료 - -EncodedCommand 패턴이 Event ID 4104 에 기록됨." -ForegroundColor Green
