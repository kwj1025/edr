<#
.SYNOPSIS
    [더미 시나리오 05] 문자열 난독화 체이닝 시뮬레이터
    탐지 대상: Replace, ToString, $env, cmd /c, 변수 보간, 메서드 체이닝
    예상 위험도: MEDIUM (risk_score >= 0.4)

.DESCRIPTION
    실제 공격에서 사용되는 문자열 난독화 기법을 안전하게 시뮬레이션합니다.
    Replace/ToString 체이닝으로 의심 문자열을 분리하여 탐지를 우회하는 패턴입니다.
#>

Write-Host "[DUMMY-05] 문자열 난독화 체이닝 시뮬레이터 시작..." -ForegroundColor Yellow

# ─── Replace 난독화 패턴 (탐지 대상) ─────────────────────────────────────
# 실제 공격: "IEX".Replace("I","").Replace("EX","Get-Process")
# 더미: 안전한 문자열로 같은 패턴 사용
$obfStr1 = "DUMMY_PAYLOAD".Replace("DUMMY_", "").Replace("PAYLOAD", "SIMULATION")
Write-Host "[INFO] Replace 체이닝 결과: $obfStr1" -ForegroundColor Cyan

# ─── ToString + 환경변수 접근 패턴 ──────────────────────────────────────
$envPath = $env:TEMP
$envOS   = $env:OS
Write-Host "[INFO] `$env 환경변수 접근: TEMP=$envPath, OS=$envOS" -ForegroundColor Cyan

# ─── 변수 보간 패턴 (중괄호 방식) ───────────────────────────────────────
${dummyVar} = "FILELESS_SIMULATION_ONLY"
Write-Host "[INFO] 변수 보간 패턴: ${dummyVar}" -ForegroundColor Cyan

# ─── 메서드 체이닝 패턴 ─────────────────────────────────────────────────
$chainResult = "dummy" .ToUpper() .Replace("D", "S") .ToString()
Write-Host "[INFO] 메서드 체이닝: $chainResult" -ForegroundColor Cyan

# ─── cmd /c 패턴 포함 ───────────────────────────────────────────────────
$cmdPattern = "cmd /c echo DUMMY_OBFUSCATION_TEST"
Write-Host "[INFO] cmd /c 패턴 기록: $cmdPattern" -ForegroundColor Cyan

# ─── [System.Text.Encoding] 패턴 ────────────────────────────────────────
$encoded = [System.Text.Encoding]::UTF8.GetBytes("DUMMY")
$decoded = [System.Text.Encoding]::UTF8.GetString($encoded)
Write-Host "[INFO] System.Text.Encoding 패턴: $decoded" -ForegroundColor Cyan

Write-Host ""
Write-Host "[DUMMY-05] 완료 - 난독화/Replace/`$env/ToString 패턴이 Event ID 4104 에 기록됨." -ForegroundColor Green
