<#
.SYNOPSIS
    [더미 시나리오 03] 리플렉션 + 바이트 배열 조작 시뮬레이터
    탐지 대상: Reflection, [Byte], New-Object, System.Reflection.Assembly
    예상 위험도: HIGH (risk_score >= 0.6)

.DESCRIPTION
    실제 DLL 인젝션 없이 Reflection 기반 메모리 조작 패턴을 로그에 기록합니다.
    실제 공격에서는 .NET Reflection을 통해 메모리에 직접 악성 DLL을 로드합니다.
#>

Write-Host "[DUMMY-03] 리플렉션 + 바이트 배열 시뮬레이터 시작..." -ForegroundColor Yellow

# ─── Reflection 패턴 시뮬레이션 ────────────────────────────────────────────
# 실제 악성 DLL 없이 패턴만 기록
$simulationNote = "[DUMMY] System.Reflection.Assembly::Load 패턴 시뮬레이션"

# [Byte] 배열 조작 패턴 (탐지 대상) - 실제 내용은 안전한 더미 데이터
[Byte[]]$dummyBytes = @(0x44, 0x55, 0x4D, 0x4D, 0x59)  # "DUMMY" in ASCII
Write-Host "[INFO] 더미 바이트 배열: $dummyBytes" -ForegroundColor Cyan

# New-Object 패턴 포함 (안전)
$dummyObj = New-Object System.Collections.ArrayList
[void]$dummyObj.Add("DUMMY_PAYLOAD_SIMULATION")
Write-Host "[INFO] New-Object ArrayList 생성: $($dummyObj[0])" -ForegroundColor Cyan

# Reflection 패턴 기록 (실제 로드 없음)
$reflectionPattern = "System.Reflection.Assembly"
$loadPattern       = "[System.Reflection.Assembly]::Load([Byte[]]`$bytes)"
Write-Host "[INFO] 탐지 패턴 기록: $reflectionPattern" -ForegroundColor Cyan
Write-Host "[INFO] 시뮬레이션 코드: $loadPattern"     -ForegroundColor DarkGray

# ToString 패턴 포함
$hexDump = ($dummyBytes | ForEach-Object { $_.ToString("X2") }) -join " "
Write-Host "[INFO] 바이트 배열 ToString 변환: $hexDump" -ForegroundColor Cyan

Write-Host ""
Write-Host "[DUMMY-03] 완료 - Reflection/[Byte]/New-Object 패턴이 Event ID 4104 에 기록됨." -ForegroundColor Green
