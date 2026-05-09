import subprocess
import re

# PowerShell로 Sysmon 이벤트 직접 읽기
cmd = """
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20 |
Select-Object Id, TimeCreated, Message |
Format-List
"""

result = subprocess.run(
    ["powershell", "-Command", cmd],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace"
)

print("stdout:")
print(result.stdout[:3000])

if result.stderr:
    print("stderr:")
    print(result.stderr[:500])