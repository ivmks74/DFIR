# Lab 01 - simulated password guessing against the local host (localhost only).
# Produces a burst of failed network logons followed by one success,
# the classic shape of a password-guessing attempt that eventually works.
# Runs entirely against the local machine. Use only in your own lab VM.

$target   = "DFIR"
$badpass  = "WrongPass_123!"
$goodpass = Read-Host "Enter the account's real password"   # not stored in the repo

Write-Host "Failed attempts starting at $(Get-Date -Format HH:mm:ss)"
1..6 | ForEach-Object {
    net use \\localhost\IPC$ /user:$target $badpass 2>$null | Out-Null
    Start-Sleep -Seconds 3
}

Write-Host "Successful logon at $(Get-Date -Format HH:mm:ss)"
net use \\localhost\IPC$ /user:$target $goodpass 2>$null | Out-Null
net use \\localhost\IPC$ /delete 2>$null | Out-Null
Write-Host "Done."
