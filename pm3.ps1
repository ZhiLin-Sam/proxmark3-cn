param([string]$cmd="")

$usbipd = "C:\Program Files\usbipd-win\usbipd.exe"

$list = & $usbipd list 2>&1 | Out-String
if ($list -match "(\d+-\d+)\s+9ac4:4b8f") {
    $busid = $Matches[1]
    Write-Host "[+] PM3 detected @ BUSID $busid"
} else {
    Write-Host "[X] PM3 not found (VID:9AC4 PID:4B8F)"
    Write-Host "    Check USB connection and usbipd-win"
    exit 1
}

wsl -d Ubuntu bash -c "echo" 2>$null | Out-Null
Write-Host "[+] WSL2 running"

& $usbipd bind --force --busid $busid 2>$null
& $usbipd attach --wsl --busid $busid 2>$null
Start-Sleep -Seconds 2
Write-Host "[+] USB attached (waiting 2s for device init)"

$client = "~/pm3_cn2/client/proxmark3"
$qt = "QT_QPA_PLATFORM=offscreen QT_LOGGING_RULES='*=false'"

if ($cmd -ne "") {
    wsl -d Ubuntu bash -c "$qt $client /dev/ttyACM0 -c `"$cmd`""
} else {
    wsl -d Ubuntu bash -c "$qt $client /dev/ttyACM0"
}
