param(
    [Parameter(Mandatory=$true)]
    [string]$Password,
    
    [Parameter(Mandatory=$false)]
    [string]$TOTPCode = $null,
    
    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 60
)

# Setup logging
$logDir = "$env:TEMP\LoginEnterprise"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$logFile = Join-Path $logDir "Windows365Connector_AuthWindow_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
}

Write-Log "Windows365Connector_AuthenticationWindow.ps1 started"
Write-Log "Password: [REDACTED]"
Write-Log "TOTP Code: $(if ([string]::IsNullOrEmpty($TOTPCode)) { '[NOT PROVIDED]' } else { '[PROVIDED]' })"
Write-Log "Timeout: $TimeoutSeconds seconds"
Write-Log "Log file: $logFile"

function Find-Element {
    param(
        [System.Windows.Automation.AutomationElement]$SearchRoot,
        [System.Windows.Automation.PropertyCondition]$Condition,
        [string]$Description,
        [int]$TimeoutSeconds = 10
    )
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $elements = $SearchRoot.FindAll([System.Windows.Automation.TreeScope]::Descendants, $Condition)
        if ($elements.Count -gt 0) {
            Write-Log "Found $Description"
            return $elements
        }
        Start-Sleep -Milliseconds 200
    }
    
    Write-Log "TIMEOUT: $Description not found within $TimeoutSeconds seconds."
    return $null
}

try {
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        Write-Log "Searching for Authentication Window..."
        
        $rootElement = [System.Windows.Automation.AutomationElement]::RootElement
        $classNameCondition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ClassNameProperty,
            "ApplicationFrameWindow"
        )
        
        $windows = $rootElement.FindAll([System.Windows.Automation.TreeScope]::Children, $classNameCondition)
        
        $authWindows = @()
        foreach ($window in $windows) {
            try {
                $processId = $window.Current.ProcessId
                $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if ($process -and ($process.ProcessName -eq "explorer" -or $process.ProcessName -eq "ApplicationFrameHost")) {
                    $authWindows += $window
                }
            }
            catch { }
        }
        
        if ($authWindows.Count -ne 1) {
            Start-Sleep -Milliseconds 500
            continue
        }
        
        $authWindow = $authWindows[0]
        Write-Log "Authentication Window found."
        
        # Step 1: Find and fill password field
        Write-Log "Step 1: Finding password field (timeout: $($TimeoutSeconds)s)..."
        $editCondition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Edit
        )
        $editControls = Find-Element -SearchRoot $authWindow -Condition $editCondition -Description "password field" -TimeoutSeconds $TimeoutSeconds
        
        if ($editControls -eq $null) {
            Write-Log "ERROR: Password field not found."
            exit 3
        }
        
        $passwordField = $null
        foreach ($control in $editControls) {
            if ($control.Current.Name -match "Enter the password for") {
                $passwordField = $control
                break
            }
        }
        
        if ($passwordField -eq $null) {
            Write-Log "ERROR: Password field not found."
            exit 3
        }
        
        Start-Sleep -Seconds 1
        Write-Log "Typing password..."
        $passwordField.SetFocus()
        Start-Sleep -Milliseconds 500
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait($Password)
        [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
        Write-Log "Password submitted."
        
        # If no TOTP code, we're done
        if ([string]::IsNullOrEmpty($TOTPCode)) {
            Write-Log "SUCCESS: Password-only flow complete (TOTP not provided)."
            exit 0
        }
        
        # Step 2: TOTP flow - wait for one of three possible screens
        Write-Log "Step 2: Waiting for MFA screen (timeout: $($TimeoutSeconds)s)..."
        Write-Log "Looking for: Authenticator hyperlink, Verification button, or Code field"
        Start-Sleep -Seconds 2
        
        $hyperlinkCondition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Hyperlink
        )
        
        $buttonCondition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Button
        )
        
        $mfaTimeout = [System.Diagnostics.Stopwatch]::StartNew()
        $foundScreen = $null
        
        while ($mfaTimeout.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
            # Check for Authenticator hyperlink
            $hyperlinks = $authWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $hyperlinkCondition)
            foreach ($link in $hyperlinks) {
                if ($link.Current.Name -match "can't use my Microsoft Authenticator") {
                    Write-Log "Found: Authenticator hyperlink screen"
                    $foundScreen = "authenticator"
                    break
                }
            }
            
            if ($foundScreen -eq $null) {
                # Check for Verification button
                $buttons = $authWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $buttonCondition)
                foreach ($btn in $buttons) {
                    if ($btn.Current.Name -match "Use a verification code") {
                        Write-Log "Found: Verification button screen"
                        $foundScreen = "verification"
                        break
                    }
                }
            }
            
            if ($foundScreen -eq $null) {
                # Check for Code field
                $edits = $authWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $editCondition)
                foreach ($edit in $edits) {
                    if ($edit.Current.Name -match "Enter code") {
                        Write-Log "Found: Code field screen"
                        $foundScreen = "codefield"
                        break
                    }
                }
            }
            
            if ($foundScreen -ne $null) { break }
            Start-Sleep -Milliseconds 300
        }
        
        if ($foundScreen -eq $null) {
            Write-Log "ERROR: No MFA screen found."
            exit 4
        }
        
        # Handle based on what screen we found
        if ($foundScreen -eq "authenticator") {
            Write-Log "Handling Authenticator hyperlink flow..."
            Start-Sleep -Seconds 1
            $hyperlinks = $authWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $hyperlinkCondition)
            foreach ($link in $hyperlinks) {
                if ($link.Current.Name -match "can't use my Microsoft Authenticator") {
                    Write-Log "Clicking Authenticator hyperlink..."
                    $invokePattern = $link.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
                    $invokePattern.Invoke()
                    Start-Sleep -Seconds 1
                    break
                }
            }
            
            # Now look for verification button
            Write-Log "Looking for verification button..."
            $buttons = Find-Element -SearchRoot $authWindow -Condition $buttonCondition -Description "verification button" -TimeoutSeconds $TimeoutSeconds
            if ($buttons -ne $null) {
                foreach ($btn in $buttons) {
                    if ($btn.Current.Name -match "Use a verification code") {
                        Start-Sleep -Seconds 1
                        Write-Log "Clicking verification button..."
                        $invokePattern = $btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
                        $invokePattern.Invoke()
                        Start-Sleep -Seconds 1
                        break
                    }
                }
            }
        }
        elseif ($foundScreen -eq "verification") {
            Write-Log "Handling Verification button flow..."
            Start-Sleep -Seconds 1
            $buttons = $authWindow.FindAll([System.Windows.Automation.TreeScope]::Descendants, $buttonCondition)
            foreach ($btn in $buttons) {
                if ($btn.Current.Name -match "Use a verification code") {
                    Write-Log "Clicking verification button..."
                    $invokePattern = $btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
                    $invokePattern.Invoke()
                    Start-Sleep -Seconds 1
                    break
                }
            }
        }
        
        # Step 3: Find code field and enter TOTP
        Write-Log "Step 3: Finding code field (timeout: $($TimeoutSeconds)s)..."
        $editControls = Find-Element -SearchRoot $authWindow -Condition $editCondition -Description "code field" -TimeoutSeconds $TimeoutSeconds
        
        if ($editControls -eq $null) {
            Write-Log "ERROR: Code field not found."
            exit 4
        }
        
        $codeField = $null
        foreach ($control in $editControls) {
            if ($control.Current.Name -match "Enter code") {
                $codeField = $control
                break
            }
        }
        
        if ($codeField -eq $null) {
            Write-Log "ERROR: Code field not found."
            exit 4
        }
        
        Start-Sleep -Seconds 1
        Write-Log "Typing TOTP code..."
        $codeField.SetFocus()
        Start-Sleep -Milliseconds 500
        [System.Windows.Forms.SendKeys]::SendWait($TOTPCode)
        [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
        
        Write-Log "SUCCESS: Password and TOTP submitted (credentials not displayed)."
        exit 0
    }
    
    Write-Log "TIMEOUT: No valid authentication flow completed within $TimeoutSeconds seconds."
    exit 1
}
catch {
    Write-Log "EXCEPTION: $_"
    exit 99
}