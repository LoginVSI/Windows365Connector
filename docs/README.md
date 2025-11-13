# Windows 365 Connector

This connector is used with Login Enterprise to start tests on Windows 365 Cloud PCs through the Windows App. It is driven by a PowerShell command line, plugs into a Login Enterprise test scenario as a Custom Connector, runs a JSON defined click path, and offloads password and TOTP handling to a separate helper script.

## What this connector does

- Launches the Windows App and cleans up stale windows from earlier runs.
- Detects whether the user is already signed in or needs to sign in.
- Types the Windows 365 username if the UI presents an email field.
- Calls a helper script that submits the password and an optional TOTP code.
- Waits for the Devices view and runs a JSON driven sequence of UI actions.
- Searches for the target Cloud PC by title and connects to it.
- Signs out at the end so the next iteration starts from a clean state.

## Prerequisites

You need the following in place before wiring this into a test scenario.

- Login Enterprise platform installed and reachable.  
  See [link](https://docs.loginvsi.com/login-enterprise/6.3/installation-and-deployment-1).

- At least one Launcher host with the Login Enterprise Launcher installed and attached to your environment.  
  See [link](https://docs.loginvsi.com/login-enterprise/6.3/configuring-the-windows-launcher).

- A test account created in Login Enterprise that can sign in to a Windows 365 Cloud PC.  
  The account should be added to Accounts in the Login Enterprise web UI.  
  See [link](https://docs.loginvsi.com/login-enterprise/6.3/managing-virtual-user-accounts).

- The Windows App installed on the Launcher host that will run this connector. This is the Microsoft client for Windows 365 Cloud PCs.  
  Download from Microsoft here: [link](https://apps.microsoft.com/detail/9n1f85v9t8bn?hl=en-US&gl=US).

- The Login Enterprise Standalone Engine extracted on the same Launcher host.  
  You need the path to `LoginEnterprise.Engine.Standalone.exe`. This is in the Universal Web Connector, which needs to be installed. After installation, the path will be at C:\Program Files\Login VSI\Universal Web Connector\engine\LoginEnterprise.Engine.Standalone.exe
  See [link](https://docs.loginvsi.com/login-enterprise/6.3/configuring-the-universal-web-connector#id-(6.3)ConfiguringtheUniversalWebConnector-downloading-and-installing-uwcDownloadingandInstallingUWC).

- This connector folder copied to the Launcher host, with all four files in the same directory:  

  - `Windows365Connector.ps1`
  - `Windows365Connector.cs`
  - `Windows365Connector_AuthenticationWindow.ps1`
  - `Windows365Connector.json`

- A Login Enterprise test scenario that:

  - Uses this Launcher host in the launcher selection.  
  - Uses the Custom Connector connector type.  
  - Has a Custom Connector command line that calls `Windows365Connector.ps1` (examples are below).  
  - Uses command line tokens so that username, password, host, and TOTP secret are not hardcoded.

  For test scenario setup, see [Continuous Testing](https://docs.loginvsi.com/login-enterprise/6.3/configuring-continuous-testing), [Application Testing](https://docs.loginvsi.com/login-enterprise/6.3/configuring-application-testing), or [Load Testing](https://docs.loginvsi.com/login-enterprise/6.3/configuring-load-testing).
  For Custom Connector configuration, see [link](https://docs.loginvsi.com/login-enterprise/6.3/configuring-connectors-and-connections#id-(6.3)ConfiguringConnectorsandConnections-custom-connectorCustomConnector).

- Secure custom fields and command line tokens:

  - Store the TOTP secret for the Windows 365 account in `securecustom1` in the Accounts page.  
    See [link](https://docs.loginvsi.com/login-enterprise/6.3/configuring-connectors-and-connections#id-(6.3)ConfiguringConnectorsandConnections-UsingSecuredCustomFieldsinTestsandConnectors).

  - Use the connector command line tokens so the scenario does not contain clear text credentials. Tokens like `{username}`, `{password}`, `{domain}`, `{host}`, and `{securecustom1}` are resolved by Login Enterprise at runtime and sent to the Launcher.  
    See [link](https://docs.loginvsi.com/login-enterprise/6.3/configuring-connectors-and-connections#id-(6.3)ConfiguringConnectorsandConnections-connection-command-line-3Connectioncommandline).  
    These tokens require Login Enterprise 6.3 or later.

- Optional: Process and window tracking for the Custom Connector (Login Enterprise 6.3 or later).  
  Configure the process tracking settings for this connector in the test scenario to improve run tracking and session end detection.  
  See [link](https://docs.loginvsi.com/login-enterprise/6.3/configuring-connectors-and-connections#id-(6.3)ConfiguringConnectorsandConnections-process-tracking-optionalProcessTracking(Optional)).

Once all of this is in place, you can configure the test workload, thresholds, and schedule in the test scenario as you normally would. Run the scenario, watch the Launcher during the first runs to confirm behavior, then review the results in the Test Scenarios reporting pages.  
For result review guidance, see viewing results of: [Continuous Tests](https://docs.loginvsi.com/login-enterprise/6.3/viewing-continuous-testing-results), [Application tests](https://docs.loginvsi.com/login-enterprise/6.3/viewing-application-testing-results), and [Load Tests](https://docs.loginvsi.com/login-enterprise/6.3/viewing-load-testing-results).

## Files in this repository

- `Windows365Connector.ps1`  
  Entry point for the connector.  
  Parses the command line parameters, builds the argument list for `LoginEnterprise.Engine.Standalone.exe`, wires up script, steps, auth script, timeout and TOTP settings, and launches the engine.

- `Windows365Connector.cs`  
  Login Enterprise workload script that runs inside the Standalone Engine.  
  Responsibilities:

  - Closes stale Windows App windows from previous runs.
  - Calls `START()` and waits for the main Windows App window.
  - Detects whether the user is already signed in (Account button) or needs to sign in (Sign in button).
  - Drives the sign in reset path when needed (Account → Sign out → Use another account).
  - Types the email address into the Windows App when an email field is visible.
  - Calls the external authentication handler script with the password and an optional TOTP code.
  - Waits for the Devices view to confirm successful authentication.
  - Loads `Windows365Connector.json` and executes the configured `steps` JSON array.
  - Searches for the target Cloud PC by title and clicks Connect.
  - Signs out after the connection lifecycle and verifies that the UI is back at Use another account.

- `Windows365Connector_AuthenticationWindow.ps1`  
  Helper script that attaches to the Microsoft authentication window, submits the password, and optionally submits a TOTP code.  
  It watches for the correct window, sends keystrokes with `System.Windows.Forms.SendKeys`, and logs success, timeout, or exception status to a log file under `%TEMP%\LoginEnterprise`.

- `Windows365Connector.json`  
  JSON file that defines additional UI steps to run inside the Windows App after authentication has completed.  
  Each entry in the `steps` array can specify:

  - `name`  
  - `action` (for example `find_and_click` or `wait`)  
  - `className`  
  - `title` (supports `{{TITLE}}` replacement with the Cloud PC title)  
  - `text`  
  - `waitSeconds`  

  The C# script reads this file at runtime and executes all defined steps in order. This allows you to extend the click path without recompiling the workload.

## High level flow

The connector flow, from entry to cleanup, looks like this:

```text
START
├─ Preflight: close stale Windows App windows
├─ Launch Windows App through Login Enterprise START()
├─ Wait for MainWindow to be available
├─ Bootstrap account state
│  ├─ If "Account" button found
│  │  ├─ Click Account
│  │  ├─ Click "Sign out"
│  │  └─ Click "Use another account"
│  └─ Else if "Sign in" button found
│     ├─ Click "Sign in"
│     ├─ If "Use another account" appears
│     │  └─ Click "Use another account"
│     └─ Else if BasicEmbeddedBrowser login window appears
│        └─ Focus window and type email address
├─ If MainWindow shows an "Email address" field
│  └─ Type email and press Enter
├─ Invoke external authentication handler script
│  ├─ Generate TOTP code if a TOTP secret is supplied
│  └─ Windows365Connector_AuthenticationWindow.ps1 types password and TOTP
├─ Wait for the "Devices" button to confirm successful authentication
├─ Load and execute steps from Windows365Connector.json
│  ├─ Click Devices
│  └─ Click Search and prepare for device lookup
├─ Type the Cloud PC title into the Search field
├─ Click "Connect to <Cloud PC title>"
├─ After the connection lifecycle
│  ├─ Click Account
│  ├─ Click "Sign out"
│  └─ Verify that "Use another account" is visible
└─ STOP
```

## Command line usage

The connector is started by calling `Windows365Connector.ps1` from the Login Enterprise Custom Connector command line.

### Direct example (hardcoded values)

```powershell -NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Minimized -File "C:\LoginEnterprise\Windows365Connector\Windows365Connector.ps1" -EnginePath "C:\LoginEnterprise\ScriptEditor\engine\LoginEnterprise.Engine.Standalone.exe" -Email "LoginVSI1@loginvsi.com" -Password "password" -Title "W365 Productivity - LoginVSI1" -TOTPSecret "totpsecret"```

### Example in a Login Enterprise Custom Connector command line

```powershell -NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Minimized -File "C:\LoginEnterprise\Windows365Connector\Windows365Connector.ps1" -EnginePath "C:\LoginEnterprise\ScriptEditor\engine\LoginEnterprise.Engine.Standalone.exe" -Email "{username}@{domain}.com" -Password "{password}" -Title "{host}" -TOTPSecret "{securecustom1}"```

This example assumes:

- The Account has `username`, `password`, and `domain` populated.
- The test scenario host field is set to the Cloud PC display name you want to connect to.
- `{securecustom1}` contains the Base32 TOTP secret for the Windows 365 account.

### Default TOTP behavior

If you do not specify the advanced TOTP parameters, the connector uses the built-in defaults from the C# workload:

- Time step: 30 seconds
- Digits: 6
- Algorithm: SHA1

These match the standard Microsoft identity platform settings and are correct for most Windows 365 accounts. Override these values only if your identity provider uses a non-standard MFA configuration.

### Advanced TOTP configuration example

To override the default behavior and use a different algorithm, larger time step window, or more digits:

```powershell -NoProfile -ExecutionPolicy RemoteSigned -WindowStyle Minimized -File "C:\LoginEnterprise\Windows365Connector\Windows365Connector.ps1" -EnginePath "C:\LoginEnterprise\ScriptEditor\engine\LoginEnterprise.Engine.Standalone.exe" -Email "{username}@{domain}.com" -Password "{password}" -Title "{host}" -TOTPSecret "{securecustom1}" -TOTPTimeStep 60 -TOTPDigits 8 -TOTPAlgorithm SHA512```

This allows you to match environments where MFA is configured with:

- longer drift tolerance  
- extended digit codes  
- stronger hashing algorithms  

### Parameters

| Parameter          | Required | Description                                                                                 |
|--------------------|----------|---------------------------------------------------------------------------------------------|
| `-EnginePath`      | Yes      | Full path to `LoginEnterprise.Engine.Standalone.exe` on the Launcher host.                 |
| `-Email`           | Yes      | Windows 365 user principal name. Used in the Windows App sign in and account selection.    |
| `-Password`        | Yes      | Password for the Windows 365 account. Passed into the authentication handler script.       |
| `-Title`           | Yes      | Cloud PC display name as shown in the Windows App Devices view. Used to find the device.   |
| `-TOTPSecret`      | No       | Base32 encoded TOTP secret. If set, a TOTP code is generated and submitted during sign in. |
| `-TimeoutSeconds`  | No       | Global timeout used by the workload for major waits. Defaults to 60 seconds.               |
| `-TOTPTimeStep`    | No       | TOTP time step window in seconds. Default is 30.                                           |
| `-TOTPDigits`      | No       | Number of digits in the TOTP code. Default is 6.                                           |
| `-TOTPAlgorithm`   | No       | Hash algorithm used for generating TOTP codes. Supported values: SHA1, SHA256, SHA512. Default is SHA1. |
| `-ScriptPath`      | No       | Override path for the main C# workload script. Usually not required.                      |
| `-StepsPath`       | No       | Override path for the JSON steps file. Usually not required.                              |
| `-AuthScriptPath`  | No       | Override path for the authentication handler script. Usually not required.                |

The C# workload also supports these values via equivalent environment variables: `TOTP_SECRET`, `TOTP_TIME_STEP`, `TOTP_DIGITS`, `TOTP_ALGORITHM`, and `W365_TIMEOUT`.

## Tested environment

This connector was developed and validated with the following environment:

- Windows App version: 2.0.706.0  
- Client version: 1.2.6515.0  
- Host operating system: Windows 11 Pro x64 25H2

Other versions may work, but these builds were used during development and testing. If you see UI locator issues or unexpected behavior, confirm the Windows App and client builds first.