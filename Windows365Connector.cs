// TARGET:Windows365.exe
// START_IN:
using LoginPI.Engine.ScriptBase;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;

public class Windows365Connector : ScriptBase
{
    // watcher flags (class-level)
    private bool _cancelWatchers = false;
    private bool _accountPathTaken = false;
    private bool _signInPathTaken = false;

    void Execute()
    {
        // ---- configuration vars ----
        int globalFunctionTimeoutInSeconds = 60;
        int globalWaitInSeconds = 1; 
        int globalCharactersPerMinuteToType = 1000;

        try
        {
            // ---- runtime inputs ----
            string runtimeEmail    = GetRequiredArg("--email", "W365_EMAIL");
            string runtimePassword = GetRequiredArg("--password", "W365_PASSWORD");
            string cloudPcTitle    = GetRequiredArg("--title", "W365_TITLE");
            string stepsPath       = GetRequiredArg("--steps", "W365_STEPS");
            string authScript      = GetRequiredArg("--authscript", "W365_AUTH_SCRIPT");
            
            int timeoutSeconds     = GetIntArg("--timeout", "W365_TIMEOUT", 60);
            int totpTimeStep       = GetIntArg("--timestep", "TOTP_TIME_STEP", 30);
            int totpDigits         = GetIntArg("--digits", "TOTP_DIGITS", 6);
            string totpAlgorithm   = GetStringArg("--algorithm", "TOTP_ALGORITHM", "SHA1");
            string totpSecret      = GetOptionalArg("--secret", "TOTP_SECRET");

            Log("[Windows365] Script start.");
            Log($"[Windows365] Email: [REDACTED]");
            Log($"[Windows365] Title: {cloudPcTitle}");
            Log($"[Windows365] TOTP: {(string.IsNullOrEmpty(totpSecret) ? "Disabled" : "Enabled")}");

            globalFunctionTimeoutInSeconds = timeoutSeconds;

            // --- PREP: close stale Windows App windows ---
            bool foundAnyStale = false;
            try
            {
                var stale1 = FindWindow(className: "Win32 Window:BasicEmbeddedBrowser", title: "Windows App", processName: "Windows365", continueOnError: true, timeout: 1);
                if (stale1 != null) { try { stale1.Close(); Log("[Windows365] Closed stale BasicEmbeddedBrowser."); foundAnyStale = true; } catch (Exception ex) { Log("[Windows365] stale1 close ex: " + ex.ToString()); } }

                var stale2 = FindWindow(className: "Win32 Window:MainWindow", title: "Windows App", processName: "Windows365", continueOnError: true, timeout: 1);
                if (stale2 != null) { try { stale2.Close(); Log("[Windows365] Closed stale MainWindow."); foundAnyStale = true; } catch (Exception ex) { Log("[Windows365] stale2 close ex: " + ex.ToString()); } }

                // stale3: lingering password / ApplicationFrameWindow style windows
                var stale3Hwnd = FindTopLevelWindowByClassAndProcesses("Win32 Window:ApplicationFrameWindow", new[] { "explorer", "ApplicationFrameHost" }, 1);
                if (stale3Hwnd != IntPtr.Zero)
                {
                    try
                    {
                        const uint WM_CLOSE = 0x0010;
                        PostMessage(stale3Hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                        Log("[Windows365] Posted WM_CLOSE to stale ApplicationFrameWindow HWND.");
                        foundAnyStale = true;
                        Wait(globalWaitInSeconds);
                    }
                    catch (Exception ex) { Log("[Windows365] stale3 WM_CLOSE ex: " + ex.ToString()); }
                }
            }
            catch (Exception exPrep) { Log("[Windows365] Prep exception: " + exPrep.ToString()); }

            if (foundAnyStale)
            {
                Log("[Windows365] Found stale windows during prep; waiting a brief moment for OS to settle.");
                Wait(globalWaitInSeconds * 2);
            }

            // Start application
            START();
            Wait(globalWaitInSeconds);
            MainWindow.Focus();

            // Wait for MainWindow to appear 
            Log("[Windows365] Waiting for MainWindow to be present...");
            DateTime mwDeadline = DateTime.UtcNow.AddSeconds(globalFunctionTimeoutInSeconds);
            while (MainWindow == null && DateTime.UtcNow < mwDeadline)
            {
                Log("[Windows365] waiting for MainWindow...");
                Wait(globalWaitInSeconds);
            }
            if (MainWindow == null)
            {
                throw new Exception("MainWindow is null after START() and wait timeout (" + globalFunctionTimeoutInSeconds + "s).");
            }
            Log("[Windows365] MainWindow is present.");

            // === Bootstrap poll: Account (already signed-in) vs Sign in (unsigned) ===
            Log("[Windows365] Bootstrap: polling for Account vs Sign in...");
            _cancelWatchers = false;
            _accountPathTaken = false;
            _signInPathTaken = false;
            DateTime stopAt = DateTime.UtcNow.AddSeconds(globalFunctionTimeoutInSeconds);

            while (DateTime.UtcNow < stopAt && !_cancelWatchers)
            {
                try
                {
                    var accountProbe = MainWindow.FindControl(className: "Button:ms-Button ms-Button--icon account-button-up root*", title: "Account", timeout: 1, continueOnError: true)
                                        ?? MainWindow.FindControl(className: "Button:account-button", title: "Account", timeout: 1, continueOnError: true);

                    if (accountProbe != null)
                    {
                        Log("[Windows365] Account detected (signed-in). Preparing sign-out -> use another account reset.");                        
                        Wait(globalWaitInSeconds);
                        try { accountProbe.Click(); Log("[Windows365] Clicked Account probe."); } catch (Exception ex) { Log("[Windows365] accountProbe.Click() ex: " + ex.ToString()); }

                        var signOutBtn = MainWindow.FindControl(className: "Button:fui-Button *", title: "Sign out", timeout: globalFunctionTimeoutInSeconds, continueOnError: true);
                        if (signOutBtn != null)
                        {
                            Wait(globalWaitInSeconds);
                            try { signOutBtn.Click(); Log("[Windows365] Clicked Sign out during reset."); } catch (Exception ex) { Log("[Windows365] signOutBtn.Click() ex: " + ex.ToString()); }
                        }

                        var useAnother = MainWindow.FindControl(className: "Button:account-button", title: "Use another account", timeout: globalFunctionTimeoutInSeconds, continueOnError: true)
                                        ?? MainWindow.FindControl(className: "Button:ms-Button ms-Button--icon account-button-up root*", title: "Use another account", timeout: globalFunctionTimeoutInSeconds, continueOnError: true);
                        if (useAnother != null)
                        {
                            Wait(globalWaitInSeconds);
                            try { useAnother.Click(); Log("[Windows365] Clicked 'Use another account' after reset."); } catch (Exception ex) { Log("[Windows365] useAnother.Click() ex: " + ex.ToString()); }
                        }
                        
                        _accountPathTaken = true;
                        _cancelWatchers = true;
                        break;
                    }

                    var signInProbe = MainWindow.FindControl(className: "Button:fui-Button *", title: "Sign in", timeout: 1, continueOnError: true);
                    if (signInProbe != null)
                    {
                        _signInPathTaken = true;
                        _cancelWatchers = true;
                        Log("[Windows365] Sign in detected (unsigned).");
                        break;
                    }
                }
                catch (Exception ex) { Log("[Windows365] bootstrap poll exception: " + ex.ToString()); }

                Wait(globalWaitInSeconds);
            }

            Log($"[Windows365] Bootstrap result: accountPathTaken={_accountPathTaken}, signInPathTaken={_signInPathTaken}");

            // --- Handle sign-in flow if needed ---
            if (_signInPathTaken)
            {
                Log("[Windows365] Clicking the Sign in button.");
                var SignInButton = MainWindow.FindControl(className: "Button:fui-Button *", title: "Sign in", timeout: globalFunctionTimeoutInSeconds, continueOnError: true);
                if (SignInButton != null)
                {
                    Wait(globalWaitInSeconds);
                    try { SignInButton.Click(); Log("[Windows365] Clicked Sign in."); } catch (Exception ex) { Log("[Windows365] SignInButton.Click() ex: " + ex.ToString()); }
                }
                else
                {
                    Log("[Windows365] SignInButton not found at expected location.");
                }

                // After clicking Sign in, watch for either "Use another account" or the ApplicationFrameWindow auth window
                bool subFlowTaken = false;
                DateTime subStop = DateTime.UtcNow.AddSeconds(globalFunctionTimeoutInSeconds);
                while (DateTime.UtcNow < subStop && !subFlowTaken)
                {
                    try
                    {
                        var useAnotherAfterSignIn = MainWindow.FindControl(className: "Button:account-button", title: "Use another account", timeout: 1, continueOnError: true)
                                                      ?? MainWindow.FindControl(className: "Button:ms-Button ms-Button--icon account-button-up root*", title: "Use another account", timeout: 1, continueOnError: true);
                        if (useAnotherAfterSignIn != null)
                        {
                            Wait(globalWaitInSeconds);
                            try { useAnotherAfterSignIn.Click(); Log("[Windows365] After Sign in -> clicked Use another account."); } catch (Exception ex) { Log("[Windows365] useAnotherAfterSignIn.Click() ex: " + ex.ToString()); }
                            subFlowTaken = true;
                            break;
                        }

                        // Check for ApplicationFrameWindow (new email auth window location)
                        var authWindowHwnd = FindTopLevelWindowByClassAndProcesses("Win32 Window:ApplicationFrameWindow", new[] { "explorer", "ApplicationFrameHost" }, 1);
                        if (authWindowHwnd != IntPtr.Zero)
                        {
                            Log("[Windows365] After Sign in -> detected ApplicationFrameWindow auth window. Delegating to external auth handler.");
                            subFlowTaken = true;
                            break;
                        }
                    }
                    catch (Exception ex) { Log("[Windows365] subflow poll ex: " + ex.ToString()); }

                    Wait(globalWaitInSeconds);
                }

                if (!subFlowTaken) Log("[Windows365] Subflow after Sign in: neither Use another account nor ApplicationFrameWindow detected.");
            }

            // ---------------------------
            // EXTERNAL AUTHENTICATION HANDLER (Email + Password + TOTP)
            // ---------------------------
            try
            {
                Log("[Windows365] Invoking external authentication handler...");
                
                string totpCode = null;
                if (!string.IsNullOrEmpty(totpSecret))
                {
                    Log("[Windows365] Generating TOTP code...");
                    totpCode = GenerateTOTPCode(totpSecret, totpTimeStep, totpDigits, totpAlgorithm);
                    Log("[Windows365] TOTP code generated (hidden from logging)");
                }

                int authExitCode = InvokeAuthenticationHandler(authScript, runtimeEmail, runtimePassword, totpCode, globalFunctionTimeoutInSeconds);
                
                if (authExitCode == 0)
                {
                    Log("[Windows365] Authentication handler completed successfully.");
                }
                else
                {
                    Log($"[Windows365] Authentication handler exited with code: {authExitCode}");
                }

                // Clear password from environment
                try { Environment.SetEnvironmentVariable("W365_PASSWORD", ""); } catch { }
            }
            catch (Exception ex) { Log("[Windows365] Authentication handler exception: " + ex.ToString()); }

            // ---------------------------
            // Wait for Devices button (60-second timeout) after auth completes
            // ---------------------------
            Log("[Windows365] Waiting for Devices button to appear (auth should be complete by now)...");
            DateTime devicesDeadline = DateTime.UtcNow.AddSeconds(60);
            bool devicesFound = false;
            while (DateTime.UtcNow < devicesDeadline)
            {
                try
                {
                    var devicesBtn = MainWindow.FindControl(className: "Button:fui-Button *", title: "Devices*", timeout: 1, continueOnError: true);
                    if (devicesBtn != null)
                    {
                        Log("[Windows365] Devices button found (authentication confirmed).");
                        devicesFound = true;
                        break;
                    }
                }
                catch (Exception ex) { Log("[Windows365] Devices button search exception: " + ex.ToString()); }

                Wait(globalWaitInSeconds);
            }

            if (!devicesFound)
            {
                Log("[Windows365] WARNING: Devices button not found after 60-second wait. Continuing anyway...");
            }

            // =============================================================================
            // Execute all steps from JSON
            // =============================================================================
            Log("[Windows365] Loading JSON steps file...");
            try
            {
                string stepsJson = File.ReadAllText(stepsPath);
                Log("[Windows365] JSON loaded, parsing steps...");
                
                var stepsMatch = Regex.Match(stepsJson, "\"steps\"\\s*:\\s*\\[(.*?)\\]", RegexOptions.Singleline | RegexOptions.IgnoreCase);
                if (stepsMatch.Success)
                {
                    var body = stepsMatch.Groups[1].Value;
                    var objs = Regex.Matches(body, "\\{(.*?)\\}", RegexOptions.Singleline);
                    
                    Log($"[Windows365] Found {objs.Count} step(s) to execute");
                    
                    if (objs.Count > 0)
                    {
                        for (int i = 0; i < objs.Count; i++)
                        {
                            try
                            {
                                var stepMatch = objs[i];
                                var stepObj = stepMatch.Groups[1].Value;
                                
                                string stepName = MatchString(stepObj, "name") ?? ("step_" + (i + 1));
                                string stepAction = MatchString(stepObj, "action") ?? "";
                                string stepClassName = MatchString(stepObj, "className") ?? "";
                                string stepTitle = MatchString(stepObj, "title") ?? "";
                                string stepText = MatchString(stepObj, "text") ?? "";
                                int stepWaitSeconds = MatchInt(stepObj, "waitSeconds", 0);
                                
                                stepTitle = stepTitle.Replace("{{TITLE}}", cloudPcTitle);
                                stepText = stepText.Replace("{{TITLE}}", cloudPcTitle);
                                
                                Log($"[Windows365] Step {i + 1}/{objs.Count} '{stepName}' action '{stepAction}'");
                                
                                if (stepAction.Equals("find_and_click", StringComparison.OrdinalIgnoreCase) || stepAction.Equals("click", StringComparison.OrdinalIgnoreCase))
                                {
                                    Log($"[Windows365] Looking for className='{stepClassName}', title='{stepTitle}'");
                                    var control = MainWindow.FindControl(className: stepClassName, title: stepTitle, timeout: globalFunctionTimeoutInSeconds, continueOnError: true);
                                    if (control != null)
                                    {
                                        Wait(globalWaitInSeconds);
                                        try
                                        {
                                            control.Click();
                                            Log($"[Windows365] Successfully clicked '{stepTitle}'");
                                        }
                                        catch (Exception ex)
                                        {
                                            Log($"[Windows365] Failed to click: {ex.ToString()}");
                                        }
                                    }
                                    else
                                    {
                                        Log($"[Windows365] Control not found");
                                    }
                                }
                                else if (stepAction.Equals("wait", StringComparison.OrdinalIgnoreCase))
                                {
                                    int waitSecs = stepWaitSeconds > 0 ? stepWaitSeconds : 1;
                                    Log($"[Windows365] Waiting {waitSecs} seconds");
                                    Wait(waitSecs);
                                }
                                else
                                {
                                    Log($"[Windows365] Action '{stepAction}' not yet supported");
                                }
                                
                                if (stepWaitSeconds > 0)
                                {
                                    Log($"[Windows365] Post-step wait {stepWaitSeconds} seconds");
                                    Wait(stepWaitSeconds);
                                }
                            }
                            catch (Exception exStep)
                            {
                                Log($"[Windows365] Step {i + 1} failed: {exStep.ToString()}");
                            }
                        }
                        
                        Log("[Windows365] All JSON steps completed");
                    }
                    else
                    {
                        Log("[Windows365] No steps found in JSON");
                    }
                }
                else
                {
                    Log("[Windows365] Could not parse 'steps' array from JSON");
                }
            }
            catch (Exception exJson)
            {
                Log("[Windows365] JSON execution error: " + exJson.ToString());
            }

            // =============================================================================
            // Continue with original hardcoded flow (Search -> Type -> Connect -> Signout)
            // =============================================================================

            // Search field, click, then type the cloudPcTitle
            try
            {
                var SearchField = MainWindow.FindControl(className: "Edit:fui-Input__input *", title: "Search", timeout: globalFunctionTimeoutInSeconds, continueOnError: true);
                if (SearchField != null)
                {
                    Wait(globalWaitInSeconds);
                    SearchField.Click();
                    Log("[Windows365] Clicked Search input.");

                    Wait(globalWaitInSeconds);
                    SearchField.Type(cloudPcTitle, cpm: globalCharactersPerMinuteToType, hideInLogging: false);
                    Log("[Windows365] Typed cloudPcTitle into Search field: " + cloudPcTitle);
                }
                else
                {
                    Log("[Windows365] Search input not found.");
                }
            }
            catch (Exception ex) { Log("[Windows365] Search/type exception: " + ex.ToString()); }

            // Find and click the Connect button
            try
            {
                var connectTitle = "Connect to " + cloudPcTitle;
                var ConnectButton = MainWindow.FindControl(className: "Button:fui-Button *", title: connectTitle, timeout: globalFunctionTimeoutInSeconds, continueOnError: true);
                if (ConnectButton != null)
                {
                    Wait(globalWaitInSeconds);
                    ConnectButton.Click();
                    Log($"[Windows365] Clicked Connect button (title='{connectTitle}').");
                }
                else
                {
                    Log($"[Windows365] Connect button with title '{connectTitle}' not found. Attempting fallback.");
                    var ConnectFallback = MainWindow.FindControl(className: "Button:fui-Button *", title: cloudPcTitle, timeout: globalFunctionTimeoutInSeconds, continueOnError: true);
                    if (ConnectFallback != null)
                    {
                        Wait(globalWaitInSeconds);
                        ConnectFallback.Click();
                        Log("[Windows365] Clicked fallback connect control.");
                    }
                }
            }
            catch (Exception ex) { Log("[Windows365] Connect click exception: " + ex.ToString()); }

            // Post-connection sign out: Account -> Sign out
            try
            {
                var AccountButton = MainWindow.FindControl(className: "Button:ms-Button ms-Button--icon account-button-up root*", title: "Account", timeout: globalFunctionTimeoutInSeconds, continueOnError: true)
                                   ?? MainWindow.FindControl(className: "Button:account-button", title: "Account", timeout: globalFunctionTimeoutInSeconds, continueOnError: true);

                if (AccountButton != null)
                {
                    Wait(globalWaitInSeconds);
                    AccountButton.Click();
                    Log("[Windows365] Clicked Account (post-connection).");

                    var SignOutButton = MainWindow.FindControl(className: "Button:fui-Button *", title: "Sign out", timeout: globalFunctionTimeoutInSeconds, continueOnError: true);
                    if (SignOutButton != null)
                    {
                        Wait(globalWaitInSeconds);
                        SignOutButton.Click();
                        Log("[Windows365] Clicked Sign out (post-connection).");
                    }
                    else Log("[Windows365] Sign out button not found (post-connection).");
                }
                else Log("[Windows365] Account button not found (post-connection).");
            }
            catch (Exception ex) { Log("[Windows365] Post-connection signout exception: " + ex.ToString()); }

            // Verify logged out by finding "Use another account"
            try
            {
                var UseAnother = MainWindow.FindControl(className: "Button:account-button", title: "Use another account", timeout: globalFunctionTimeoutInSeconds, continueOnError: true);
                if (UseAnother != null)
                {
                    Log("[Windows365] Found 'Use another account' (logged out).");
                }
                else
                {
                    Log("[Windows365] 'Use another account' not found after signout.");
                }
            }
            catch (Exception ex) { Log("[Windows365] Final use-another check exception: " + ex.ToString()); }

            STOP();
        }
        catch (Exception ex)
        {
            Log("[Windows365] FATAL unhandled exception in Execute(): " + ex.ToString());
            throw;
        }
    }

    // -------------------------------------------------------------------------
    // TOTP Generation
    // -------------------------------------------------------------------------
    private string GenerateTOTPCode(string totpSecret, int timeStep, int digits, string algorithm)
    {
        Func<string, byte[]> ConvertFromBase32 = (base32) =>
        {
            string base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            string bits = "";
            base32 = base32.Replace(" ", "").ToUpper();

            foreach (char c in base32)
            {
                int index = base32chars.IndexOf(c);
                if (index < 0) throw new Exception($"Invalid base32 character: {c}");
                bits += Convert.ToString(index, 2).PadLeft(5, '0');
            }

            byte[] bytes = new byte[(bits.Length - (bits.Length % 8)) / 8];
            for (int i = 0; i < bits.Length - 7; i += 8)
                bytes[i / 8] = Convert.ToByte(bits.Substring(i, 8), 2);

            return bytes;
        };

        Func<long, byte[]> ConvertToByteArray = (value) =>
        {
            byte[] bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return bytes;
        };

        byte[] secretBytes = ConvertFromBase32(totpSecret);
        long unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long counter = unixTime / timeStep;
        byte[] counterBytes = ConvertToByteArray(counter);

        HMAC hmac = algorithm switch
        {
            "SHA1" => new HMACSHA1(secretBytes),
            "SHA256" => new HMACSHA256(secretBytes),
            "SHA512" => new HMACSHA512(secretBytes),
            _ => throw new Exception($"Unsupported algorithm: {algorithm}")
        };

        byte[] hash = hmac.ComputeHash(counterBytes);
        int offset = hash[hash.Length - 1] & 0x0F;
        int binaryCode = ((hash[offset] & 0x7F) << 24) |
                        ((hash[offset + 1] & 0xFF) << 16) |
                        ((hash[offset + 2] & 0xFF) << 8) |
                        (hash[offset + 3] & 0xFF);

        int modulo = (int)Math.Pow(10, digits);
        string totpCode = (binaryCode % modulo).ToString().PadLeft(digits, '0');

        return totpCode;
    }

    // -------------------------------------------------------------------------
    // External Authentication Handler Invocation
    // -------------------------------------------------------------------------
    private int InvokeAuthenticationHandler(string scriptPath, string email, string password, string totpCode, int timeoutSeconds)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = BuildAuthHandlerArgs(scriptPath, email, password, totpCode, timeoutSeconds),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (var process = Process.Start(psi))
            {
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                
                if (!process.WaitForExit(timeoutSeconds * 1000 + 5000))
                {
                    Log("[Windows365] Authentication handler timeout - terminating process");
                    try { process.Kill(); } catch { }
                    return -1;
                }

                if (!string.IsNullOrWhiteSpace(output))
                    Log($"[Windows365] Auth handler output: {output}");

                if (!string.IsNullOrWhiteSpace(error))
                    Log($"[Windows365] Auth handler error: {error}");

                Log($"[Windows365] Authentication handler exit code: {process.ExitCode}");
                return process.ExitCode;
            }
        }
        catch (Exception ex)
        {
            Log($"[Windows365] ERROR invoking authentication handler: {ex.Message}");
            return -1;
        }
    }

    private string BuildAuthHandlerArgs(string scriptPath, string email, string password, string totpCode, int timeoutSeconds)
    {
        var args = $"-ExecutionPolicy RemoteSigned -WindowStyle Minimized -NoProfile -File \"{scriptPath}\" " +
                   $"-Email \"{EscapeForPowerShell(email)}\" " +
                   $"-Password \"{EscapeForPowerShell(password)}\" " +
                   $"-TimeoutSeconds {timeoutSeconds}";

        if (!string.IsNullOrEmpty(totpCode))
        {
            args += $" -TOTPCode \"{totpCode}\"";
        }

        return args;
    }

    private string EscapeForPowerShell(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;
        return value.Replace("\"", "\\\"").Replace("$", "`$");
    }

    // -------------------------------------------------------------------------
    // P/Invoke + helpers to find and close stale windows
    // -------------------------------------------------------------------------
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool BringWindowToTop(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern IntPtr SetActiveWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    private static string GetClassNameSafe(IntPtr hWnd)
    {
        var sb = new StringBuilder(256);
        try { GetClassName(hWnd, sb, sb.Capacity); } catch { return string.Empty; }
        return sb.ToString();
    }

    private static void BringWindowToFront(IntPtr hWnd)
    {
        try
        {
            if (hWnd == IntPtr.Zero) return;
            ShowWindow(hWnd, 5);
            uint currentThreadId = GetCurrentThreadId();
            GetWindowThreadProcessId(hWnd, out uint windowThreadId);
            AttachThreadInput(windowThreadId, currentThreadId, true);
            BringWindowToTop(hWnd);
            SetForegroundWindow(hWnd);
            SetActiveWindow(hWnd);
            AttachThreadInput(windowThreadId, currentThreadId, false);
            Thread.Sleep(150);
        }
        catch { }
    }

    private static IntPtr FindTopLevelWindowByClassAndProcesses(string rawClassName, string[] processNames, int timeoutSeconds)
    {
        if (string.IsNullOrEmpty(rawClassName)) throw new ArgumentNullException(nameof(rawClassName));
        if (processNames == null || processNames.Length == 0) throw new ArgumentNullException(nameof(processNames));

        string className = rawClassName;
        var colon = rawClassName.IndexOf(':');
        if (colon >= 0 && colon + 1 < rawClassName.Length) className = rawClassName.Substring(colon + 1);

        var procSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in processNames)
        {
            if (string.IsNullOrEmpty(p)) continue;
            var pn = p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? p.Substring(0, p.Length - 4) : p;
            procSet.Add(pn);
        }

        var sw = Stopwatch.StartNew();
        while (sw.Elapsed.TotalSeconds < timeoutSeconds)
        {
            IntPtr found = IntPtr.Zero;

            EnumWindows((hWnd, lParam) =>
            {
                try
                {
                    string currentClass = GetClassNameSafe(hWnd);
                    if (string.IsNullOrEmpty(currentClass)) return true;

                    if (!string.Equals(currentClass, className, StringComparison.OrdinalIgnoreCase)
                        && !currentClass.EndsWith(className, StringComparison.OrdinalIgnoreCase))
                        return true;

                    GetWindowThreadProcessId(hWnd, out uint pid);
                    try
                    {
                        var p = Process.GetProcessById((int)pid);
                        if (p != null && procSet.Contains(p.ProcessName))
                        {
                            found = hWnd;
                            return false;
                        }
                    }
                    catch { }
                }
                catch { }
                return true;
            }, IntPtr.Zero);

            if (found != IntPtr.Zero) return found;
            Thread.Sleep(120);
        }
        return IntPtr.Zero;
    }

    // -------------------------------------------------------------------------
    // Arg/Env helpers
    // -------------------------------------------------------------------------
    private string GetRequiredArg(string argName, string envName)
    {
        try
        {
            var args = Environment.GetCommandLineArgs();
            if (args != null)
            {
                foreach (var a in args)
                {
                    if (!string.IsNullOrEmpty(a) && a.StartsWith(argName + "=", StringComparison.OrdinalIgnoreCase))
                    {
                        var v = a.Substring((argName + "=").Length).Trim().Trim('"', '\'');
                        if (!string.IsNullOrEmpty(v)) return v;
                    }
                }
            }
        }
        catch { }

        try
        {
            var ev = Environment.GetEnvironmentVariable(envName);
            if (!string.IsNullOrEmpty(ev)) return ev;
        }
        catch { }

        throw new Exception($"Missing required argument: {argName} or env {envName}");
    }

    private string GetOptionalArg(string argName, string envName)
    {
        try
        {
            var args = Environment.GetCommandLineArgs();
            if (args != null)
            {
                foreach (var a in args)
                {
                    if (!string.IsNullOrEmpty(a) && a.StartsWith(argName + "=", StringComparison.OrdinalIgnoreCase))
                    {
                        var v = a.Substring((argName + "=").Length).Trim().Trim('"', '\'');
                        if (!string.IsNullOrEmpty(v)) return v;
                    }
                }
            }
        }
        catch { }

        try
        {
            var ev = Environment.GetEnvironmentVariable(envName);
            if (!string.IsNullOrEmpty(ev)) return ev;
        }
        catch { }

        return null;
    }

    private int GetIntArg(string argName, string envName, int defaultValue)
    {
        try
        {
            var args = Environment.GetCommandLineArgs();
            if (args != null)
            {
                foreach (var a in args)
                {
                    if (!string.IsNullOrEmpty(a) && a.StartsWith(argName + "=", StringComparison.OrdinalIgnoreCase))
                    {
                        var v = a.Substring((argName + "=").Length).Trim();
                        if (int.TryParse(v, out int result)) return result;
                    }
                }
            }
        }
        catch { }

        try
        {
            var ev = Environment.GetEnvironmentVariable(envName);
            if (!string.IsNullOrEmpty(ev) && int.TryParse(ev, out int result))
                return result;
        }
        catch { }

        return defaultValue;
    }

    private string GetStringArg(string argName, string envName, string defaultValue)
    {
        try
        {
            var args = Environment.GetCommandLineArgs();
            if (args != null)
            {
                foreach (var a in args)
                {
                    if (!string.IsNullOrEmpty(a) && a.StartsWith(argName + "=", StringComparison.OrdinalIgnoreCase))
                    {
                        var v = a.Substring((argName + "=").Length).Trim().Trim('"', '\'');
                        if (!string.IsNullOrEmpty(v)) return v;
                    }
                }
            }
        }
        catch { }

        try
        {
            var ev = Environment.GetEnvironmentVariable(envName);
            if (!string.IsNullOrEmpty(ev)) return ev;
        }
        catch { }

        return defaultValue;
    }

    // -------------------------------------------------------------------------
    // JSON helper methods (minimal parsing)
    // -------------------------------------------------------------------------
    private string MatchString(string obj, string prop)
    {
        var pat = "\"" + Regex.Escape(prop) + "\"\\s*:\\s*\"(?<v>(?:\\\\\"|[^\"])*)\"";
        var m = Regex.Match(obj, pat, RegexOptions.Singleline | RegexOptions.IgnoreCase);
        if (m.Success) return m.Groups["v"].Value.Replace("\\\"", "\"");
        return null;
    }

    private int MatchInt(string obj, string prop, int def)
    {
        var pat = "\"" + Regex.Escape(prop) + "\"\\s*:\\s*(?<v>\\d+)";
        var m = Regex.Match(obj, pat, RegexOptions.Singleline | RegexOptions.IgnoreCase);
        if (m.Success && int.TryParse(m.Groups["v"].Value, out var v)) return v;
        return def;
    }

    private bool MatchBool(string obj, string prop, bool def)
    {
        var pat = "\"" + Regex.Escape(prop) + "\"\\s*:\\s*(?<v>true|false)";
        var m = Regex.Match(obj, pat, RegexOptions.Singleline | RegexOptions.IgnoreCase);
        if (m.Success && bool.TryParse(m.Groups["v"].Value, out var v)) return v;
        return def;
    }
}