using System.Runtime.InteropServices;
using System.Security.Principal;

namespace WinSecAudit;

class Program
{
    // For console color/elevation checks
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        // Parse args
        bool htmlOnly    = args.Contains("--html-only");
        bool consoleOnly = args.Contains("--console-only");
        bool verbose     = args.Contains("--verbose") || args.Contains("-v");
        string? outPath  = null;

        for (int i = 0; i < args.Length; i++)
        {
            if ((args[i] == "--output" || args[i] == "-o") && i + 1 < args.Length)
                outPath = args[i + 1];
        }

        PrintBanner();

        // System info
        string hostName    = Environment.MachineName;
        string osVersion   = Environment.OSVersion.ToString();
        string currentUser = Environment.UserName;
        bool isElevated    = CheckElevation();
        DateTime timestamp = DateTime.UtcNow;

        WriteStatus($"Host:      {hostName}");
        WriteStatus($"OS:        {osVersion}");
        WriteStatus($"User:      {currentUser}");
        WriteStatus($"Elevated:  {(isElevated ? "Yes" : "No — some checks may be incomplete")}",
            isElevated ? ConsoleColor.Green : ConsoleColor.Yellow);
        WriteStatus($"Time:      {timestamp:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine();

        if (!isElevated)
        {
            WriteWarn("Running without elevation. Re-run as Administrator for complete results.");
            Console.WriteLine();
        }

        // Run all auditors
        var allFindings = new List<Finding>();

        RunAuditor("Password & Account Policy", PasswordPolicyAuditor.Audit, allFindings);
        RunAuditor("Privileged Group Membership", PrivilegedGroupAuditor.Audit, allFindings);
        RunAuditor("Network Exposure & Firewall", NetworkAuditor.Audit, allFindings);
        RunAuditor("Services & Persistence", ServicesAuditor.Audit, allFindings);
        RunAuditor("Patch Management & Defender", PatchAuditor.Audit, allFindings);

        // Build result
        var result = new AuditResult(
            hostName, osVersion, currentUser, isElevated, timestamp, allFindings
        );

        Console.WriteLine();
        PrintSummary(result);

        // Console findings detail
        if (!htmlOnly)
        {
            Console.WriteLine();
            PrintFindings(result, verbose);
        }

        // HTML report
        if (!consoleOnly)
        {
            string reportPath = outPath ?? $"WinSecAudit_{hostName}_{timestamp:yyyyMMdd_HHmmss}.html";

            try
            {
                string html = HtmlReportGenerator.Generate(result);
                await File.WriteAllTextAsync(reportPath, html);
                Console.WriteLine();
                WriteSuccess($"HTML report saved: {Path.GetFullPath(reportPath)}");
            }
            catch (Exception ex)
            {
                WriteError($"Failed to write HTML report: {ex.Message}");
            }
        }

        Console.WriteLine();

        // Exit code: 0 = pass/low, 1 = medium, 2 = high/critical
        return result.RiskTier switch
        {
            "CRITICAL" or "HIGH" => 2,
            "MEDIUM"             => 1,
            _                    => 0
        };
    }

    private static void RunAuditor(string name, Func<List<Finding>> auditor, List<Finding> allFindings)
    {
        Console.Write($"  [{Dim("...")}] {name,-40}");
        try
        {
            var findings = auditor();
            allFindings.AddRange(findings);

            int issues = findings.Count(f => f.Severity >= Severity.Low);
            if (issues == 0)
                WriteInline($"[{Green("PASS")}] {findings.Count} checks");
            else
                WriteInline($"[{Yellow("WARN")}] {issues} issue{(issues == 1 ? "" : "s")} found");
        }
        catch (Exception ex)
        {
            WriteInline($"[{Red("ERR ")}] {ex.Message}");
        }
    }

    private static void PrintBanner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine(@"  ██╗    ██╗██╗███╗   ██╗███████╗███████╗ ██████╗ ");
        Console.WriteLine(@"  ██║    ██║██║████╗  ██║██╔════╝██╔════╝██╔════╝ ");
        Console.WriteLine(@"  ██║ █╗ ██║██║██╔██╗ ██║███████╗█████╗  ██║      ");
        Console.WriteLine(@"  ██║███╗██║██║██║╚██╗██║╚════██║██╔══╝  ██║      ");
        Console.WriteLine(@"  ╚███╔███╔╝██║██║ ╚████║███████║███████╗╚██████╗ ");
        Console.WriteLine(@"   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝ ");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.WriteLine("  ╔══════════════════════════════════════════════════╗");
        Console.WriteLine("  ║    Windows Security Auditor  v1.0                ║");
        Console.WriteLine("  ║    Host-based security posture assessment         ║");
        Console.WriteLine("  ╚══════════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void PrintSummary(AuditResult result)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ────────────────────────────────────────────────────");
        Console.ResetColor();
        Console.Write("  RISK TIER: ");

        Console.ForegroundColor = result.RiskTier switch
        {
            "CRITICAL" => ConsoleColor.Red,
            "HIGH"     => ConsoleColor.DarkYellow,
            "MEDIUM"   => ConsoleColor.Yellow,
            _          => ConsoleColor.Green
        };
        Console.WriteLine($"  {result.RiskTier}  ");
        Console.ResetColor();

        Console.WriteLine();
        Console.Write($"  Critical: {Red(result.CriticalCount.ToString())}   ");
        Console.Write($"High: {Yellow(result.HighCount.ToString())}   ");
        Console.Write($"Medium: {Cyan(result.MediumCount.ToString())}   ");
        Console.Write($"Low: {Dim(result.LowCount.ToString())}   ");
        Console.WriteLine($"Pass: {Green(result.PassCount.ToString())}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  ────────────────────────────────────────────────────");
        Console.ResetColor();
    }

    private static void PrintFindings(AuditResult result, bool verbose)
    {
        // Only show issues (non-pass, non-info) unless verbose
        var toShow = result.Findings
            .Where(f => verbose || f.Severity >= Severity.Low)
            .OrderByDescending(f => (int)f.Severity)
            .ToList();

        if (toShow.Count == 0)
        {
            WriteSuccess("No issues detected.");
            return;
        }

        Console.WriteLine("  FINDINGS:");
        Console.WriteLine();

        string? lastCategory = null;
        foreach (var f in toShow)
        {
            if (f.Category != lastCategory)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"  ── {f.Category.ToUpper()} ──");
                Console.ResetColor();
                lastCategory = f.Category;
            }

            string sevLabel = f.Severity.ToString().ToUpper().PadRight(8);
            ConsoleColor sevColor = f.Severity switch
            {
                Severity.Critical => ConsoleColor.Red,
                Severity.High     => ConsoleColor.DarkYellow,
                Severity.Medium   => ConsoleColor.Yellow,
                Severity.Low      => ConsoleColor.Cyan,
                Severity.Pass     => ConsoleColor.Green,
                _                 => ConsoleColor.DarkGray
            };

            Console.Write("  ");
            Console.ForegroundColor = sevColor;
            Console.Write($"[{sevLabel.TrimEnd()}]");
            Console.ResetColor();
            Console.WriteLine($" {f.Control}");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine($"         {f.Description}");

            if (verbose && f.Severity >= Severity.Low)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"         → {f.Remediation.Replace("\n", "\n           ")}");
            }

            Console.ResetColor();
            Console.WriteLine();
        }

        if (!verbose && toShow.Any(f => f.Severity >= Severity.Low))
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Run with --verbose / -v to see remediation steps in console.");
            Console.ResetColor();
        }
    }

    private static bool CheckElevation()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    // Console helpers
    private static void WriteStatus(string msg, ConsoleColor color = ConsoleColor.DarkGray)
    {
        Console.ForegroundColor = color;
        Console.WriteLine($"  {msg}");
        Console.ResetColor();
    }

    private static void WriteInline(string msg)
    {
        Console.Write(msg);
        Console.WriteLine();
    }

    private static void WriteWarn(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"  ⚠  {msg}");
        Console.ResetColor();
    }

    private static void WriteError(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗  {msg}");
        Console.ResetColor();
    }

    private static void WriteSuccess(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ✓  {msg}");
        Console.ResetColor();
    }

    // ANSI-style inline color helpers
    private static string ColorWrap(string text, ConsoleColor _) => text; // passthrough for inline writes

    private static string Red(string s)    { Console.ForegroundColor = ConsoleColor.Red;      var r = s; Console.ResetColor(); return r; }
    private static string Yellow(string s) { Console.ForegroundColor = ConsoleColor.Yellow;   var r = s; Console.ResetColor(); return r; }
    private static string Green(string s)  { Console.ForegroundColor = ConsoleColor.Green;    var r = s; Console.ResetColor(); return r; }
    private static string Cyan(string s)   { Console.ForegroundColor = ConsoleColor.Cyan;     var r = s; Console.ResetColor(); return r; }
    private static string Dim(string s)    { Console.ForegroundColor = ConsoleColor.DarkGray; var r = s; Console.ResetColor(); return r; }
}
