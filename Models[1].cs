namespace WinSecAudit;

public enum Severity { Pass, Info, Low, Medium, High, Critical }

public record Finding(
    string Category,
    string Control,
    string Description,
    Severity Severity,
    string Detail,
    string Remediation
);

public record AuditResult(
    string HostName,
    string OSVersion,
    string CurrentUser,
    bool IsElevated,
    DateTime Timestamp,
    List<Finding> Findings
)
{
    public int CriticalCount => Findings.Count(f => f.Severity == Severity.Critical);
    public int HighCount     => Findings.Count(f => f.Severity == Severity.High);
    public int MediumCount   => Findings.Count(f => f.Severity == Severity.Medium);
    public int LowCount      => Findings.Count(f => f.Severity == Severity.Low);
    public int PassCount     => Findings.Count(f => f.Severity == Severity.Pass);

    public string RiskTier => (CriticalCount, HighCount) switch
    {
        ( > 0, _) => "CRITICAL",
        (_, > 2)  => "HIGH",
        (_, > 0)  => "MEDIUM",
        _         => "LOW"
    };
}
