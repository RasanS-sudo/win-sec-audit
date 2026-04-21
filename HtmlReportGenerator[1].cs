using System.Text;

namespace WinSecAudit;

public static class HtmlReportGenerator
{
    public static string Generate(AuditResult result)
    {
        var sb = new StringBuilder();

        // Group findings by category
        var categories = result.Findings
            .GroupBy(f => f.Category)
            .OrderBy(g => g.Key)
            .ToList();

        string riskColor = result.RiskTier switch
        {
            "CRITICAL" => "#ff2d55",
            "HIGH"     => "#ff6b35",
            "MEDIUM"   => "#ffd60a",
            _          => "#30d158"
        };

        sb.AppendLine($"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WinSecAudit Report — {result.HostName} — {result.Timestamp:yyyy-MM-dd}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

    :root {{
      --bg:          #0a0a0f;
      --bg-card:     #0f0f1a;
      --bg-row:      #12121f;
      --border:      #1e1e35;
      --border-glow: #2a2a50;
      --text:        #c8c8e0;
      --text-muted:  #5a5a7a;
      --text-dim:    #3a3a5a;
      --accent:      #4c9fff;
      --pass:        #30d158;
      --info:        #64d2ff;
      --low:         #a8c7fa;
      --medium:      #ffd60a;
      --high:        #ff6b35;
      --critical:    #ff2d55;
      --mono:        'IBM Plex Mono', monospace;
      --sans:        'IBM Plex Sans', sans-serif;
    }}

    * {{ margin: 0; padding: 0; box-sizing: border-box; }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
    }}

    /* Scanline overlay */
    body::before {{
      content: '';
      position: fixed;
      inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,0,0,0.03) 2px,
        rgba(0,0,0,0.03) 4px
      );
      pointer-events: none;
      z-index: 999;
    }}

    .container {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 40px 24px 80px;
    }}

    /* Header */
    .header {{
      border-bottom: 1px solid var(--border);
      padding-bottom: 32px;
      margin-bottom: 40px;
    }}

    .header-top {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 24px;
      margin-bottom: 20px;
    }}

    .tool-name {{
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 500;
      color: var(--accent);
      letter-spacing: 0.15em;
      text-transform: uppercase;
      margin-bottom: 8px;
    }}

    .report-title {{
      font-family: var(--mono);
      font-size: 28px;
      font-weight: 600;
      color: #e8e8ff;
      letter-spacing: -0.02em;
    }}

    .risk-badge {{
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.1em;
      color: {riskColor};
      border: 1px solid {riskColor};
      padding: 8px 20px;
      flex-shrink: 0;
      position: relative;
    }}

    .risk-badge::before {{
      content: 'RISK TIER';
      display: block;
      font-size: 9px;
      letter-spacing: 0.2em;
      color: var(--text-muted);
      margin-bottom: 2px;
    }}

    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1px;
      background: var(--border);
      border: 1px solid var(--border);
    }}

    .meta-item {{
      background: var(--bg-card);
      padding: 12px 16px;
    }}

    .meta-label {{
      font-family: var(--mono);
      font-size: 9px;
      font-weight: 500;
      letter-spacing: 0.15em;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 4px;
    }}

    .meta-value {{
      font-family: var(--mono);
      font-size: 13px;
      color: var(--text);
    }}

    /* Score summary */
    .score-grid {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 1px;
      background: var(--border);
      border: 1px solid var(--border);
      margin-bottom: 40px;
    }}

    .score-cell {{
      background: var(--bg-card);
      padding: 20px 16px;
      text-align: center;
    }}

    .score-num {{
      font-family: var(--mono);
      font-size: 32px;
      font-weight: 600;
      line-height: 1;
      margin-bottom: 6px;
    }}

    .score-label {{
      font-family: var(--mono);
      font-size: 9px;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: var(--text-muted);
    }}

    .c-critical {{ color: var(--critical); }}
    .c-high     {{ color: var(--high); }}
    .c-medium   {{ color: var(--medium); }}
    .c-low      {{ color: var(--low); }}
    .c-pass     {{ color: var(--pass); }}
    .c-info     {{ color: var(--info); }}

    /* Elevation warning */
    .elevation-warning {{
      border: 1px solid var(--high);
      background: rgba(255,107,53,0.05);
      padding: 14px 18px;
      margin-bottom: 32px;
      font-family: var(--mono);
      font-size: 12px;
      color: var(--high);
    }}

    .elevation-warning strong {{ font-weight: 600; }}

    /* Category sections */
    .category {{
      margin-bottom: 36px;
    }}

    .category-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border);
    }}

    .category-name {{
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: #9090c0;
    }}

    .category-count {{
      font-family: var(--mono);
      font-size: 10px;
      color: var(--text-dim);
    }}

    /* Finding rows */
    .finding {{
      border: 1px solid var(--border);
      margin-bottom: 4px;
      transition: border-color 0.15s;
    }}

    .finding:hover {{
      border-color: var(--border-glow);
    }}

    .finding-header {{
      display: grid;
      grid-template-columns: 90px 1fr auto;
      align-items: center;
      gap: 16px;
      padding: 12px 16px;
      cursor: pointer;
      background: var(--bg-card);
    }}

    .finding-header:hover {{
      background: var(--bg-row);
    }}

    .sev-tag {{
      font-family: var(--mono);
      font-size: 9px;
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      padding: 3px 8px;
      text-align: center;
      border: 1px solid currentColor;
    }}

    .sev-CRITICAL {{ color: var(--critical); border-color: var(--critical); background: rgba(255,45,85,0.08); }}
    .sev-HIGH     {{ color: var(--high);     border-color: var(--high);     background: rgba(255,107,53,0.08); }}
    .sev-MEDIUM   {{ color: var(--medium);   border-color: var(--medium);   background: rgba(255,214,10,0.06); }}
    .sev-LOW      {{ color: var(--low);      border-color: var(--low);      background: rgba(168,199,250,0.06); }}
    .sev-PASS     {{ color: var(--pass);     border-color: var(--pass);     background: rgba(48,209,88,0.06); }}
    .sev-INFO     {{ color: var(--info);     border-color: var(--info);     background: rgba(100,210,255,0.06); }}

    .finding-title {{
      font-size: 13px;
      color: var(--text);
    }}

    .finding-control {{
      font-family: var(--mono);
      font-size: 10px;
      color: var(--text-muted);
      margin-top: 2px;
    }}

    .expand-icon {{
      font-family: var(--mono);
      font-size: 12px;
      color: var(--text-dim);
      transition: transform 0.2s;
      user-select: none;
    }}

    .finding-body {{
      display: none;
      padding: 16px;
      border-top: 1px solid var(--border);
      background: var(--bg);
    }}

    .finding-body.open {{
      display: block;
    }}

    .expand-icon.open {{
      transform: rotate(90deg);
    }}

    .detail-section {{
      margin-bottom: 14px;
    }}

    .detail-label {{
      font-family: var(--mono);
      font-size: 9px;
      font-weight: 600;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 4px;
    }}

    .detail-value {{
      font-family: var(--mono);
      font-size: 12px;
      color: var(--text);
      white-space: pre-wrap;
      word-break: break-word;
    }}

    .remediation-box {{
      border-left: 2px solid var(--accent);
      padding: 12px 14px;
      background: rgba(76,159,255,0.04);
    }}

    .remediation-box .detail-label {{
      color: var(--accent);
    }}

    .remediation-box .detail-value {{
      color: #a0c0ff;
      font-size: 12px;
    }}

    /* Footer */
    .footer {{
      margin-top: 60px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 10px;
      color: var(--text-dim);
      display: flex;
      justify-content: space-between;
    }}

    /* No findings pass-through */
    .all-pass {{
      font-family: var(--mono);
      font-size: 12px;
      color: var(--pass);
      padding: 12px 16px;
      border: 1px solid rgba(48,209,88,0.2);
      background: rgba(48,209,88,0.04);
    }}

    @media print {{
      .finding-body {{ display: block !important; }}
      body::before {{ display: none; }}
    }}
  </style>
</head>
<body>
<div class="container">

  <div class="header">
    <div class="header-top">
      <div>
        <div class="tool-name">WinSecAudit v1.0 // Security Posture Assessment</div>
        <div class="report-title">{result.HostName}</div>
      </div>
      <div class="risk-badge">{result.RiskTier}</div>
    </div>
    <div class="meta-grid">
      <div class="meta-item">
        <div class="meta-label">Generated</div>
        <div class="meta-value">{result.Timestamp:yyyy-MM-dd HH:mm} UTC</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Host</div>
        <div class="meta-value">{result.HostName}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">OS</div>
        <div class="meta-value">{result.OSVersion}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Run As</div>
        <div class="meta-value">{result.CurrentUser}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Elevation</div>
        <div class="meta-value" style="color: {(result.IsElevated ? "var(--pass)" : "var(--high))"}">{(result.IsElevated ? "Elevated (Admin)" : "Standard User")}</div>
      </div>
    </div>
  </div>

""");

        if (!result.IsElevated)
        {
            sb.AppendLine("""
  <div class="elevation-warning">
    <strong>⚠ NOT ELEVATED:</strong> Some checks require Administrator privileges. Re-run as Administrator for complete results.
    Password policy, group membership, and some network checks may be incomplete.
  </div>
""");
        }

        // Score summary
        sb.AppendLine($"""
  <div class="score-grid">
    <div class="score-cell">
      <div class="score-num c-critical">{result.CriticalCount}</div>
      <div class="score-label">Critical</div>
    </div>
    <div class="score-cell">
      <div class="score-num c-high">{result.HighCount}</div>
      <div class="score-label">High</div>
    </div>
    <div class="score-cell">
      <div class="score-num c-medium">{result.MediumCount}</div>
      <div class="score-label">Medium</div>
    </div>
    <div class="score-cell">
      <div class="score-num c-low">{result.LowCount}</div>
      <div class="score-label">Low</div>
    </div>
    <div class="score-cell">
      <div class="score-num c-pass">{result.PassCount}</div>
      <div class="score-label">Pass</div>
    </div>
  </div>

""");

        // Findings by category
        foreach (var group in categories)
        {
            var orderedFindings = group
                .OrderBy(f => f.Severity == Severity.Pass ? 99 : (int)f.Severity * -1)
                .ToList();

            sb.AppendLine($"""
  <div class="category">
    <div class="category-header">
      <span class="category-name">{group.Key}</span>
      <span class="category-count">({group.Count()} finding{(group.Count() == 1 ? "" : "s")})</span>
    </div>
""");

            foreach (var finding in orderedFindings)
            {
                string sevClass = finding.Severity.ToString().ToUpper();
                string findingId = $"f{Guid.NewGuid().ToString("N")[..8]}";
                string escapedDetail      = HtmlEncode(finding.Detail);
                string escapedDescription = HtmlEncode(finding.Description);
                string escapedRemediation = HtmlEncode(finding.Remediation);
                string escapedControl     = HtmlEncode(finding.Control);

                sb.AppendLine($"""
    <div class="finding">
      <div class="finding-header" onclick="toggle('{findingId}')">
        <span class="sev-tag sev-{sevClass}">{finding.Severity}</span>
        <div>
          <div class="finding-title">{escapedDescription}</div>
          <div class="finding-control">{escapedControl}</div>
        </div>
        <span class="expand-icon" id="icon-{findingId}">▶</span>
      </div>
      <div class="finding-body" id="body-{findingId}">
        <div class="detail-section">
          <div class="detail-label">Technical Detail</div>
          <div class="detail-value">{escapedDetail}</div>
        </div>
        <div class="remediation-box">
          <div class="detail-label">Remediation</div>
          <div class="detail-value">{escapedRemediation}</div>
        </div>
      </div>
    </div>
""");
            }

            sb.AppendLine("  </div>"); // end category
        }

        sb.AppendLine($"""
  <div class="footer">
    <span>WinSecAudit v1.0 — github.com/YOUR_USERNAME/win-sec-audit</span>
    <span>Report generated {result.Timestamp:yyyy-MM-dd HH:mm:ss} UTC</span>
  </div>

</div>
<script>
function toggle(id) {{
  const body = document.getElementById('body-' + id);
  const icon = document.getElementById('icon-' + id);
  body.classList.toggle('open');
  icon.classList.toggle('open');
}}
</script>
</body>
</html>
""");

        return sb.ToString();
    }

    private static string HtmlEncode(string text) =>
        System.Net.WebUtility.HtmlEncode(text)
            .Replace("\n", "<br>")
            .Replace("  ", "&nbsp;&nbsp;");
}
