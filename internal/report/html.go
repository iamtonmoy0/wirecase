// Package report renders self-contained reports that work offline.
package report

import (
	"fmt"
	"html/template"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/iamtonmoy0/wirecase/internal/casefile"
	"github.com/iamtonmoy0/wirecase/internal/diagnosis"
)

type page struct {
	Case     casefile.Case
	Findings []diagnosis.Finding
	Rows     []row
}

type row struct {
	Name, Status, Error, Duration, Details string
	Width                                  int
}

var htmlTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WIRECASE report — {{.Case.Host}}</title><style>
:root{color-scheme:dark;--bg:#0c1117;--panel:#151c25;--line:#263341;--text:#e8eef5;--muted:#9eacbb;--cyan:#53d6c3;--red:#ff7e79;--amber:#ffcc66}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,sans-serif}main{max-width:980px;margin:auto;padding:36px 20px 64px}h1,h2,h3{line-height:1.2}h1{font-size:2rem;margin:0}h2{font-size:1.25rem;margin:30px 0 12px}.meta,.hint{color:var(--muted)}.meta{margin-top:8px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin-top:24px}.card,.finding,.probe{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}.finding{margin:10px 0}.finding h3{margin:4px 0 6px;font-size:1.03rem}.badge{font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:var(--cyan)}.high{color:var(--red)}.medium,.low{color:var(--amber)}.probe{margin:10px 0}.probe summary{cursor:pointer;font-weight:650}.probe p{overflow-wrap:anywhere}.bar{height:7px;background:#27333e;border-radius:8px;margin:12px 0 4px;overflow:hidden}.bar span{display:block;height:100%;background:var(--cyan)}code{color:#c3d6e7}footer{margin-top:32px;color:var(--muted);font-size:.85rem}
</style></head><body><main><header><div class="badge">WIRECASE · OFFLINE DIAGNOSTIC</div><h1>{{.Case.Host}}</h1><div class="meta">{{.Case.Target}} · Captured {{.Case.CapturedAt.UTC.Format "2006-01-02 15:04:05 UTC"}} · Case {{.Case.ID}}</div></header>
<section><h2>Likely explanations</h2>{{range .Findings}}<article class="finding"><span class="badge {{.Severity}}">{{.Severity}} · {{.Layer}}</span><h3>{{.Title}}</h3><p>{{.Explanation}}</p></article>{{end}}</section>
<section><h2>Probe timeline</h2><div class="grid">{{range .Rows}}<article class="card"><strong>{{.Name}}</strong><div class="meta">{{.Status}} · {{.Duration}}</div><div class="bar" role="img" aria-label="relative duration"><span style="width:{{.Width}}%"></span></div></article>{{end}}</div></section>
<section><h2>Evidence</h2>{{range .Rows}}<details class="probe"><summary>{{.Name}} · {{.Status}} · {{.Duration}}</summary>{{if .Error}}<p><strong>Error:</strong> <code>{{.Error}}</code></p>{{end}}{{if .Details}}<p><strong>Details:</strong> <code>{{.Details}}</code></p>{{end}}</details>{{end}}</section>
<footer>Generated locally by WIRECASE. Explanations are rule-based hints, not proof of root cause.</footer></main></body></html>`))

func WriteHTML(w io.Writer, c casefile.Case) error {
	maxDuration := int64(1)
	for _, result := range c.Results {
		if result.DurationMS > maxDuration {
			maxDuration = result.DurationMS
		}
	}
	data := page{Case: c, Findings: diagnosis.Analyze(c)}
	for _, result := range c.Results {
		width := int(math.Round(float64(result.DurationMS) * 100 / float64(maxDuration)))
		if width < 3 {
			width = 3
		}
		details := ""
		if len(result.Details) > 0 {
			keys := make([]string, 0, len(result.Details))
			for key := range result.Details {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			pieces := make([]string, 0, len(result.Details))
			for _, key := range keys {
				value := result.Details[key]
				pieces = append(pieces, fmt.Sprintf("%s=%v", key, value))
			}
			details = strings.Join(pieces, ", ")
		}
		data.Rows = append(data.Rows, row{strings.ToUpper(result.Name), result.Status, result.Error, fmt.Sprintf("%d ms", result.DurationMS), details, width})
	}
	return htmlTemplate.Execute(w, data)
}
