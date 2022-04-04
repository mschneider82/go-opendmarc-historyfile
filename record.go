package goopendmarchistoryfile

import (
	"fmt"
	"io"
	"strings"
	"time"
)

type Record struct {
	Received  time.Time // %ld
	JobID     string
	Reporter  string // hostname
	IPAddr    string // ipv4 or v6
	From      string // MIME Header FROM Domain
	EnvFrom   string // MAIL FROM DOMAIN
	PDomain   string // policy domain (the "organizational" domain, the one asserting policy)
	ARCPolicy string // arc_policy %d(=ARCPolicyValue) json:[instance{"i":%d,"d":"%s","s":"%s","ip":"%s"},... instance{}...]
	RUA       string // empty value: "-""
	Policy    DMARCPolicy
	PCT       int                     // from DNS value 0 to 100 (not in dns=100)
	ADKIM     ALIGNMENTRULE           // published policy's alignment rule for DKIM and SPF (114 = relaxed, 115 = strict)
	ASPF      ALIGNMENTRULE           // published policy's alignment rule for DKIM and SPF (114 = relaxed, 115 = strict)
	P         DMARC_DNS_RECORD_Policy // Policy from DNS Record (required in dns)
	SP        DMARC_DNS_RECORD_Policy // SubDomainPolicy from DNS Record (optional in dns)
	AlignDKIM bool                    // whether identifier alignment was established (4 = yes, 5 = no)
	AlignSPF  bool                    // whether identifier alignment was established (4 = yes, 5 = no)
	ARC       bool                    // ARC evaluation (0 = pass, 7 = fail) = https://github.com/trusteddomainproject/OpenDMARC/issues/214
	SPF       SPF                     // (0 = pass, 2 = fail, 6 = none, -1 = not evaluated)
	Action    DMARCResult
}

func (r Record) String() string {
	s := strings.Builder{}
	s.WriteString("job " + r.JobID + "\n")
	s.WriteString("reporter " + r.Reporter + "\n")
	fmt.Fprintf(&s, "received %d\n", r.Received.Unix())
	s.WriteString("ipaddr " + r.IPAddr + "\n")
	s.WriteString("from " + strings.ToLower(r.From) + "\n")
	s.WriteString("mfrom " + strings.ToLower(r.EnvFrom) + "\n")
	fmt.Fprintf(&s, "spf %d\n", r.SPF)
	s.WriteString("pdomain " + r.PDomain + "\n")
	fmt.Fprintf(&s, "policy %d\n", r.Policy)
	if r.RUA == "" {
		s.WriteString("rua -\n")
	} else {
		fmt.Fprintf(&s, "rua %s\n", r.RUA)
	}
	fmt.Fprintf(&s, "pct %d\n", r.PCT)
	fmt.Fprintf(&s, "adkim %d\n", r.ADKIM)
	fmt.Fprintf(&s, "aspf %d\n", r.ASPF)
	fmt.Fprintf(&s, "p %d\n", r.P)
	fmt.Fprintf(&s, "sp %d\n", r.SP)
	aligndkim := 5 // no
	alignspf := 5  // no
	if r.AlignDKIM {
		aligndkim = 4
	}
	if r.AlignSPF {
		alignspf = 4
	}
	fmt.Fprintf(&s, "align_dkim %d\n", aligndkim)
	fmt.Fprintf(&s, "align_spf %d\n", alignspf)
	arc := 7
	if r.ARC {
		arc = 0
	}
	fmt.Fprintf(&s, "arc %d\n", arc)
	arcpolicy := r.ARCPolicy
	if arcpolicy == "" {
		if r.ARC {
			arcpolicy = "0 json:[]"
		} else {
			arcpolicy = "2 json:[]"
		}
	}
	fmt.Fprintf(&s, "arc_policy %s\n", arcpolicy)
	fmt.Fprintf(&s, "action %d\n", r.Action)
	return s.String()
}

func (r *Record) WriteTo(w io.Writer) (n int64, err error) {
	nn, err := w.Write([]byte(r.String()))
	return int64(nn), err
}
