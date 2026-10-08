// Command s1-sidecar evaluates HTTP requests against the OWASP Core Rule Set
// using OWASP Coraza, and returns a GRADED anomaly signal over a Unix domain
// socket.
//
// # Why a sidecar
//
// Coraza is a Go library and is the mature, CRS-compatible rule engine. The
// CSF gateway is Python (ADR-0006), and the Python binding for libmodsecurity
// does not build on our platform (measured — see ADR-0007). A small Go
// sidecar keeps the mature engine while costing one IPC hop, which this
// phase measures rather than assumes.
//
// # Why it returns a score, not a verdict
//
// ADR-0004: S1 is a cheap prefilter and a graded signal, not a detector we
// rely on. It emits the anomaly score, the matched rule IDs and their
// severities; the gateway's policy engine decides. Returning "blocked: true"
// here would throw away the information the cascade depends on.
//
// # Transport
//
// Unix domain socket by default: no TCP stack, no network exposure, and
// filesystem permissions are the access control. The socket must not be
// world-writable, since anything that can reach it can ask the engine
// questions about arbitrary payloads.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

var version = "dev"

// EvalRequest is what the gateway sends. It mirrors the fields CSF's S0 stage
// has already parsed, so the sidecar never re-parses raw HTTP — that would
// create a second interpretation to disagree with (threat model T3).
type EvalRequest struct {
	ID         string              `json:"id"`
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	Query      string              `json:"query"`
	Proto      string              `json:"proto"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
	ClientIP   string              `json:"client_ip"`
	ClientPort int                 `json:"client_port"`
	ServerIP   string              `json:"server_ip"`
	ServerPort int                 `json:"server_port"`
}

// MatchedRule is one CRS rule that fired.
type MatchedRule struct {
	ID       int      `json:"id"`
	Severity string   `json:"severity"`
	Message  string   `json:"message"`
	Data     string   `json:"data"`
	Tags     []string `json:"tags,omitempty"`
}

// EvalResponse is the graded signal.
//
// Two scores are reported, and conflating them is a real mistake we made
// before measuring. CRS evaluates blocking at tx.blocking_paranoia_level and
// reports that total in rule 949110, but detection-only rules at higher
// paranoia levels keep accumulating afterwards. On one probe the blocking
// score was 5 while the full detection score was 42.
//
//   - BlockingScore  : what classic CRS would have used to block.
//   - DetectionScore : the full signal across all evaluated paranoia levels.
//
// CSF thresholds against DetectionScore (richer signal, ADR-0004) and reports
// BlockingScore for comparison against a classic deployment.
type EvalResponse struct {
	ID string `json:"id"`
	// AnomalyScore is DetectionScore. Kept as the primary field name because
	// it is what the gateway thresholds against; it is NOT a verdict.
	AnomalyScore int `json:"anomaly_score"`
	// AttackScore is the anomaly score with CRS PROTOCOL-ENFORCEMENT and
	// PROTOCOL-ATTACK rules removed. In CSF, HTTP-protocol correctness is S0's
	// job (framing.go / Phase 11), so S1's protocol rules double-count a
	// concern another stage owns -- and they are the dominant cross-corpus
	// false-positive source (a serialized test corpus trips them on benign
	// traffic). AttackScore is S1's application-layer attack signal alone,
	// which is what transfers across applications. See ADR-0015.
	AttackScore   int            `json:"attack_score"`
	BlockingScore int            `json:"blocking_score"`
	ScoreByPL     map[string]int `json:"score_by_pl"`
	// TotalRulesFired counts every rule including CRS bookkeeping actions.
	// MatchedRules below contains only ACTIONABLE rules (those carrying an
	// attack-* tag); on one probe that was 8 of 74.
	TotalRulesFired int `json:"total_rules_fired"`
	// Interrupted reports whether CRS itself would have blocked at the
	// configured paranoia/threshold. Reported for comparison with the
	// classic deployment, not used as the decision.
	Interrupted  bool          `json:"interrupted"`
	MatchedRules []MatchedRule `json:"matched_rules"`
	// Categories are the attack classes implied by the matched rule tags,
	// e.g. "sqli", "xss", "rce". Used for the audit log and for comparing
	// S1's opinion against S2/S3.
	Categories  []string `json:"categories"`
	ElapsedUs   int64    `json:"elapsed_us"`
	EngineError string   `json:"engine_error,omitempty"`
}

type server struct {
	waf      coraza.WAF
	requests atomic.Uint64
	errors   atomic.Uint64
	totalUs  atomic.Int64
}

// tagCategory maps CRS rule tags onto the attack classes CSF reports.
// CRS tags are the authoritative source for what a rule is about.
var tagCategory = map[string]string{
	"attack-sqli":              "sqli",
	"attack-xss":               "xss",
	"attack-rce":               "rce",
	"attack-lfi":               "lfi",
	"attack-rfi":               "rfi",
	"attack-injection-php":     "php",
	"attack-injection-generic": "injection",
	"attack-protocol":          "protocol",
	"attack-fixation":          "session_fixation",
	"attack-disclosure":        "disclosure",
	"attack-generic":           "generic",
}

func severityName(s types.RuleSeverity) string { return s.String() }

// severityWeight is the CRS anomaly contribution for a rule severity:
// CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2 (the standard CRS scoring). Used to
// re-derive the attack-only score, which CRS's own per-PL variables cannot
// give because they are not broken down by category.
func severityWeight(name string) int {
	switch name {
	case "emergency", "alert", "critical":
		return 5
	case "error":
		return 4
	case "warning":
		return 3
	case "notice":
		return 2
	default:
		return 0
	}
}

// isProtocolRule reports whether a rule belongs to CRS's HTTP-protocol
// categories (enforcement or protocol-level attacks such as smuggling), which
// CSF's S0 framing layer owns.
func isProtocolRule(tags []string) bool {
	for _, t := range tags {
		if strings.Contains(t, "PROTOCOL-ENFORCEMENT") ||
			strings.Contains(t, "PROTOCOL-ATTACK") {
			return true
		}
	}
	return false
}

func (s *server) evaluate(req *EvalRequest) *EvalResponse {
	start := time.Now()
	resp := &EvalResponse{ID: req.ID}

	tx := s.waf.NewTransaction()
	defer func() {
		// ProcessLogging finalises the transaction and runs the logging
		// phase, which is where CRS computes the final anomaly score.
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			log.Printf("transaction close: %v", err)
		}
	}()

	clientIP := req.ClientIP
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}
	serverIP := req.ServerIP
	if serverIP == "" {
		serverIP = "127.0.0.1"
	}
	tx.ProcessConnection(clientIP, req.ClientPort, serverIP, req.ServerPort)

	uri := req.Path
	if req.Query != "" {
		uri += "?" + req.Query
	}
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	tx.ProcessURI(uri, req.Method, proto)

	hasContentLength := false
	for name, values := range req.Headers {
		if strings.EqualFold(name, "content-length") {
			hasContentLength = true
		}
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}
	// Supply Content-Length when the caller did not.
	//
	// This is not cosmetic. Without it Coraza cannot frame the body, falls
	// back to URLENCODED parsing, and the ENTIRE JSON document becomes a
	// single argument name. Measured before the fix: the benign body
	// {"comment":"Great product! 5/5 would buy again."} matched rule 942340
	// (SQL authentication bypass) on ARGS_NAMES, scoring 8. It also trips
	// rule 920180 (POST without Content-Length).
	//
	// The gateway has already read and bounded the body, so its length is
	// known exactly and supplying it introduces no ambiguity.
	if !hasContentLength && req.Body != "" {
		tx.AddRequestHeader("Content-Length", strconv.Itoa(len(req.Body)))
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		resp.Interrupted = true
	}

	if req.Body != "" {
		if _, _, err := tx.WriteRequestBody([]byte(req.Body)); err != nil {
			resp.EngineError = fmt.Sprintf("write body: %v", err)
		}
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		resp.EngineError = fmt.Sprintf("process body: %v", err)
	}
	if it != nil {
		resp.Interrupted = true
	}

	// Collect matched rules. Most of what CRS reports is bookkeeping
	// (SecAction entries with no severity and no attack tag); including them
	// would make the audit log unreadable and the categories meaningless.
	// We keep only ACTIONABLE rules: those carrying an attack-* tag.
	seen := map[string]bool{}
	all := tx.MatchedRules()
	resp.TotalRulesFired = len(all)
	for _, mr := range all {
		rule := mr.Rule()
		var tags []string
		actionable := false
		for _, tag := range rule.Tags() {
			tags = append(tags, tag)
			if strings.HasPrefix(tag, "attack-") {
				actionable = true
			}
			if cat, ok := tagCategory[tag]; ok && !seen[cat] {
				seen[cat] = true
				resp.Categories = append(resp.Categories, cat)
			}
		}
		if !actionable {
			continue
		}
		sev := severityName(rule.Severity())
		if !isProtocolRule(tags) {
			resp.AttackScore += severityWeight(sev)
		}
		resp.MatchedRules = append(resp.MatchedRules, MatchedRule{
			ID:       rule.ID(),
			Severity: sev,
			Message:  mr.Message(),
			Data:     mr.Data(),
			Tags:     tags,
		})
	}

	resp.AnomalyScore, resp.BlockingScore, resp.ScoreByPL = scores(tx)
	resp.ElapsedUs = time.Since(start).Microseconds()
	s.totalUs.Add(resp.ElapsedUs)
	return resp
}

// scores reads CRS's anomaly accounting from the transaction variables.
//
// Reading CRS's own variables is more faithful than re-deriving a score from
// rule severities, because CRS applies per-paranoia-level accounting that a
// naive sum would get wrong.
//
// Returns (detection, blocking, perPL).
func scores(tx types.Transaction) (int, int, map[string]int) {
	// Coraza exposes the transaction variable collections through an
	// interface the concrete transaction satisfies. We assert for it rather
	// than importing internal packages.
	txv, ok := tx.(interface {
		Variables() plugintypes.TransactionVariables
	})
	if !ok {
		return 0, 0, nil
	}
	col := txv.Variables().TX()
	read := func(key string) int {
		if v := col.Get(key); len(v) > 0 {
			if n, err := strconv.Atoi(v[0]); err == nil {
				return n
			}
		}
		return 0
	}

	perPL := map[string]int{}
	detection := 0
	for _, pl := range []string{"1", "2", "3", "4"} {
		n := read("inbound_anomaly_score_pl" + pl)
		perPL["pl"+pl] = n
		detection += n
	}
	// The aggregate CRS itself maintains. When both are available the
	// aggregate wins, since it reflects CRS's own accounting.
	if agg := read("inbound_anomaly_score"); agg > detection {
		detection = agg
	}

	// Blocking score: only the paranoia levels at or below the blocking PL
	// contribute to what classic CRS would have blocked on.
	blockingPL := read("blocking_paranoia_level")
	if blockingPL == 0 {
		blockingPL = 1
	}
	blocking := 0
	for pl := 1; pl <= blockingPL && pl <= 4; pl++ {
		blocking += perPL["pl"+strconv.Itoa(pl)]
	}
	return detection, blocking, perPL
}

func (s *server) handleEval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req EvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errors.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.requests.Add(1)
	resp := s.evaluate(&req)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *server) handleStats(w http.ResponseWriter, _ *http.Request) {
	n := s.requests.Load()
	var avg int64
	if n > 0 {
		avg = s.totalUs.Load() / int64(n)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version":     version,
		"requests":    n,
		"errors":      s.errors.Load(),
		"avg_eval_us": avg,
	})
}

func buildWAF(crsPath, exclusions string, blockingPL, detectionPL, threshold int) (coraza.WAF, error) {
	setup := strings.Join([]string{
		"SecRuleEngine DetectionOnly",
		"SecRequestBodyAccess On",
		"SecRequestBodyLimit 1048576",
		"SecRequestBodyNoFilesLimit 131072",
		"SecRequestBodyLimitAction Reject",
		"SecResponseBodyAccess Off",
		"SecDebugLogLevel 0",
		// CRS v4 separates what BLOCKS from what is merely DETECTED. We run
		// detection above blocking so high-paranoia rules enrich the score
		// without unilaterally blocking (ADR-0004).
		fmt.Sprintf(
			`SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d"`,
			blockingPL),
		fmt.Sprintf(
			`SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.detection_paranoia_level=%d"`,
			detectionPL),
		fmt.Sprintf(
			`SecAction "id:900002,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=%d"`,
			threshold),
		`SecAction "id:900003,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=4"`,

		// Activate the JSON and XML body processors by Content-Type.
		//
		// This is NOT part of CRS: it lives in ModSecurity's recommended
		// configuration, and omitting it is a serious misconfiguration we
		// made and measured. Without it the engine treats a JSON body as
		// opaque text, so braces, quotes and colons look like SQL syntax.
		// Measured impact: EVERY benign JSON body scored above zero, with
		// {"comment":"Great product! 5/5 would buy again."} scoring 8 and
		// tagged attack-sqli. With the processor enabled, CRS inspects the
		// parsed values instead of the serialised document.
		// The vendor prefix must be OPTIONAL. An earlier version used
		// ^application/[a-z0-9.+-]+[+]?json, which requires at least one
		// character before "json" and therefore never matched plain
		// application/json — the body processor silently stayed URLENCODED.
		`SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(?:[a-z0-9.-]+[+])?json" ` +
			`"id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"`,
		`SecRule REQUEST_HEADERS:Content-Type "@rx ^(?:application(?:/soap\+|/)|text/)xml" ` +
			`"id:200002,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"`,
		`SecRule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" ` +
			`"id:200003,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=MULTIPART"`,
	}, "\n")

	// Root the rule filesystem at the CRS directory and use RELATIVE
	// includes. Two reasons, both learned the hard way:
	//   - io/fs rejects absolute paths, so Include /abs/path fails with
	//     "invalid argument" under any DirFS.
	//   - the include path is parsed as a SecLang directive argument, so a
	//     path containing spaces (common on macOS) would break it.
	cfg := coraza.NewWAFConfig().
		WithRootFS(os.DirFS(crsPath)).
		WithDirectives(setup).
		WithDirectives("Include crs-setup.conf.example").
		WithDirectives("Include rules/*.conf")

	// Per-application rule exclusions, loaded AFTER the rule set so they can
	// remove rules by ID.
	//
	// Tuning is not cheating: it is what every real CRS deployment does, and
	// CRS ships REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example precisely
	// for it. What matters is that exclusions are (a) explicit and reviewable,
	// (b) derived from the TRAINING/VALIDATION data only, never the frozen
	// holdout, and (c) reported alongside any number they affect.
	if exclusions != "" {
		data, err := os.ReadFile(exclusions)
		if err != nil {
			return nil, fmt.Errorf("read exclusions %s: %w", exclusions, err)
		}
		cfg = cfg.WithDirectives(string(data))
	}

	return coraza.NewWAF(cfg)
}

func main() {
	socket := flag.String("socket", "/tmp/csf-s1.sock", "unix socket path")
	tcpAddr := flag.String("tcp", "", "listen on TCP instead (testing only)")
	crsPath := flag.String("crs", "../vendor/crs", "path to coreruleset checkout")
	blockingPL := flag.Int("blocking-pl", 1, "CRS blocking paranoia level (1-4)")
	detectionPL := flag.Int("detection-pl", 2, "CRS detection paranoia level (1-4)")
	threshold := flag.Int("threshold", 5, "CRS inbound anomaly score threshold")
	exclusions := flag.String("exclusions", "", "path to a SecLang rule-exclusion file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("s1-sidecar", version)
		return
	}

	abs, err := filepath.Abs(*crsPath)
	if err != nil {
		log.Fatalf("fatal: resolve crs path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(abs, "rules")); err != nil {
		log.Fatalf("fatal: CRS rules not found at %s: %v", abs, err)
	}

	exclusionsPath := ""
	if *exclusions != "" {
		exclusionsPath, err = filepath.Abs(*exclusions)
		if err != nil {
			log.Fatalf("fatal: resolve exclusions path: %v", err)
		}
	}
	waf, err := buildWAF(abs, exclusionsPath, *blockingPL, *detectionPL, *threshold)
	if err != nil {
		log.Fatalf("fatal: build WAF: %v", err)
	}
	srv := &server{waf: waf}

	mux := http.NewServeMux()
	mux.HandleFunc("/eval", srv.handleEval)
	mux.HandleFunc("/healthz", srv.handleHealth)
	mux.HandleFunc("/statsz", srv.handleStats)

	var ln net.Listener
	if *tcpAddr != "" {
		ln, err = net.Listen("tcp", *tcpAddr)
	} else {
		// A stale socket from an unclean shutdown would block startup.
		if err := os.Remove(*socket); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("fatal: remove stale socket: %v", err)
		}
		ln, err = net.Listen("unix", *socket)
		if err == nil {
			// Owner-only. Anything that can reach this socket can ask the
			// engine about arbitrary payloads.
			if cerr := os.Chmod(*socket, 0o600); cerr != nil {
				log.Fatalf("fatal: chmod socket: %v", cerr)
			}
		}
	}
	if err != nil {
		log.Fatalf("fatal: listen: %v", err)
	}

	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	where := *socket
	if *tcpAddr != "" {
		where = *tcpAddr
	}
	log.Printf("s1-sidecar %s listening on %s (crs=%s blocking_pl=%d detection_pl=%d threshold=%d exclusions=%q)",
		version, where, abs, *blockingPL, *detectionPL, *threshold, exclusionsPath)

	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("fatal: serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down")
	_ = httpSrv.Close()
	if *tcpAddr == "" {
		_ = os.Remove(*socket)
	}
}
