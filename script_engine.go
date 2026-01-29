package main

import (
	"fmt"
	"sync"
)

// ScriptCategory defines script categories
type ScriptCategory string

const (
	CategoryAuth        ScriptCategory = "auth"
	CategoryBroadcast   ScriptCategory = "broadcast"
	CategoryBruteforce  ScriptCategory = "brute"
	CategoryDefault     ScriptCategory = "default"
	CategoryDiscovery   ScriptCategory = "discovery"
	CategoryDos         ScriptCategory = "dos"
	CategoryExploit     ScriptCategory = "exploit"
	CategoryExternal    ScriptCategory = "external"
	CategoryFuzzer      ScriptCategory = "fuzzer"
	CategoryIntrusive   ScriptCategory = "intrusive"
	CategoryMalware     ScriptCategory = "malware"
	CategorySafe        ScriptCategory = "safe"
	CategoryVersion     ScriptCategory = "version"
	CategoryVuln        ScriptCategory = "vuln"
)

// Script represents a network reconnaissance script
type Script interface {
	Name() string
	Description() string
	Categories() []ScriptCategory
	PortRule(port int, service string) bool
	Execute(target ScriptTarget) (*ScriptResult, error)
}

// ScriptTarget contains information passed to scripts
type ScriptTarget struct {
	Host    string
	Port    int
	Service string
	Version string
	Banner  string
}

// ScriptResult contains script execution results
type ScriptResult struct {
	ScriptName string   `json:"script_name" xml:"name,attr"`
	Output     string   `json:"output" xml:"output"`
	Findings   []string `json:"findings,omitempty" xml:"findings>finding,omitempty"`
	Vulnerable bool     `json:"vulnerable" xml:"vulnerable,attr"`
	Error      error    `json:"-" xml:"-"`
	ErrorStr   string   `json:"error,omitempty" xml:"error,omitempty"`
}

// ScriptEngine manages and executes scripts
type ScriptEngine struct {
	scripts  []Script
	enabled  bool
	category ScriptCategory
	verbose  bool
}

// NewScriptEngine creates a new script engine
func NewScriptEngine(enabled bool, category ScriptCategory, verbose bool) *ScriptEngine {
	engine := &ScriptEngine{
		scripts:  make([]Script, 0),
		enabled:  enabled,
		category: category,
		verbose:  verbose,
	}
	
	// Register all available scripts
	engine.registerScripts()
	
	return engine
}

// registerScripts registers all available scripts
func (se *ScriptEngine) registerScripts() {
	// HTTP/Web Application scripts
	se.scripts = append(se.scripts, &HTTPAuthScript{})
	se.scripts = append(se.scripts, &HTTPTitleScript{})
	se.scripts = append(se.scripts, &HTTPHeadersScript{})
	se.scripts = append(se.scripts, &HTTPVulnScript{})
	se.scripts = append(se.scripts, &HTTPMethodsScript{})
	se.scripts = append(se.scripts, &HTTPRobotsScript{})
	se.scripts = append(se.scripts, &HTTPEnumScript{})
	se.scripts = append(se.scripts, &HTTPWebDAVScript{})
	se.scripts = append(se.scripts, &HTTPBackupFilesScript{})
	se.scripts = append(se.scripts, &HTTPCGIScript{})
	se.scripts = append(se.scripts, &HTTPSQLMapScript{})
	se.scripts = append(se.scripts, &HTTPXSSScript{})
	se.scripts = append(se.scripts, &HTTPLFIScript{})
	se.scripts = append(se.scripts, &HTTPWordPressScript{})
	
	// SSH/FTP/SMTP scripts
	se.scripts = append(se.scripts, &FTPAnonScript{})
	se.scripts = append(se.scripts, &SSHAuthMethodsScript{})
	se.scripts = append(se.scripts, &SSHVersionScript{})
	se.scripts = append(se.scripts, &SMTPCommandsScript{})
	
	// SSL/TLS scripts
	se.scripts = append(se.scripts, &SSLCertScript{})
	se.scripts = append(se.scripts, &SSLVulnScript{})
	
	// Database scripts
	se.scripts = append(se.scripts, &MySQLInfoScript{})
	se.scripts = append(se.scripts, &RedisInfoScript{})
	se.scripts = append(se.scripts, &MongoDBInfoScript{})
	se.scripts = append(se.scripts, &CassandraScript{})
	se.scripts = append(se.scripts, &MSQLServerInfoScript{})
	se.scripts = append(se.scripts, &ElasticsearchScript{})
	
	// SMB/Windows scripts
	se.scripts = append(se.scripts, &SMBVersionScript{})
	se.scripts = append(se.scripts, &SMBSigningScript{})
	se.scripts = append(se.scripts, &SMBVulnMS17010Script{})
	se.scripts = append(se.scripts, &SMBEnumSharesScript{})
	se.scripts = append(se.scripts, &SMBEnumUsersScript{})
	se.scripts = append(se.scripts, &NetBIOSInfoScript{})
	se.scripts = append(se.scripts, &RDPSecurityScript{})
	se.scripts = append(se.scripts, &RDPNLAScript{})
	se.scripts = append(se.scripts, &MSRPCEndpointScript{})
	se.scripts = append(se.scripts, &WinRMScript{})
	se.scripts = append(se.scripts, &LDAPAnonBindScript{})
	se.scripts = append(se.scripts, &KerberosEnumScript{})
	
	// VNC and remote access
	se.scripts = append(se.scripts, &VNCAuthScript{})
	
	// Network services
	se.scripts = append(se.scripts, &NFSExportScript{})
	se.scripts = append(se.scripts, &DNSVersionScript{})
	se.scripts = append(se.scripts, &DNSZoneTransferScript{})
	se.scripts = append(se.scripts, &NTPMonlistScript{})
	se.scripts = append(se.scripts, &TFTPEnumScript{})
	se.scripts = append(se.scripts, &TelnetEnumScript{})
	se.scripts = append(se.scripts, &RLoginScript{})
	se.scripts = append(se.scripts, &JavaRMIScript{})
	se.scripts = append(se.scripts, &DistCCScript{})
	se.scripts = append(se.scripts, &RSyncScript{})
	se.scripts = append(se.scripts, &SNMPEnumScript{})
}

// RunScripts executes applicable scripts for a target
func (se *ScriptEngine) RunScripts(target ScriptTarget) []ScriptResult {
	if !se.enabled {
		return nil
	}
	
	var results []ScriptResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Find applicable scripts
	applicableScripts := se.getApplicableScripts(target)
	
	if se.verbose && len(applicableScripts) > 0 {
		fmt.Printf("\n"+ColorCyan+"[*] "+ColorReset+"Running "+ColorPurple+"%d"+ColorReset+" scripts against "+ColorTeal+"%s:%d"+ColorReset+"...\n", len(applicableScripts), target.Host, target.Port)
	}
	
	// Execute scripts concurrently
	for _, script := range applicableScripts {
		wg.Add(1)
		go func(s Script) {
			defer wg.Done()
			
			if se.verbose {
				fmt.Printf(ColorTeal+"  [→] "+ColorReset+"Running script: "+ColorPurple+"%s\n"+ColorReset, s.Name())
			}
			
			result, err := s.Execute(target)
			if err != nil {
				result = &ScriptResult{
					ScriptName: s.Name(),
					Error:      err,
				}
			}
			
			mu.Lock()
			results = append(results, *result)
			mu.Unlock()
		}(script)
	}
	
	wg.Wait()
	return results
}

// getApplicableScripts returns scripts that should run for the target
func (se *ScriptEngine) getApplicableScripts(target ScriptTarget) []Script {
	var applicable []Script
	
	for _, script := range se.scripts {
		// FIRST: Check if script applies to this port/service (REQUIRED)
		if !script.PortRule(target.Port, target.Service) {
			continue // Skip if port/service doesn't match
		}
		
		// SECOND: If category filter is set, script MUST be in that category
		if se.category != "" {
			matches := false
			for _, cat := range script.Categories() {
				if cat == se.category {
					matches = true
					break
				}
			}
			if !matches {
				continue // Skip if category doesn't match
			}
		}
		
		// Both conditions met - include this script
		applicable = append(applicable, script)
	}
	
	return applicable
}

// ListScripts lists all available scripts
func (se *ScriptEngine) ListScripts() {
	fmt.Println(ColorCyan + ColorBold + "\n╔════════════════════════════════════════════════╗")
	fmt.Println("║         AVAILABLE SCRIPTS (52 Total)           ║")
	fmt.Println("╚════════════════════════════════════════════════╝" + ColorReset)
	
	categoryMap := make(map[ScriptCategory][]Script)
	
	for _, script := range se.scripts {
		for _, cat := range script.Categories() {
			categoryMap[cat] = append(categoryMap[cat], script)
		}
	}
	
	categoryColors := map[ScriptCategory]string{
		CategoryAuth:      ColorGreen,
		CategoryDiscovery: ColorCyan,
		CategoryVuln:      ColorRed,
		CategoryVersion:   ColorPurple,
		CategoryDefault:   ColorTeal,
		CategorySafe:      ColorGreen,
	}
	
	for category, scripts := range categoryMap {
		color := categoryColors[category]
		if color == "" {
			color = ColorCyan
		}
		
		fmt.Printf("\n" + color + ColorBold + "═══ %s Scripts ═══\n" + ColorReset, category)
		for _, script := range scripts {
			fmt.Printf(ColorPurple+"  • "+ColorReset+ColorBold+"%s"+ColorReset+": %s\n", script.Name(), script.Description())
		}
	}
	
	fmt.Println(ColorCyan + "\n════════════════════════════════════════════════" + ColorReset)
}
