package main

import (
	"regexp"
	"strings"
)

// ServiceVulnEntry represents a vulnerability entry for a service
type ServiceVulnEntry struct {
	MinVersion     string              // Minimum affected version (inclusive)
	MaxVersion     string              // Maximum affected version (inclusive)
	VersionPattern string              // Regex pattern for version matching
	Platform       string              // Affected platform
	Type           string              // Exploit type (remote, local, webapps, dos)
	Vulns          []VulnerabilityInfo // Associated vulnerabilities
}

// ServiceVulnDB is the embedded vulnerability database
// Maps service names to known vulnerabilities
var ServiceVulnDB = map[string][]ServiceVulnEntry{
	"openssh": {
		{
			MaxVersion: "7.7",
			Platform:   "linux",
			Type:       "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2018-15473", EDBID: "45233", Title: "OpenSSH < 7.7 - User Enumeration", Severity: "medium", CVSS: 5.3, Verified: true},
			},
		},
		{
			MinVersion: "8.2", MaxVersion: "8.2p1",
			Platform: "multiple",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2020-15778", EDBID: "48618", Title: "OpenSSH 8.2p1 - Command Injection via scp", Severity: "high", CVSS: 7.8, Verified: true},
			},
		},
		{
			MinVersion: "2.3", MaxVersion: "7.6",
			Platform: "linux",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2016-10012", EDBID: "40962", Title: "OpenSSH < 7.4 - Agent Protocol Arbitrary Library Loading", Severity: "high", CVSS: 7.8},
			},
		},
	},

	"vsftpd": {
		{
			VersionPattern: "2\\.3\\.4",
			Platform:       "unix",
			Type:           "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2011-2523", EDBID: "17491", Title: "vsftpd 2.3.4 - Backdoor Command Execution", Severity: "critical", CVSS: 10.0, Metasploit: "exploit/unix/ftp/vsftpd_234_backdoor", Verified: true},
			},
		},
	},

	"proftpd": {
		{
			MinVersion: "1.3.3", MaxVersion: "1.3.3c",
			Platform: "unix",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2010-4221", EDBID: "15449", Title: "ProFTPD 1.3.3c - Backdoor Command Execution", Severity: "critical", CVSS: 10.0, Metasploit: "exploit/unix/ftp/proftpd_133c_backdoor", Verified: true},
			},
		},
		{
			MinVersion: "1.3.5", MaxVersion: "1.3.5",
			Platform: "linux",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2015-3306", EDBID: "36742", Title: "ProFTPD 1.3.5 - mod_copy Remote Command Execution", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/unix/ftp/proftpd_modcopy_exec", Verified: true},
			},
		},
	},

	"apache": {
		{
			MinVersion: "2.4.49", MaxVersion: "2.4.50",
			Platform: "multiple",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2021-41773", EDBID: "50383", Title: "Apache 2.4.49/50 - Path Traversal & RCE", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/multi/http/apache_normalize_path_rce", Verified: true},
			},
		},
		{
			MinVersion: "2.4.0", MaxVersion: "2.4.29",
			Platform: "linux",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2017-15715", EDBID: "44569", Title: "Apache 2.4.0-2.4.29 - Filename Bypass Upload", Severity: "high", CVSS: 8.1},
			},
		},
	},

	"nginx": {
		{
			MinVersion: "0.5.6", MaxVersion: "1.13.2",
			Platform: "linux",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2017-7529", EDBID: "43014", Title: "nginx 0.5.6-1.13.2 - Integer Overflow", Severity: "high", CVSS: 7.5},
			},
		},
	},

	"iis": {
		{
			MinVersion: "6.0", MaxVersion: "6.0",
			Platform: "windows",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2017-7269", EDBID: "41738", Title: "IIS 6.0 - WebDAV Remote Code Execution", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/windows/iis/iis_webdav_scstoragepathfromurl", Verified: true},
			},
		},
	},

	"smb": {
		{
			Platform: "windows",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2017-0144", EDBID: "41891", Title: "EternalBlue - SMB Remote Code Execution (MS17-010)", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/windows/smb/ms17_010_eternalblue", Verified: true},
				{CVE: "CVE-2017-0145", EDBID: "41987", Title: "EternalRomance - SMB Remote Code Execution (MS17-010)", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/windows/smb/ms17_010_psexec", Verified: true},
				{CVE: "CVE-2020-0796", EDBID: "48153", Title: "SMBGhost - SMBv3 Remote Code Execution", Severity: "critical", CVSS: 10.0, Metasploit: "exploit/windows/smb/smbghost_cve_2020_0796", Verified: true},
			},
		},
	},

	"samba": {
		{
			MinVersion: "3.5.0", MaxVersion: "4.6.4",
			Platform: "linux",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2017-7494", EDBID: "42084", Title: "Samba 3.5.0-4.6.4 - SambaCry Remote Code Execution", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/linux/samba/is_known_pipename", Verified: true},
			},
		},
	},

	"mysql": {
		{
			MinVersion: "5.0", MaxVersion: "5.5.9",
			Platform: "linux",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2012-2122", EDBID: "19092", Title: "MySQL 5.x - Authentication Bypass", Severity: "critical", CVSS: 9.8, Metasploit: "auxiliary/scanner/mysql/mysql_authbypass_hashdump", Verified: true},
			},
		},
	},

	"postgres": {
		{
			MinVersion: "8.4", MaxVersion: "9.3",
			Platform: "linux",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2019-9193", EDBID: "46813", Title: "PostgreSQL 9.3-11.2 - Arbitrary Code Execution", Severity: "high", CVSS: 8.8, Metasploit: "exploit/multi/postgres/postgres_copy_from_program_cmd_exec"},
			},
		},
	},

	"redis": {
		{
			MinVersion: "4.0", MaxVersion: "5.0.5",
			Platform: "linux",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2019-10192", EDBID: "47195", Title: "Redis 4.x/5.x - Unauthenticated Code Execution", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/linux/redis/redis_unauth_exec", Verified: true},
			},
		},
	},

	"elasticsearch": {
		{
			MinVersion: "1.1", MaxVersion: "1.1.1",
			Platform: "linux",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2014-3120", EDBID: "33370", Title: "Elasticsearch 1.1.1 - Remote Code Execution", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/multi/elasticsearch/script_mvel_rce", Verified: true},
			},
		},
	},

	"tomcat": {
		{
			MinVersion: "7.0", MaxVersion: "7.0.79",
			Platform: "multiple",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2017-12617", EDBID: "42966", Title: "Apache Tomcat - JSP Upload Bypass RCE", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/multi/http/tomcat_jsp_upload_bypass", Verified: true},
			},
		},
		{
			MinVersion: "8.5.0", MaxVersion: "8.5.19",
			Platform: "multiple",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2017-12615", EDBID: "42953", Title: "Apache Tomcat - PUT Method RCE", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/multi/http/tomcat_put_rce", Verified: true},
			},
		},
	},

	"jenkins": {
		{
			MaxVersion: "2.137",
			Platform:   "java",
			Type:       "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2019-1003000", EDBID: "46572", Title: "Jenkins < 2.137 - Remote Code Execution", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/multi/http/jenkins_script_console"},
			},
		},
	},

	"wordpress": {
		{
			MinVersion: "4.6", MaxVersion: "4.7.4",
			Platform: "php",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2017-8295", EDBID: "41963", Title: "WordPress 4.6-4.7.4 - PHPMailer RCE", Severity: "high", CVSS: 8.1},
			},
		},
		{
			MinVersion: "5.0", MaxVersion: "5.0.0",
			Platform: "php",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2019-8942", EDBID: "46662", Title: "WordPress 5.0.0 - Image RCE via crop-image", Severity: "high", CVSS: 8.8, Metasploit: "exploit/unix/webapp/wp_crop_rce"},
			},
		},
	},

	"drupal": {
		{
			MinVersion: "7.0", MaxVersion: "7.58",
			Platform: "php",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2018-7600", EDBID: "44449", Title: "Drupal < 7.58 - Drupalgeddon2 RCE", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/unix/webapp/drupal_drupalgeddon2", Verified: true},
			},
		},
		{
			MinVersion: "8.0", MaxVersion: "8.5.0",
			Platform: "php",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2018-7602", EDBID: "44557", Title: "Drupal < 8.5.1 - Drupalgeddon3 RCE", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/unix/webapp/drupal_drupalgeddon3", Verified: true},
			},
		},
	},

	"joomla": {
		{
			MinVersion: "1.5", MaxVersion: "3.4.5",
			Platform: "php",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2015-8562", EDBID: "38977", Title: "Joomla 1.5-3.4.5 - Object Injection RCE", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/unix/webapp/joomla_http_header_rce", Verified: true},
			},
		},
	},

	"struts": {
		{
			MinVersion: "2.0", MaxVersion: "2.5.12",
			Platform: "java",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2017-5638", EDBID: "41570", Title: "Apache Struts 2 - Content-Type RCE (Equifax)", Severity: "critical", CVSS: 10.0, Metasploit: "exploit/multi/http/struts2_content_type_ognl", Verified: true},
			},
		},
		{
			MinVersion: "2.1", MaxVersion: "2.3.33",
			Platform: "java",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2017-9805", EDBID: "42627", Title: "Apache Struts 2 - REST Plugin RCE", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/multi/http/struts2_rest_xstream", Verified: true},
			},
		},
	},

	"shellshock": {
		{
			Platform: "linux",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2014-6271", EDBID: "34765", Title: "Shellshock - Bash Remote Code Execution", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/multi/http/apache_mod_cgi_bash_env_exec", Verified: true},
			},
		},
	},

	"heartbleed": {
		{
			Platform: "multiple",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2014-0160", EDBID: "32745", Title: "Heartbleed - OpenSSL Information Disclosure", Severity: "high", CVSS: 7.5, Metasploit: "auxiliary/scanner/ssl/openssl_heartbleed", Verified: true},
			},
		},
	},

	"weblogic": {
		{
			MinVersion: "10.3.6", MaxVersion: "12.2.1.3",
			Platform: "java",
			Type:     "webapps",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2019-2725", EDBID: "46780", Title: "Oracle WebLogic - Deserialization RCE", Severity: "critical", CVSS: 9.8, Metasploit: "exploit/multi/misc/weblogic_deserialize_asyncresponseservice", Verified: true},
			},
		},
	},

	"vncserver": {
		{
			Platform: "multiple",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2006-2369", EDBID: "1838", Title: "RealVNC 4.1.1 - Authentication Bypass", Severity: "critical", CVSS: 9.8, Metasploit: "auxiliary/scanner/vnc/vnc_none_auth"},
			},
		},
	},

	"log4j": {
		{
			MinVersion: "2.0", MaxVersion: "2.14.1",
			Platform: "java",
			Type:     "remote",
			Vulns: []VulnerabilityInfo{
				{CVE: "CVE-2021-44228", EDBID: "50592", Title: "Log4j 2.x - Log4Shell Remote Code Execution", Severity: "critical", CVSS: 10.0, Metasploit: "exploit/multi/http/log4shell_header_injection", Verified: true},
			},
		},
	},
}

// checkBuiltInVulnDB checks service version against built-in vulnerability database
func checkBuiltInVulnDB(service, version string) []VulnerabilityInfo {
	vulns := make([]VulnerabilityInfo, 0)

	serviceLower := strings.ToLower(service)
	versionClean := extractVersionNumber(version)

	// Direct lookup
	if entries, exists := ServiceVulnDB[serviceLower]; exists {
		vulns = append(vulns, matchVulnEntries(entries, versionClean)...)
	}

	// Partial match for service names
	for svcName, entries := range ServiceVulnDB {
		if strings.Contains(serviceLower, svcName) || strings.Contains(svcName, serviceLower) {
			vulns = append(vulns, matchVulnEntries(entries, versionClean)...)
		}
	}

	// Check version string for known vulnerable software
	versionLower := strings.ToLower(version)
	for svcName, entries := range ServiceVulnDB {
		if strings.Contains(versionLower, svcName) {
			vulns = append(vulns, matchVulnEntries(entries, versionClean)...)
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := make([]VulnerabilityInfo, 0)
	for _, v := range vulns {
		key := v.CVE + v.EDBID
		if !seen[key] {
			seen[key] = true
			unique = append(unique, v)
		}
	}

	return unique
}

// matchVulnEntries checks if a version matches any vulnerability entries
func matchVulnEntries(entries []ServiceVulnEntry, version string) []VulnerabilityInfo {
	vulns := make([]VulnerabilityInfo, 0)

	for _, entry := range entries {
		matched := false

		// Check version pattern
		if entry.VersionPattern != "" {
			if re, err := regexp.Compile(entry.VersionPattern); err == nil {
				if re.MatchString(version) {
					matched = true
				}
			}
		}

		// Check version range
		if !matched && version != "" {
			if entry.MinVersion != "" && entry.MaxVersion != "" {
				if CompareVersions(version, entry.MinVersion) >= 0 &&
					CompareVersions(version, entry.MaxVersion) <= 0 {
					matched = true
				}
			} else if entry.MaxVersion != "" {
				if CompareVersions(version, entry.MaxVersion) <= 0 {
					matched = true
				}
			} else if entry.MinVersion != "" {
				if CompareVersions(version, entry.MinVersion) >= 0 {
					matched = true
				}
			}
		}

		// If no version constraints or no version provided, include all
		if !matched && version == "" && entry.MinVersion == "" && entry.MaxVersion == "" && entry.VersionPattern == "" {
			matched = true
		}

		if matched {
			vulns = append(vulns, entry.Vulns...)
		}
	}

	return vulns
}

// GetMetasploitModule returns the Metasploit module path for a vulnerability
func GetMetasploitModule(cve string) string {
	for _, entries := range ServiceVulnDB {
		for _, entry := range entries {
			for _, vuln := range entry.Vulns {
				if vuln.CVE == cve && vuln.Metasploit != "" {
					return vuln.Metasploit
				}
			}
		}
	}
	return ""
}

// GetVulnByCVE retrieves vulnerability info by CVE
func GetVulnByCVE(cve string) *VulnerabilityInfo {
	for _, entries := range ServiceVulnDB {
		for _, entry := range entries {
			for _, vuln := range entry.Vulns {
				if vuln.CVE == cve {
					return &vuln
				}
			}
		}
	}
	return nil
}
