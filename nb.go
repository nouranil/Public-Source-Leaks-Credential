package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	maxFileSize = 2 * 1024 * 1024
	maxDisplay  = 15
	userAgent   = "OSINT-Scanner/1.0"
	timeout     = 10 * time.Second
)

type Finding struct {
	Source      string `json:"source"`
	Repository  string `json:"repository,omitempty"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	FileURL     string `json:"file_url"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

type Pattern struct {
	Name  string
	Regex *regexp.Regexp
	Desc  string
}

type Scanner struct {
	target      string
	findings    []Finding
	patterns    []Pattern
	client      *http.Client
	githubToken string
	gitlabToken string
	seen        map[string]bool
}

func NewScanner(target string) *Scanner {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://"), "www.")
	target = strings.Split(target, "/")[0]

	return &Scanner{
		target:      target,
		findings:    []Finding{},
		patterns:    initPatterns(),
		client:      &http.Client{Timeout: timeout},
		githubToken: os.Getenv("GITHUB_TOKEN"),
		gitlabToken: os.Getenv("GITLAB_TOKEN"),
		seen:        make(map[string]bool),
	}
}

func initPatterns() []Pattern {
	return []Pattern{
		{"AWS Access Key", regexp.MustCompile(`(AKIA[0-9A-Z]{16})`), "AWS access key"},
		{"AWS Secret", regexp.MustCompile(`(?i)aws.{0,20}?['"][0-9a-zA-Z/+]{40}['"]`), "AWS secret key"},
		{"Private Key", regexp.MustCompile(`-----BEGIN[A-Z\s]+PRIVATE KEY-----`), "Private key (PEM)"},
		{"Database URL", regexp.MustCompile(`(mongodb|mysql|postgres|postgresql|redis)://[^\s]+`), "Database connection"},
		{"Stripe Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), "Stripe live key"},
		{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "Google API key"},
		{"GitHub Token", regexp.MustCompile(`gh[pousr]_[0-9a-zA-Z]{36,}`), "GitHub token"},
		{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`), "API key"},
		{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})`), "Bearer token"},
		{"JWT Token", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`), "JWT"},
		{"Password", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{6,})['"]?`), "Password"},
		{"Secret Key", regexp.MustCompile(`(?i)(secret|secret[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{16,})['"]?`), "Secret key"},
		{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`), "Slack token"},
		{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Z0-9/]+`), "Slack webhook"},
		{"Discord Webhook", regexp.MustCompile(`https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+`), "Discord webhook"},
	}
}

func (s *Scanner) Run() error {
	fmt.Printf("OSINT Scanner - Target: %s\n\n", s.target)

	sources := []struct {
		name string
		fn   func() error
	}{
		{"GitHub", s.scanGitHub},
		{"GitHub Gists", s.scanGists},
		{"GitLab", s.scanGitLab},
		{"Pastebin", s.scanPastebin},
	}

	for _, src := range sources {
		fmt.Printf("Scanning %s...\n", src.name)
		before := len(s.findings)

		if err := src.fn(); err != nil {
			fmt.Printf("  ⚠ Skipped: %v\n", err)
		} else {
			after := len(s.findings)
			if after > before {
				fmt.Printf("  ✓ Found %d leaks\n", after-before)
			} else {
				fmt.Printf("  ✓ Complete\n")
			}
		}
		time.Sleep(2 * time.Second)
	}

	s.report()
	return nil
}

func (s *Scanner) scanGitHub() error {
	if s.githubToken == "" {
		return fmt.Errorf("GITHUB_TOKEN not set")
	}

	queries := []string{
		fmt.Sprintf("%s filename:.env", s.target),
		fmt.Sprintf("%s filename:config", s.target),
		fmt.Sprintf("%s password", s.target),
	}

	for _, q := range queries {
		apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=20", url.QueryEscape(q))
		req, _ := http.NewRequest("GET", apiURL, nil)
		req.Header.Set("Authorization", "token "+s.githubToken)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", userAgent)

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		var result struct {
			Items []struct {
				Path    string `json:"path"`
				HTMLURL string `json:"html_url"`
				Repo    struct {
					FullName string `json:"full_name"`
					HTMLURL  string `json:"html_url"`
				} `json:"repository"`
			} `json:"items"`
		}

		json.NewDecoder(resp.Body).Decode(&result)

		for _, item := range result.Items {
			rawURL := strings.Replace(item.HTMLURL, "github.com", "raw.githubusercontent.com", 1)
			rawURL = strings.Replace(rawURL, "/blob/", "/", 1)

			content := s.fetch(rawURL)
			if content != "" && strings.Contains(strings.ToLower(content), strings.ToLower(s.target)) {
				s.scan(content, "GitHub", item.Repo.FullName, item.Path, item.Repo.HTMLURL, item.HTMLURL)
			}
		}
	}
	return nil
}

func (s *Scanner) scanGists() error {
	if s.githubToken == "" {
		return fmt.Errorf("GITHUB_TOKEN not set")
	}

	req, _ := http.NewRequest("GET", "https://api.github.com/gists/public?per_page=30", nil)
	req.Header.Set("Authorization", "token "+s.githubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var gists []struct {
		HTMLURL string `json:"html_url"`
		Files   map[string]struct {
			Filename string `json:"filename"`
			RawURL   string `json:"raw_url"`
		} `json:"files"`
	}

	json.NewDecoder(resp.Body).Decode(&gists)

	for _, gist := range gists {
		for _, file := range gist.Files {
			content := s.fetch(file.RawURL)
			if content != "" && strings.Contains(strings.ToLower(content), strings.ToLower(s.target)) {
				fileURL := fmt.Sprintf("%s#file-%s", gist.HTMLURL, strings.ReplaceAll(strings.ToLower(file.Filename), ".", "-"))
				s.scan(content, "GitHub Gist", "", file.Filename, gist.HTMLURL, fileURL)
			}
		}
	}
	return nil
}

func (s *Scanner) scanGitLab() error {
	if s.gitlabToken == "" {
		return fmt.Errorf("GITLAB_TOKEN not set")
	}

	searchURL := fmt.Sprintf("https://gitlab.com/api/v4/projects?search=%s&visibility=public&per_page=10", url.QueryEscape(s.target))
	req, _ := http.NewRequest("GET", searchURL, nil)
	req.Header.Set("PRIVATE-TOKEN", s.gitlabToken)
	req.Header.Set("User-Agent", userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var projects []struct {
		ID                int    `json:"id"`
		PathWithNamespace string `json:"path_with_namespace"`
		WebURL            string `json:"web_url"`
		DefaultBranch     string `json:"default_branch"`
	}

	json.NewDecoder(resp.Body).Decode(&projects)

	for _, proj := range projects {
		branch := proj.DefaultBranch
		if branch == "" {
			branch = "main"
		}

		for _, file := range []string{".env", "config.yml", "settings.py"} {
			fileURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s/raw?ref=%s",
				proj.ID, url.PathEscape(file), branch)

			req2, _ := http.NewRequest("GET", fileURL, nil)
			req2.Header.Set("PRIVATE-TOKEN", s.gitlabToken)

			resp2, err := s.client.Do(req2)
			if err != nil || resp2.StatusCode != 200 {
				if resp2 != nil {
					resp2.Body.Close()
				}
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp2.Body, maxFileSize))
			resp2.Body.Close()
			content := string(body)

			if content != "" && strings.Contains(strings.ToLower(content), strings.ToLower(s.target)) {
				viewURL := fmt.Sprintf("%s/-/blob/%s/%s", proj.WebURL, branch, file)
				s.scan(content, "GitLab", proj.PathWithNamespace, file, proj.WebURL, viewURL)
			}
		}
	}
	return nil
}

func (s *Scanner) scanPastebin() error {
	content := s.fetch("https://pastebin.com/archive")
	if content == "" {
		return fmt.Errorf("unable to fetch archive")
	}

	pasteRegex := regexp.MustCompile(`<a href="/([a-zA-Z0-9]{8})"`)
	matches := pasteRegex.FindAllStringSubmatch(content, 30)

	count := 0
	for _, match := range matches {
		if len(match) > 1 && count < 15 {
			pasteID := match[1]
			pasteURL := fmt.Sprintf("https://pastebin.com/%s", pasteID)
			pasteContent := s.fetch(fmt.Sprintf("https://pastebin.com/raw/%s", pasteID))

			if pasteContent != "" && strings.Contains(strings.ToLower(pasteContent), strings.ToLower(s.target)) {
				s.scan(pasteContent, "Pastebin", "", pasteID, pasteURL, pasteURL)
				count++
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	return nil
}

func (s *Scanner) fetch(u string) string {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := s.client.Do(req)
	if err != nil || resp.StatusCode != 200 || resp.ContentLength > maxFileSize {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxFileSize))
	return string(body)
}

func (s *Scanner) scan(content, source, repo, file, repoURL, fileURL string) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	line := 0

	for scanner.Scan() {
		line++
		text := scanner.Text()

		for _, p := range s.patterns {
			matches := p.Regex.FindAllStringSubmatch(text, -1)
			for _, m := range matches {
				if len(m) == 0 {
					continue
				}

				value := m[0]
				if len(m) > 1 {
					value = m[len(m)-1]
				}

				key := fmt.Sprintf("%s:%s:%d:%s", source, file, line, value)
				if s.seen[key] {
					continue
				}
				s.seen[key] = true

				s.findings = append(s.findings, Finding{
					Source:      source,
					Repository:  repo,
					File:        file,
					Line:        line,
					Type:        p.Name,
					Value:       value,
					FileURL:     fileURL,
					URL:         repoURL,
					Description: p.Desc,
				})
			}
		}
	}
}

func (s *Scanner) report() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("SCAN REPORT")
	fmt.Println(strings.Repeat("=", 80) + "\n")

	total := len(s.findings)
	if total == 0 {
		fmt.Println("No leaks detected.")
		return
	}

	fmt.Printf("Total Findings: %d\n\n", total)

	display := total
	if display > maxDisplay {
		display = maxDisplay
	}

	for i := 0; i < display; i++ {
		f := s.findings[i]
		fmt.Printf("[%d]\n", i+1)
		fmt.Printf("Source: %s\n", f.Source)
		if f.Repository != "" {
			fmt.Printf("Repository: %s\n", f.Repository)
		}
		fmt.Printf("File: %s\n", f.File)
		fmt.Printf("Line: %d\n", f.Line)
		fmt.Printf("Type: %s\n", f.Type)
		fmt.Printf("Value: %s\n", f.Value)
		fmt.Printf("Description: %s\n", f.Description)
		if f.FileURL != "" {
			fmt.Printf("Location: %s\n", f.FileURL)
		}
		fmt.Println()
	}

	if total > maxDisplay {
		fmt.Printf("Showing %d of %d findings\n", maxDisplay, total)
		data, _ := json.MarshalIndent(map[string]interface{}{
			"target": s.target, "total": total, "findings": s.findings,
		}, "", "  ")
		os.WriteFile("findings_full.json", data, 0644)
		fmt.Println("Full report saved to: findings_full.json")
	}

	fmt.Println(strings.Repeat("=", 80))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("OSINT Public Source Leak Scanner\n")
		fmt.Println("Usage: scanner <target>")
		fmt.Println("Example: scanner example.com\n")
		fmt.Println("Environment Variables:")
		fmt.Println("  GITHUB_TOKEN - GitHub personal access token")
		fmt.Println("  GITLAB_TOKEN - GitLab personal access token")
		os.Exit(1)
	}

	scanner := NewScanner(os.Args[1])
	scanner.Run()
}
