package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Environment variable configuration
var (
	port         = getEnv("SERVER_PORT", getEnv("PORT", "3000"))
	vmms         = getEnv("VPATH", "vls")
	vmmport      = getEnv("VL_PORT", "8002")
	vmpath       = getEnv("MPATH", "vms")
	vmport       = getEnv("VM_PORT", "8001")
	xieyi        = getEnv("XIEYI", "vms")
	uuid         = getEnv("UUID", "3a8a1de5-7d41-45e2-88fe-0f538b822169")
	youxuan      = getEnv("CF_IP", "ip.sb")
	subName      = getEnv("SUB_NAME", "")
	subURL       = getEnv("SUB_URL", "")
	baohuoURL    = getEnv("BAOHUO_URL", "")
	nezhaServer  = getEnv("NEZ_SERVER", "")
	nezhaKey     = getEnv("NEZ_KEY", "")
	nezhaPort    = getEnv("NEZ_PORT", "443")
	nezhaTLS     = getEnv("NEZ_TLS", "--tls")
	filePath     = getEnv("FILE_PATH", "/tmp/")
	tok          = getEnv("TOK", "")
	hostName     = getEnv("ARG_DOMAIN", "")
	agentUUID    = ""
	nezhaHasPort = strings.Contains(nezhaServer, ":")

	// Download URLs
	nezhaURLX64      = getEnv("NEZHA_URL_X64", "https://github.com/Fscarmon/flies/releases/latest/download/agent-linux_amd64")
	nezhaURLArm64    = getEnv("NEZHA_URL_ARM64", "https://github.com/Fscarmon/flies/releases/latest/download/agent-linux_arm64")
	nezhaURLBsd      = getEnv("NEZHA_URL_BSD", "https://github.com/Fscarmon/flies/releases/latest/download/agent-freebsd_amd64")
	nezhaURLX64Alt   = getEnv("NEZHA_URL_X64_ALT", "https://github.com/Fscarmon/flies/releases/latest/download/agent2-linux_amd64")
	nezhaURLArm64Alt = getEnv("NEZHA_URL_ARM64_ALT", "https://github.com/Fscarmon/flies/releases/latest/download/agent2-linux_arm64")
	nezhaURLBsdAlt   = getEnv("NEZHA_URL_BSD_ALT", "https://github.com/Fscarmon/flies/releases/latest/download/agent2-freebsd_amd64")
	webURLX64        = getEnv("WEB_URL_X64", "https://github.com/dsadsadsss/1/releases/download/xry/kano-yuan")
	webURLArm64      = getEnv("WEB_URL_ARM64", "https://github.com/dsadsadsss/1/releases/download/xry/kano-yuan-arm")
	webURLBsd        = getEnv("WEB_URL_BSD", "https://github.com/dsadsadsss/1/releases/download/xry/kano-bsd")
	cffURLX64        = getEnv("CFF_URL_X64", "https://github.com/Fscarmon/flies/releases/latest/download/cff-linux-amd64")
	cffURLArm64      = getEnv("CFF_URL_ARM64", "https://github.com/Fscarmon/flies/releases/latest/download/cff-linux-arm64")
	cffURLBsd        = getEnv("CFF_URL_BSD", "https://github.com/dsadsadsss/1/releases/download/xry/argo-bsdamd")

	// Filenames
	webFilename   = getEnv("WEB_FILENAME", "webdav")
	nezhaFilename = getEnv("NEZHA_FILENAME", "nexus")
	cffFilename   = getEnv("CFF_FILENAME", "cfloat")

	vport = vmport

	// App start time
	startTime time.Time
)

// Process management
var (
	processMutex sync.Mutex
	runningProcs = make(map[string]*os.Process)
)

// ProcessStatus defines the structure for reporting process status.
type ProcessStatus struct {
	Process string `json:"process"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func generateAgentUUID() {
	seed := fmt.Sprintf("%s%s%s%s", uuid, nezhaServer, nezhaKey, tok)
	hash := sha256.Sum256([]byte(seed))
	hexHash := fmt.Sprintf("%x", hash)
	agentUUID = fmt.Sprintf("%s-%s-%s-%s-%s", hexHash[0:8], hexHash[8:12], hexHash[12:16], hexHash[16:20], hexHash[20:32])
	if os.Getenv("AGENT_UUID") != "" {
		agentUUID = os.Getenv("AGENT_UUID")
	}
}

func getCountryCode() string {
	urls := []string{
		"http://ipinfo.io/country",
		"https://ifconfig.co/country",
		"https://ipapi.co/country",
	}
	for _, u := range urls {
		resp, err := http.Get(u)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			code := strings.TrimSpace(string(body))
			if len(code) > 0 && len(code) <= 3 {
				return code
			}
		}
	}
	return "UN"
}

// extractHostNameFromLog dynamically extracts the Cloudflare hostname from the log file.
func extractHostNameFromLog() string {
	if tok != "" {
		return hostName // Use fixed hostname if token is present
	}

	logPath := filepath.Join(filePath, "argo.log") //
	content, err := os.ReadFile(logPath)           //
	if err == nil {
		// Extract hostname matching the format https://xxx.cloudflare.com
		re := regexp.MustCompile(`https://([^/\s]+cloudflare\.com)`)      //
		if matches := re.FindStringSubmatch(string(content)); len(matches) > 1 { //
			return matches[1] //
		}
	}
	return "" //
}

func generateVmessLink(countryCode, currentHostName string) string {
	config := map[string]interface{}{
		"v":    "2",
		"ps":   fmt.Sprintf("%s-%s", countryCode, subName),
		"add":  youxuan,
		"port": "443",
		"id":   uuid,
		"aid":  "0",
		"net":  "ws",
		"type": "none",
		"host": currentHostName,
		"path": "/" + vmpath + "?ed=2048",
		"tls":  "tls",
		"sni":  currentHostName,
		"alpn": "",
	}
	jsonConfig, _ := json.Marshal(config)
	return "vmess://" + base64.StdEncoding.EncodeToString(jsonConfig)
}

func buildSubscriptionURL(countryCode, currentHostName string) string {
	if xieyi == "vms" {
		return generateVmessLink(countryCode, currentHostName)
	}
	rawURL := fmt.Sprintf("vless://%s@%s:443?path=%%2F%s%%3Fed%%3D2048&security=tls&encryption=none&host=%s&type=ws&sni=%s#%s-%s",
		uuid, youxuan, vmms, currentHostName, currentHostName, countryCode, subName)
	return rawURL
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return os.Chmod(dest, 0777)
}

func downloadBinaries() {
	arch := runtime.GOARCH
	platform := runtime.GOOS

	// WEB
	var webURL string
	switch {
	case platform == "linux" && arch == "amd64":
		webURL = webURLX64
	case platform == "linux" && arch == "arm64":
		webURL = webURLArm64
	case platform == "freebsd":
		webURL = webURLBsd
	}
	if webURL != "" {
		log.Println("Downloading web binary...")
		if err := downloadFile(webURL, filepath.Join(filePath, webFilename)); err != nil {
			log.Printf("Failed to download web binary: %v", err)
		} else {
			log.Println("Web binary downloaded.")
		}
	}

	// Nezha
	if nezhaServer != "" && nezhaKey != "" {
		var nezhaURL string
		alt := nezhaHasPort
		switch {
		case platform == "linux" && arch == "amd64":
			nezhaURL = map[bool]string{false: nezhaURLX64, true: nezhaURLX64Alt}[alt]
		case platform == "linux" && arch == "arm64":
			nezhaURL = map[bool]string{false: nezhaURLArm64, true: nezhaURLArm64Alt}[alt]
		case platform == "freebsd":
			nezhaURL = map[bool]string{false: nezhaURLBsd, true: nezhaURLBsdAlt}[alt]
		}
		if nezhaURL != "" {
			log.Println("Downloading nezha agent...")
			if err := downloadFile(nezhaURL, filepath.Join(filePath, nezhaFilename)); err != nil {
				log.Printf("Failed to download nezha agent: %v", err)
			} else {
				log.Println("Nezha agent downloaded.")
			}
		}
	}

	// CFF
	var cffURL string
	switch {
	case platform == "linux" && arch == "amd64":
		cffURL = cffURLX64
	case platform == "linux" && arch == "arm64":
		cffURL = cffURLArm64
	case platform == "freebsd":
		cffURL = cffURLBsd
	}
	if cffURL != "" {
		log.Println("Downloading cff binary...")
		if err := downloadFile(cffURL, filepath.Join(filePath, cffFilename)); err != nil {
			log.Printf("Failed to download cff binary: %v", err)
		} else {
			log.Println("Cff binary downloaded.")
		}
	}
}

func createNezhaConfig() {
	if nezhaServer == "" || !nezhaHasPort {
		return
	}
	configContent := fmt.Sprintf(`client_secret: %s
debug: false
disable_auto_update: false
disable_command_execute: false
disable_force_update: false
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 3
server: %s
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: %t
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: %s`, nezhaKey, nezhaServer, nezhaTLS == "--tls", agentUUID)

	configPath := filepath.Join(filePath, "config.yml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		log.Printf("Failed to create config.yml: %v", err)
	} else {
		log.Println("config.yml created successfully.")
	}
}

func isProcessRunning(name string) bool {
	out, err := exec.Command("pgrep", "-f", name).Output()
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

// startProcess now includes improved restart logic.
func startProcess(name string, env []string, command string, args ...string) ProcessStatus {
	processMutex.Lock()
	defer processMutex.Unlock()

	status := ProcessStatus{Process: name}

	// Add cleanup logic before starting the process.
	if proc, exists := runningProcs[name]; exists {
		// Attempt to gracefully shut down the process.
		if err := proc.Signal(syscall.SIGTERM); err == nil { //
			time.Sleep(2 * time.Second) // Wait for the process to exit.
		}
		proc.Kill()                  // Forcefully terminate the process.
		delete(runningProcs, name) //
	}

	// Fallback check using pgrep
	if isProcessRunning(name) {
		status.Status = "Already running (detected by pgrep)"
		return status
	}

	log.Printf("Starting %s...", name)
	cmd := exec.Command(command, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err := cmd.Start()
	if err != nil {
		log.Printf("Failed to start %s: %v", name, err)
		status.Status = "Failed to start"
		status.Error = err.Error()
		return status
	}

	runningProcs[name] = cmd.Process
	log.Printf("%s started with PID %d.", name, cmd.Process.Pid)
	status.Status = "Started"

	// Asynchronously wait for the process to exit to clean up the map
	go func() {
		_ = cmd.Wait()
		processMutex.Lock()
		delete(runningProcs, name)
		processMutex.Unlock()
		log.Printf("Process %s (PID %d) has exited.", name, cmd.Process.Pid)
	}()

	return status
}

func checkAndStartProcesses() []ProcessStatus {
	statuses := []ProcessStatus{}

	// Start CFF
	cffPath := filepath.Join(filePath, cffFilename)
	var cffArgs []string
	if tok != "" {
		cffArgs = []string{"tunnel", "--edge-ip-version", "auto", "--protocol", "auto", "run", "--no-autoupdate", "--token", tok}
	} else {
		logFile := "> " + filepath.Join(filePath, "argo.log") + " 2>&1"
		cffArgs = []string{"tunnel", "--edge-ip-version", "auto", "--protocol", "auto", "--url", "http://localhost:" + vport, "--no-autoupdate", logFile}
	}
	statuses = append(statuses, startProcess(cffFilename, nil, cffPath, cffArgs...))

	// Start Web
	webPath := filepath.Join(filePath, webFilename)
	webEnv := []string{
		"MPATH=" + vmpath,
		"VM_PORT=" + vmport,
		"VPATH=" + vmms,
		"VL_PORT=" + vmmport,
		"UUID=" + uuid,
	}
	statuses = append(statuses, startProcess(webFilename, webEnv, webPath))

	// Start Nezha
	if nezhaServer != "" && nezhaKey != "" {
		nezhaPath := filepath.Join(filePath, nezhaFilename)
		var nezhaArgs []string
		if nezhaHasPort {
			nezhaArgs = []string{"-c", filepath.Join(filePath, "config.yml")}
		} else {
			nezhaArgs = []string{"-s", nezhaServer + ":" + nezhaPort, "-p", nezhaKey}
			if nezhaTLS == "--tls" {
				nezhaArgs = append(nezhaArgs, "--tls")
			}
		}
		statuses = append(statuses, startProcess(nezhaFilename, nil, nezhaPath, nezhaArgs...))
	}
	return statuses
}

func keepAlive() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		<-ticker.C
		log.Println("Running keep-alive checks...")
		checkAndStartProcesses() // In keep-alive, we don't need the status response

		// Keep-alive pings
		if os.Getenv("SPACE_HOST") != "" {
			http.Get("https://" + os.Getenv("SPACE_HOST"))
		} else if baohuoURL != "" {
			http.Get("https://" + baohuoURL)
		} else if os.Getenv("PROJECT_DOMAIN") != "" {
			http.Get("https://" + os.Getenv("PROJECT_DOMAIN") + ".glitch.me")
		}
	}
}

// subscriptionManager now uses the dynamic hostname extractor.
func subscriptionManager() {
	if subURL == "" {
		return
	}

	var lastHostName string
	var lastSentTime time.Time
	countryCode := getCountryCode()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C
		currentHostName := hostName
		// Dynamically extract the hostname if no token is provided.
		if tok == "" {
			currentHostName = extractHostNameFromLog() //
		}

		if currentHostName != "" && (currentHostName != lastHostName || time.Since(lastSentTime) > 5*time.Minute) {
			upURL := buildSubscriptionURL(countryCode, currentHostName)
			postData := map[string]string{
				"URL_NAME": subName,
				"URL":      upURL,
			}
			jsonData, _ := json.Marshal(postData)

			resp, err := http.Post(subURL, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				log.Printf("Sub Upload failed: %v", err)
			} else {
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					log.Println("Sub Upload successful")
				} else {
					log.Printf("Sub Upload failed with status: %s", resp.Status)
				}
				resp.Body.Close()
			}

			lastHostName = currentHostName
			lastSentTime = time.Now()
		}
	}
}

// uploadSubName implements the upname functionality.
func uploadSubName() error {
	if nezhaServer == "" || nezhaKey == "" {
		return nil
	}

	nezURL := strings.Split(nezhaServer, ":")[0]
	url := fmt.Sprintf("https://%s/upload", nezURL)

	postData := map[string]string{
		"SUBNAME": subName,
		"UUID":    agentUUID,
	}

	jsonData, _ := json.Marshal(postData)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.URL.RawQuery = "token=" + nezhaKey

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 202 {
		log.Println("Upload sub_name succeeded")
	}
	return nil
}

func main() {
	startTime = time.Now()

	if xieyi != "vms" {
		vport = vmmport
	}

	generateAgentUUID()
	log.Println("Starting application...")
	log.Println("==============================")
	log.Println("     /info 系统信息")
	log.Println("     /start 检查进程")
	log.Printf("     /%s 订阅", uuid)
	log.Println("==============================")

	downloadBinaries()
	createNezhaConfig()

	// Initial start of processes after a delay
	go func() {
		time.Sleep(5 * time.Second)
		checkAndStartProcesses()
	}()

	// Start keep-alive loop
	go keepAlive()

	// Start subscription manager
	go subscriptionManager()

	// Start periodic sub_name upload if needed
	if nezhaHasPort {
		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()
			for {
				<-ticker.C
				if err := uploadSubName(); err != nil {
					log.Printf("Periodic sub_name upload failed: %v", err)
				}
			}
		}()
	}

	// Setup web server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello world")
	})

	// Add /info endpoint.
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		info := map[string]interface{}{
			"platform": runtime.GOOS,
			"arch":     runtime.GOARCH,
			"version":  runtime.Version(),
			"uptime":   time.Since(startTime).String(),
		}
		json.NewEncoder(w).Encode(info)
	})

	mux.HandleFunc(fmt.Sprintf("/%s", uuid), func(w http.ResponseWriter, r *http.Request) {
		countryCode := getCountryCode()
		currentHostName := hostName
		if tok == "" {
			currentHostName = extractHostNameFromLog()
		}

		subscriptionLink := buildSubscriptionURL(countryCode, currentHostName)
		if xieyi == "vms" {
			fmt.Fprint(w, subscriptionLink)
		} else {
			encodedURL := base64.StdEncoding.EncodeToString([]byte(subscriptionLink))
			fmt.Fprint(w, encodedURL)
		}
	})

	// Updated /start endpoint to return detailed status.
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Manual process start triggered.")
		statuses := checkAndStartProcesses()

		response := map[string]interface{}{
			"message":   "Process check and start completed",
			"processes": statuses,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Setup proxies
	proxyHandler := func(targetPort string) http.Handler {
		targetURL, _ := url.Parse("http://127.0.0.1:" + targetPort)
		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		return proxy
	}
	mux.Handle("/"+vmms, http.StripPrefix("/"+vmms, proxyHandler(vmmport)))
	mux.Handle("/"+vmpath, http.StripPrefix("/"+vmpath, proxyHandler(vmport)))

	log.Printf("nx-app listening on port %s!\n==============================", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}