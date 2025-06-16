package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	defaultToken         = "dkcv-xnc-1235-djvjk"
	defaultDbPath        = "/dashboard/data/sqlite.db"
	defaultApiPort       = "8009"
	defaultBackupScript  = "/dashboard/backup.sh"
	maxRetries          = 3
	retryDelay          = 20 * time.Second
)

type UploadRequest struct {
	SUBNAME string `json:"SUBNAME"`
	UUID    string `json:"UUID"`
}

type App struct {
	DB               *sql.DB
	Token            string
	BackupScriptPath string
	ctx              context.Context
	cancel           context.CancelFunc
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func main() {
	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Shutting down gracefully...")
		cancel()
	}()

	token := getEnv("API_TOKEN", defaultToken)
	dbPath := getEnv("DB_PATH", defaultDbPath)
	port := getEnv("API_PORT", defaultApiPort)
	backupScriptPath := getEnv("API_SH", defaultBackupScript)
	listenAddr := ":" + port

	log.Println("--- Application Configuration ---")
	log.Printf("Token:            [Loaded from API_TOKEN or default]")
	log.Printf("Database Path:    %s (env: DB_PATH)", dbPath)
	log.Printf("Listening on:     %s (env: API_PORT)", listenAddr)
	log.Printf("Backup Script:    %s (env: API_SH)", backupScriptPath)
	log.Println("---------------------------------")

	db, err := initDatabase(dbPath)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	defer db.Close()

	app := &App{
		DB:               db,
		Token:            token,
		BackupScriptPath: backupScriptPath,
		ctx:              ctx,
		cancel:           cancel,
	}

	// Create HTTP server with timeouts
	server := &http.Server{
		Addr:         listenAddr,
		Handler:      app.setupRoutes(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("服务器启动，准备在 %s 接受请求...", listenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
	log.Println("Server stopped")
}

func initDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)
	
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	
	log.Println("数据库连接成功。")
	return db, nil
}

func (app *App) setupRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/upload", app.uploadHandler)
	mux.HandleFunc("/health", app.healthHandler)
	return mux
}

func (app *App) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check database connection
	if err := app.DB.Ping(); err != nil {
		http.Error(w, "Database unhealthy", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (app *App) uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持POST方法", http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Query().Get("token") != app.Token {
		http.Error(w, "无效的Token", http.StatusUnauthorized)
		return
	}

	var req UploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("JSON decode error: %v", err)
		http.Error(w, "无效的JSON数据", http.StatusBadRequest)
		return
	}

	if req.UUID == "" || req.SUBNAME == "" {
		http.Error(w, "UUID和SUBNAME字段不能为空", http.StatusBadRequest)
		return
	}

	// Validate input length to prevent potential issues
	if len(req.UUID) > 100 || len(req.SUBNAME) > 255 {
		http.Error(w, "输入数据过长", http.StatusBadRequest)
		return
	}

	go app.processUpload(req)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"message": "请求已接受，正在后台处理"})
}

func (app *App) processUpload(req UploadRequest) {
	log.Printf("开始处理 UUID: %s, SUBNAME: %s", req.UUID, req.SUBNAME)

	var currentName string
	var err error

	// Retry logic with exponential backoff
	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-app.ctx.Done():
			log.Printf("Processing cancelled for UUID: %s", req.UUID)
			return
		default:
		}

		err = app.DB.QueryRow("SELECT name FROM servers WHERE uuid = ?", req.UUID).Scan(&currentName)
		
		if err == nil {
			break // Success
		}
		
		if err != sql.ErrNoRows {
			log.Printf("Database query error for UUID %s (attempt %d): %v", req.UUID, attempt, err)
			return
		}
		
		if attempt < maxRetries {
			log.Printf("UUID: %s 未找到，等待%v后重试... (尝试 %d/%d)", req.UUID, retryDelay, attempt, maxRetries)
			
			select {
			case <-time.After(retryDelay):
				continue
			case <-app.ctx.Done():
				log.Printf("Processing cancelled for UUID: %s", req.UUID)
				return
			}
		}
	}

	if err != nil {
		log.Printf("经过%d次尝试后仍无法找到 UUID %s: %v。操作中止。", maxRetries, req.UUID, err)
		return
	}

	if currentName == req.SUBNAME {
		log.Printf("UUID: %s 的name值已是 %s，无需更新。", req.UUID, req.SUBNAME)
		return
	}

	log.Printf("UUID: %s 的name值不一致 (DB: %s, Req: %s)。准备更新...", req.UUID, currentName, req.SUBNAME)
	
	// Use transaction for update
	tx, err := app.DB.Begin()
	if err != nil {
		log.Printf("开始事务失败 for UUID %s: %v", req.UUID, err)
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec("UPDATE servers SET name = ? WHERE uuid = ?", req.SUBNAME, req.UUID)
	if err != nil {
		log.Printf("更新数据库失败 for UUID %s: %v", req.UUID, err)
		return
	}

	if err = tx.Commit(); err != nil {
		log.Printf("提交事务失败 for UUID %s: %v", req.UUID, err)
		return
	}

	log.Printf("UUID: %s 的name值成功更新为 %s。", req.UUID, req.SUBNAME)
	
	go app.runBackupScript()
}

func (app *App) runBackupScript() {
	select {
	case <-time.After(10 * time.Second):
		log.Println("正在执行备份脚本...")
	case <-app.ctx.Done():
		log.Println("备份脚本执行被取消")
		return
	}

	// Create context with timeout for script execution
	ctx, cancel := context.WithTimeout(app.ctx, 5*time.Minute)
	defer cancel()

	log.Printf("正在执行 %s...", app.BackupScriptPath)
	cmd := exec.CommandContext(ctx, app.BackupScriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("备份脚本执行超时: %s", app.BackupScriptPath)
		} else {
			log.Printf("执行 %s 失败: %v", app.BackupScriptPath, err)
		}
	} else {
		log.Printf("成功执行 %s。", app.BackupScriptPath)
	}
}
