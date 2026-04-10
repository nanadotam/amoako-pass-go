package main

import (
	"log"
	"net/http"
	"time"

	"github.com/nanadotam/amoako-pass/go-backend/api/handlers"
	"github.com/nanadotam/amoako-pass/go-backend/api/middlewares"
	"github.com/nanadotam/amoako-pass/go-backend/config"
	"github.com/nanadotam/amoako-pass/go-backend/repositories"
	"github.com/nanadotam/amoako-pass/go-backend/services"
	"github.com/nanadotam/amoako-pass/go-backend/storage"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := storage.ConnectDBWithMode(cfg.DBURL, cfg.NoDB)
	if err != nil {
		log.Fatalf("connect db: %v", err)
	}
	if db != nil {
		defer db.Close()
	}

	tokenService := services.NewTokenService(cfg.JWTSecret, cfg.AccessTokenTTL)
	encryptionService := services.NewEncryptionService(cfg.EncryptionKey)
	loginRateLimiter := services.NewRateLimiter(5, 10*time.Minute)

	var (
		authService        *services.AuthService
		vaultService       *services.VaultService
		categoryService    *services.CategoryService
		wifiService        *services.WifiService
		userService        *services.UserService
		sessionService     *services.SessionService
		auditService       *services.AuditService
		maintenanceService *services.MaintenanceService
		transferService    *services.TransferService
	)

	if cfg.NoDB {
		memStores := repositories.NewMemoryStores()
		authService = services.NewAuthService(
			memStores.Users,
			memStores.Sessions,
			tokenService,
			cfg.AccessTokenTTL,
			cfg.RefreshTokenTTL,
			cfg.RequestTimeout,
		)
		vaultService = services.NewVaultService(memStores.Passwords, memStores.Categories, encryptionService, cfg.RequestTimeout)
		categoryService = services.NewCategoryService(memStores.Categories, cfg.RequestTimeout)
		wifiService = services.NewWifiService(memStores.Wifi, encryptionService, cfg.RequestTimeout)
		userService = services.NewUserService(memStores.Users, cfg.RequestTimeout)
		sessionService = services.NewSessionService(memStores.Sessions, cfg.RequestTimeout)
		auditService = nil
		maintenanceService = nil
		transferService = services.NewTransferService(vaultService, wifiService, encryptionService, cfg.RequestTimeout)
	} else {
		userRepository := repositories.NewUserRepository(db)
		passwordRepository := repositories.NewPasswordRepository(db)
		sessionRepository := repositories.NewSessionRepository(db)
		categoryRepository := repositories.NewCategoryRepository(db)
		wifiRepository := repositories.NewWifiRepository(db)
		auditRepository := repositories.NewAuditLogRepository(db)

		authService = services.NewAuthService(
			userRepository,
			sessionRepository,
			tokenService,
			cfg.AccessTokenTTL,
			cfg.RefreshTokenTTL,
			cfg.RequestTimeout,
		)
		vaultService = services.NewVaultService(passwordRepository, categoryRepository, encryptionService, cfg.RequestTimeout)
		categoryService = services.NewCategoryService(categoryRepository, cfg.RequestTimeout)
		wifiService = services.NewWifiService(wifiRepository, encryptionService, cfg.RequestTimeout)
		userService = services.NewUserService(userRepository, cfg.RequestTimeout)
		sessionService = services.NewSessionService(sessionRepository, cfg.RequestTimeout)
		auditService = services.NewAuditService(auditRepository, cfg.RequestTimeout)
		maintenanceService = services.NewMaintenanceService(passwordRepository, wifiRepository, encryptionService, cfg.RequestTimeout)
		transferService = services.NewTransferService(vaultService, wifiService, encryptionService, cfg.RequestTimeout)
	}

	hibpService := services.NewHIBPService(cfg.RequestTimeout)

	healthHandler := handlers.NewHealthHandler(db, cfg.AppVersion)
	authHandler := handlers.NewAuthHandler(authService, maintenanceService, auditService, loginRateLimiter)
	vaultHandler := handlers.NewVaultHandler(vaultService, maintenanceService, transferService, auditService)
	categoryHandler := handlers.NewCategoryHandler(categoryService)
	wifiHandler := handlers.NewWifiHandler(wifiService, auditService)
	userHandler := handlers.NewUserHandler(userService, sessionService)
	auditHandler := handlers.NewAuditHandler(auditService)
	utilityHandler := handlers.NewUtilityHandler(hibpService)

	requireAuth := middlewares.RequireAuth(tokenService)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", healthHandler.Check)
	mux.HandleFunc("POST /api/v1/auth/register", authHandler.Register)
	mux.HandleFunc("POST /api/v1/auth/login", authHandler.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", authHandler.Refresh)
	mux.Handle("POST /api/v1/auth/logout", requireAuth(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("POST /api/v1/auth/change-password", requireAuth(http.HandlerFunc(authHandler.ChangePassword)))

	mux.Handle("GET /api/v1/vault/passwords", requireAuth(http.HandlerFunc(vaultHandler.ListPasswords)))
	mux.Handle("POST /api/v1/vault/passwords", requireAuth(http.HandlerFunc(vaultHandler.CreatePassword)))
	mux.Handle("GET /api/v1/vault/passwords/{id}", requireAuth(http.HandlerFunc(vaultHandler.GetPassword)))
	mux.Handle("PUT /api/v1/vault/passwords/{id}", requireAuth(http.HandlerFunc(vaultHandler.UpdatePassword)))
	mux.Handle("DELETE /api/v1/vault/passwords/{id}", requireAuth(http.HandlerFunc(vaultHandler.DeletePassword)))
	mux.Handle("PUT /api/v1/vault/rekey", requireAuth(http.HandlerFunc(vaultHandler.Rekey)))
	mux.Handle("GET /api/v1/vault/export", requireAuth(http.HandlerFunc(vaultHandler.Export)))
	mux.Handle("POST /api/v1/vault/import", requireAuth(http.HandlerFunc(vaultHandler.Import)))

	mux.Handle("GET /api/v1/vault", requireAuth(http.HandlerFunc(vaultHandler.FlutterListPasswords)))
	mux.Handle("POST /api/v1/vault", requireAuth(http.HandlerFunc(vaultHandler.FlutterCreatePassword)))
	mux.Handle("GET /api/v1/vault/{id}", requireAuth(http.HandlerFunc(vaultHandler.FlutterGetPassword)))
	mux.Handle("PUT /api/v1/vault/{id}", requireAuth(http.HandlerFunc(vaultHandler.FlutterUpdatePassword)))
	mux.Handle("DELETE /api/v1/vault/{id}", requireAuth(http.HandlerFunc(vaultHandler.DeletePassword)))

	mux.Handle("GET /api/v1/vault/wifi", requireAuth(http.HandlerFunc(wifiHandler.List)))
	mux.Handle("POST /api/v1/vault/wifi", requireAuth(http.HandlerFunc(wifiHandler.Create)))
	mux.Handle("GET /api/v1/vault/wifi/{id}", requireAuth(http.HandlerFunc(wifiHandler.Get)))
	mux.Handle("PUT /api/v1/vault/wifi/{id}", requireAuth(http.HandlerFunc(wifiHandler.Update)))
	mux.Handle("DELETE /api/v1/vault/wifi/{id}", requireAuth(http.HandlerFunc(wifiHandler.Delete)))

	mux.Handle("GET /api/v1/wifi", requireAuth(http.HandlerFunc(wifiHandler.FlutterList)))
	mux.Handle("POST /api/v1/wifi", requireAuth(http.HandlerFunc(wifiHandler.FlutterCreate)))
	mux.Handle("GET /api/v1/wifi/{id}", requireAuth(http.HandlerFunc(wifiHandler.FlutterGet)))
	mux.Handle("PUT /api/v1/wifi/{id}", requireAuth(http.HandlerFunc(wifiHandler.FlutterUpdate)))
	mux.Handle("DELETE /api/v1/wifi/{id}", requireAuth(http.HandlerFunc(wifiHandler.Delete)))

	mux.Handle("GET /api/v1/categories", requireAuth(http.HandlerFunc(categoryHandler.List)))
	mux.Handle("POST /api/v1/categories", requireAuth(http.HandlerFunc(categoryHandler.Create)))
	mux.Handle("PUT /api/v1/categories/{id}", requireAuth(http.HandlerFunc(categoryHandler.Update)))
	mux.Handle("DELETE /api/v1/categories/{id}", requireAuth(http.HandlerFunc(categoryHandler.Delete)))

	mux.Handle("GET /api/v1/user/profile", requireAuth(http.HandlerFunc(userHandler.Profile)))
	mux.Handle("GET /api/v1/user/sessions", requireAuth(http.HandlerFunc(userHandler.Sessions)))
	mux.Handle("DELETE /api/v1/user/sessions/{id}", requireAuth(http.HandlerFunc(userHandler.RevokeSession)))

	mux.Handle("GET /api/v1/audit/logs", requireAuth(http.HandlerFunc(auditHandler.List)))
	mux.Handle("POST /api/v1/util/hibp-check", requireAuth(http.HandlerFunc(utilityHandler.HIBPCheck)))

	handler := middlewares.CORS(cfg.CORSAllowedOrigins)(mux)

	server := &http.Server{
		Addr:              cfg.ServerAddr,
		Handler:           handler,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	log.Printf("server listening on %s", cfg.ServerAddr)
	log.Fatal(server.ListenAndServe())
}
