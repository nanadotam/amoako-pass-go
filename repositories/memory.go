package repositories

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type memoryState struct {
	mu sync.RWMutex

	users           map[string]User
	userIDsByEmail  map[string]string
	userIDsByName   map[string]string
	sessions        map[string]Session
	sessionIDsByTok map[string]string
	passwords       map[string]PasswordRecord
	wifi            map[string]WifiRecord
	categories      map[string]Category
	auditLogs       map[string]AuditLog
	auditUserIDs    map[string]string
}

type MemoryStores struct {
	Users        *memUserStore
	Sessions     *memSessionStore
	Passwords    *memPasswordStore
	Wifi         *memWifiStore
	Categories   *memCategoryStore
	Audit        *memAuditStore
	LoginHistory *memLoginHistoryStore
}

type memUserStore struct {
	state *memoryState
}

type memSessionStore struct {
	state *memoryState
}

type memPasswordStore struct {
	state *memoryState
}

type memWifiStore struct {
	state *memoryState
}

type memCategoryStore struct {
	state *memoryState
}

type memAuditStore struct {
	state *memoryState
}

func NewMemoryStores() *MemoryStores {
	state := &memoryState{
		users:           make(map[string]User),
		userIDsByEmail:  make(map[string]string),
		userIDsByName:   make(map[string]string),
		sessions:        make(map[string]Session),
		sessionIDsByTok: make(map[string]string),
		passwords:       make(map[string]PasswordRecord),
		wifi:            make(map[string]WifiRecord),
		categories:      make(map[string]Category),
		auditLogs:       make(map[string]AuditLog),
		auditUserIDs:    make(map[string]string),
	}

	return &MemoryStores{
		Users:        &memUserStore{state: state},
		Sessions:     &memSessionStore{state: state},
		Passwords:    &memPasswordStore{state: state},
		Wifi:         &memWifiStore{state: state},
		Categories:   &memCategoryStore{state: state},
		Audit:        &memAuditStore{state: state},
		LoginHistory: &memLoginHistoryStore{},
	}
}

func (r *memUserStore) Create(_ context.Context, email, username, firstName, lastName, passwordHash string) (*User, error) {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	emailKey := strings.ToLower(strings.TrimSpace(email))
	usernameKey := strings.ToLower(strings.TrimSpace(username))
	if _, exists := r.state.userIDsByEmail[emailKey]; exists {
		return nil, ErrUserConflict
	}
	if _, exists := r.state.userIDsByName[usernameKey]; exists {
		return nil, ErrUserConflict
	}

	now := time.Now()
	user := User{
		ID:           uuid.New().String(),
		Email:        email,
		Username:     username,
		FirstName:    nullableString(firstName),
		LastName:     nullableString(lastName),
		PasswordHash: passwordHash,
		CreatedAt:    now,
	}

	r.state.users[user.ID] = user
	r.state.userIDsByEmail[emailKey] = user.ID
	r.state.userIDsByName[usernameKey] = user.ID

	copyUser := user
	return &copyUser, nil
}

func (r *memUserStore) FindByEmail(_ context.Context, email string) (*User, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	userID, exists := r.state.userIDsByEmail[strings.ToLower(strings.TrimSpace(email))]
	if !exists {
		return nil, ErrUserNotFound
	}

	user := r.state.users[userID]
	copyUser := user
	return &copyUser, nil
}

func (r *memUserStore) FindByID(_ context.Context, userID string) (*User, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	user, exists := r.state.users[userID]
	if !exists {
		return nil, ErrUserNotFound
	}

	copyUser := user
	return &copyUser, nil
}

func (r *memUserStore) UpdateLastLogin(_ context.Context, userID string) error {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	if _, exists := r.state.users[userID]; !exists {
		return ErrUserNotFound
	}

	return nil
}

func (r *memUserStore) UpdatePasswordHash(_ context.Context, userID, passwordHash string) error {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	user, exists := r.state.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	user.PasswordHash = passwordHash
	r.state.users[userID] = user
	return nil
}

func (r *memUserStore) Profile(_ context.Context, userID string) (*UserProfile, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	user, exists := r.state.users[userID]
	if !exists {
		return nil, ErrUserNotFound
	}

	passwordCount := 0
	totalStrength := 0
	for _, record := range r.state.passwords {
		if record.UserID != userID {
			continue
		}
		passwordCount++
		totalStrength += record.PasswordStrength
	}

	wifiCount := 0
	for _, item := range r.state.wifi {
		if item.UserID == userID {
			wifiCount++
		}
	}

	categoryCount := 0
	for _, category := range r.state.categories {
		if category.UserID == userID {
			categoryCount++
		}
	}

	securityScore := 0
	if passwordCount > 0 {
		securityScore = totalStrength / passwordCount
	}

	return &UserProfile{
		ID:            user.ID,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Name:          user.Username,
		Email:         user.Email,
		PasswordCount: passwordCount,
		WifiCount:     wifiCount,
		CategoryCount: categoryCount,
		SecurityScore: securityScore,
		MemberSince:   user.CreatedAt,
	}, nil
}

func (r *memSessionStore) Create(_ context.Context, params SessionCreateParams) (*Session, error) {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	now := time.Now()
	session := Session{
		ID:           uuid.New().String(),
		UserID:       params.UserID,
		Token:        params.Token,
		IP:           cloneStringPtr(params.IP),
		UserAgent:    cloneStringPtr(params.UserAgent),
		ExpiresAt:    params.ExpiresAt,
		CreatedAt:    now,
		LastAccessed: now,
		IsActive:     true,
	}

	r.state.sessions[session.ID] = session
	r.state.sessionIDsByTok[session.Token] = session.ID

	copySession := cloneSession(session)
	return &copySession, nil
}

func (r *memSessionStore) FindByToken(_ context.Context, token string) (*Session, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	sessionID, exists := r.state.sessionIDsByTok[token]
	if !exists {
		return nil, ErrSessionNotFound
	}

	session, exists := r.state.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	copySession := cloneSession(session)
	return &copySession, nil
}

func (r *memSessionStore) RevokeByToken(_ context.Context, token string) error {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	sessionID, exists := r.state.sessionIDsByTok[token]
	if !exists {
		return ErrSessionNotFound
	}

	session, exists := r.state.sessions[sessionID]
	if !exists || !session.IsActive {
		return ErrSessionNotFound
	}

	session.IsActive = false
	session.LastAccessed = time.Now()
	r.state.sessions[sessionID] = session
	return nil
}

func (r *memSessionStore) Rotate(ctx context.Context, oldToken string, params SessionCreateParams) (*Session, error) {
	if err := r.RevokeByToken(ctx, oldToken); err != nil {
		return nil, err
	}

	return r.Create(ctx, params)
}

func (r *memSessionStore) ListByUser(_ context.Context, userID string) ([]Session, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	items := make([]Session, 0)
	for _, session := range r.state.sessions {
		if session.UserID == userID && session.IsActive {
			items = append(items, cloneSession(session))
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].LastAccessed.Equal(items[j].LastAccessed) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].LastAccessed.After(items[j].LastAccessed)
	})

	return items, nil
}

func (r *memSessionStore) RevokeByID(_ context.Context, userID, sessionID string) error {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	session, exists := r.state.sessions[sessionID]
	if !exists || session.UserID != userID || !session.IsActive {
		return ErrSessionNotFound
	}

	session.IsActive = false
	session.LastAccessed = time.Now()
	r.state.sessions[sessionID] = session
	return nil
}

func (r *memPasswordStore) ListByUser(_ context.Context, options PasswordListOptions) ([]PasswordRecord, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	search := strings.ToLower(strings.TrimSpace(options.Search))
	items := make([]PasswordRecord, 0)
	for _, record := range r.state.passwords {
		if record.UserID != options.UserID {
			continue
		}
		if options.CategoryID != "" && derefString(record.CategoryID) != options.CategoryID {
			continue
		}
		if search != "" {
			website := strings.ToLower(record.Website)
			username := strings.ToLower(derefString(record.Username))
			email := strings.ToLower(derefString(record.Email))
			if !strings.Contains(website, search) && !strings.Contains(username, search) && !strings.Contains(email, search) {
				continue
			}
		}
		items = append(items, clonePasswordRecord(record))
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})

	return items, nil
}

func (r *memPasswordStore) FindByID(_ context.Context, userID, passwordID string) (*PasswordRecord, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	record, exists := r.state.passwords[passwordID]
	if !exists || record.UserID != userID {
		return nil, ErrPasswordNotFound
	}

	copyRecord := clonePasswordRecord(record)
	return &copyRecord, nil
}

func (r *memPasswordStore) Create(_ context.Context, params PasswordCreateParams) (*PasswordRecord, error) {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	now := time.Now()
	record := PasswordRecord{
		ID:                uuid.New().String(),
		UserID:            params.UserID,
		CategoryID:        cloneStringPtr(params.CategoryID),
		Website:           params.Website,
		Username:          cloneStringPtr(params.Username),
		Email:             cloneStringPtr(params.Email),
		PasswordEncrypted: params.PasswordEncrypted,
		NotesEncrypted:    cloneStringPtr(params.NotesEncrypted),
		URL:               cloneStringPtr(params.URL),
		IsFavorite:        params.IsFavorite,
		PasswordStrength:  params.PasswordStrength,
		Tags:              cloneStringSlice(params.Tags),
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	r.state.passwords[record.ID] = record

	copyRecord := clonePasswordRecord(record)
	return &copyRecord, nil
}

func (r *memPasswordStore) Update(_ context.Context, params PasswordUpdateParams) (*PasswordRecord, error) {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	record, exists := r.state.passwords[params.ID]
	if !exists || record.UserID != params.UserID {
		return nil, ErrPasswordNotFound
	}

	record.CategoryID = cloneStringPtr(params.CategoryID)
	record.Website = params.Website
	record.Username = cloneStringPtr(params.Username)
	record.Email = cloneStringPtr(params.Email)
	record.PasswordEncrypted = params.PasswordEncrypted
	record.NotesEncrypted = cloneStringPtr(params.NotesEncrypted)
	record.URL = cloneStringPtr(params.URL)
	record.IsFavorite = params.IsFavorite
	record.PasswordStrength = params.PasswordStrength
	record.Tags = cloneStringSlice(params.Tags)
	record.UpdatedAt = time.Now()
	r.state.passwords[record.ID] = record

	copyRecord := clonePasswordRecord(record)
	return &copyRecord, nil
}

func (r *memPasswordStore) Delete(_ context.Context, userID, passwordID string) error {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	record, exists := r.state.passwords[passwordID]
	if !exists || record.UserID != userID {
		return ErrPasswordNotFound
	}

	delete(r.state.passwords, passwordID)
	return nil
}

func (r *memWifiStore) ListByUser(_ context.Context, userID string) ([]WifiRecord, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	items := make([]WifiRecord, 0)
	for _, record := range r.state.wifi {
		if record.UserID == userID {
			items = append(items, cloneWifiRecord(record))
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})

	return items, nil
}

func (r *memWifiStore) FindByID(_ context.Context, userID, wifiID string) (*WifiRecord, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	record, exists := r.state.wifi[wifiID]
	if !exists || record.UserID != userID {
		return nil, ErrWifiNotFound
	}

	copyRecord := cloneWifiRecord(record)
	return &copyRecord, nil
}

func (r *memWifiStore) Create(_ context.Context, params WifiCreateParams) (*WifiRecord, error) {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	now := time.Now()
	record := WifiRecord{
		ID:                uuid.New().String(),
		UserID:            params.UserID,
		NetworkName:       params.NetworkName,
		PasswordEncrypted: params.PasswordEncrypted,
		SecurityType:      params.SecurityType,
		NotesEncrypted:    cloneStringPtr(params.NotesEncrypted),
		Location:          cloneStringPtr(params.Location),
		IsFavorite:        params.IsFavorite,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	r.state.wifi[record.ID] = record

	copyRecord := cloneWifiRecord(record)
	return &copyRecord, nil
}

func (r *memWifiStore) Update(_ context.Context, params WifiUpdateParams) (*WifiRecord, error) {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	record, exists := r.state.wifi[params.ID]
	if !exists || record.UserID != params.UserID {
		return nil, ErrWifiNotFound
	}

	record.NetworkName = params.NetworkName
	record.PasswordEncrypted = params.PasswordEncrypted
	record.SecurityType = params.SecurityType
	record.NotesEncrypted = cloneStringPtr(params.NotesEncrypted)
	record.Location = cloneStringPtr(params.Location)
	record.IsFavorite = params.IsFavorite
	record.UpdatedAt = time.Now()
	r.state.wifi[record.ID] = record

	copyRecord := cloneWifiRecord(record)
	return &copyRecord, nil
}

func (r *memWifiStore) Delete(_ context.Context, userID, wifiID string) error {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	record, exists := r.state.wifi[wifiID]
	if !exists || record.UserID != userID {
		return ErrWifiNotFound
	}

	delete(r.state.wifi, wifiID)
	return nil
}

func (r *memCategoryStore) ListByUser(_ context.Context, userID string) ([]Category, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	items := make([]Category, 0)
	for _, category := range r.state.categories {
		if category.UserID == userID {
			items = append(items, cloneCategory(category))
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDefault != items[j].IsDefault {
			return items[i].IsDefault
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	return items, nil
}

func (r *memCategoryStore) Create(_ context.Context, params CategoryParams) (*Category, error) {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	for _, category := range r.state.categories {
		if category.UserID == params.UserID && strings.EqualFold(category.Name, params.Name) {
			return nil, ErrUserConflict
		}
	}

	now := time.Now()
	category := Category{
		ID:        uuid.New().String(),
		UserID:    params.UserID,
		Name:      params.Name,
		Color:     cloneStringPtr(params.Color),
		Icon:      cloneStringPtr(params.Icon),
		IsDefault: false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	r.state.categories[category.ID] = category

	copyCategory := cloneCategory(category)
	return &copyCategory, nil
}

func (r *memCategoryStore) Update(_ context.Context, params CategoryUpdateParams) (*Category, error) {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	category, exists := r.state.categories[params.ID]
	if !exists || category.UserID != params.UserID {
		return nil, ErrCategoryNotFound
	}

	for _, existing := range r.state.categories {
		if existing.UserID == params.UserID && existing.ID != params.ID && strings.EqualFold(existing.Name, params.Name) {
			return nil, ErrUserConflict
		}
	}

	category.Name = params.Name
	category.Color = cloneStringPtr(params.Color)
	category.Icon = cloneStringPtr(params.Icon)
	category.UpdatedAt = time.Now()
	r.state.categories[category.ID] = category

	copyCategory := cloneCategory(category)
	return &copyCategory, nil
}

func (r *memCategoryStore) Delete(_ context.Context, userID, categoryID string) error {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	category, exists := r.state.categories[categoryID]
	if !exists || category.UserID != userID || category.IsDefault {
		return ErrCategoryNotFound
	}

	delete(r.state.categories, categoryID)
	return nil
}

func (r *memAuditStore) Create(_ context.Context, params AuditLogCreateParams) error {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()

	id := uuid.New().String()
	record := AuditLog{
		ID:           id,
		Action:       params.Action,
		ResourceType: cloneStringPtr(params.ResourceType),
		ResourceID:   cloneStringPtr(params.ResourceID),
		IP:           cloneStringPtr(params.IP),
		UserAgent:    cloneStringPtr(params.UserAgent),
		Details:      cloneRawJSON(params.Details),
		CreatedAt:    time.Now(),
	}

	r.state.auditLogs[id] = record
	r.state.auditUserIDs[id] = params.UserID
	return nil
}

func (r *memAuditStore) ListByUser(_ context.Context, options AuditLogListOptions) ([]AuditLog, error) {
	r.state.mu.RLock()
	defer r.state.mu.RUnlock()

	if options.Page < 1 {
		options.Page = 1
	}
	if options.PerPage < 1 {
		options.PerPage = 20
	}

	items := make([]AuditLog, 0)
	for _, log := range r.state.auditLogs {
		if !belongsToUser(r.state, log.ID, options.UserID) {
			continue
		}
		if options.Action != "" && log.Action != options.Action {
			continue
		}
		items = append(items, cloneAuditLog(log))
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})

	start := (options.Page - 1) * options.PerPage
	if start >= len(items) {
		return []AuditLog{}, nil
	}

	end := start + options.PerPage
	if end > len(items) {
		end = len(items)
	}

	return items[start:end], nil
}

func belongsToUser(state *memoryState, auditID, userID string) bool {
	return state.auditUserIDs[auditID] == userID
}

func cloneStringPtr(value *string) *string {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	copyValues := make([]string, len(values))
	copy(copyValues, values)
	return copyValues
}

func cloneRawJSON(value []byte) json.RawMessage {
	if len(value) == 0 {
		return json.RawMessage(`{}`)
	}
	copyValue := make([]byte, len(value))
	copy(copyValue, value)
	return json.RawMessage(copyValue)
}

func cloneSession(session Session) Session {
	session.IP = cloneStringPtr(session.IP)
	session.UserAgent = cloneStringPtr(session.UserAgent)
	return session
}

func clonePasswordRecord(record PasswordRecord) PasswordRecord {
	record.CategoryID = cloneStringPtr(record.CategoryID)
	record.Username = cloneStringPtr(record.Username)
	record.Email = cloneStringPtr(record.Email)
	record.NotesEncrypted = cloneStringPtr(record.NotesEncrypted)
	record.URL = cloneStringPtr(record.URL)
	record.Tags = cloneStringSlice(record.Tags)
	return record
}

func cloneWifiRecord(record WifiRecord) WifiRecord {
	record.NotesEncrypted = cloneStringPtr(record.NotesEncrypted)
	record.Location = cloneStringPtr(record.Location)
	return record
}

func cloneCategory(category Category) Category {
	category.Color = cloneStringPtr(category.Color)
	category.Icon = cloneStringPtr(category.Icon)
	return category
}

func cloneAuditLog(log AuditLog) AuditLog {
	log.ResourceType = cloneStringPtr(log.ResourceType)
	log.ResourceID = cloneStringPtr(log.ResourceID)
	log.IP = cloneStringPtr(log.IP)
	log.UserAgent = cloneStringPtr(log.UserAgent)
	log.Details = cloneRawJSON(log.Details)
	return log
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// memLoginHistoryStore is an in-memory no-op store used in no-DB mode.
type memLoginHistoryStore struct{}

func (r *memLoginHistoryStore) Create(_ context.Context, _ LoginHistoryCreateParams) (*LoginHistoryRecord, error) {
	return &LoginHistoryRecord{}, nil
}

func (r *memLoginHistoryStore) ListByUser(_ context.Context, _ string, _ int) ([]LoginHistoryRecord, error) {
	return []LoginHistoryRecord{}, nil
}

func (r *memLoginHistoryStore) SetTrusted(_ context.Context, _, _ string, _ bool) error {
	return ErrLoginHistoryNotFound
}

func (r *memLoginHistoryStore) Delete(_ context.Context, _, _ string) error {
	return ErrLoginHistoryNotFound
}

func (r *memLoginHistoryStore) ClearByUser(_ context.Context, _ string) error {
	return nil
}
