package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubTokenParser struct {
	userID string
	err    error
}

func (s stubTokenParser) ParseToken(tokenString string) (string, error) {
	return s.userID, s.err
}

func TestRequireAuthRejectsMissingAuthorizationHeader(t *testing.T) {
	middleware := RequireAuth(stubTokenParser{})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/vault/passwords", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuthPassesRequestWhenTokenIsValid(t *testing.T) {
	middleware := RequireAuth(stubTokenParser{userID: "user-1"})

	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/vault/passwords", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("next handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
