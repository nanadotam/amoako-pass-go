package middlewares

import (
	"net/http"
	"strings"

	apicontext "github.com/nanadotam/amoako-pass/go-backend/api/context"
	"github.com/nanadotam/amoako-pass/go-backend/api/respond"
	"github.com/nanadotam/amoako-pass/go-backend/services"
)

type tokenParser interface {
	ParseToken(tokenString string) (string, error)
}

func RequireAuth(tokens tokenParser) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := strings.TrimSpace(r.Header.Get("Authorization"))
			if header == "" {
				respond.Error(w, http.StatusUnauthorized, "missing authorization header")
				return
			}

			const prefix = "Bearer "
			if !strings.HasPrefix(header, prefix) {
				respond.Error(w, http.StatusUnauthorized, "authorization header must use bearer token")
				return
			}

			tokenString := strings.TrimSpace(strings.TrimPrefix(header, prefix))
			userID, err := tokens.ParseToken(tokenString)
			if err != nil {
				respond.Error(w, http.StatusUnauthorized, services.ErrInvalidToken.Error())
				return
			}

			next.ServeHTTP(w, r.WithContext(apicontext.WithUserID(r.Context(), userID)))
		})
	}
}
