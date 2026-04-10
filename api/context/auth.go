package context

import "context"

type authUserIDKey struct{}

func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, authUserIDKey{}, userID)
}

func UserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(authUserIDKey{}).(string)
	return userID, ok
}
