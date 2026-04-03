package memory

import (
	"fmt"
	"sync"

	"github.com/ocrosby/identity-platform-go/services/auth-server/internal/domain"
)

// TokenRepository is an in-memory token repository.
type TokenRepository struct {
	mu     sync.RWMutex
	tokens map[string]*domain.Token
}

func NewTokenRepository() *TokenRepository {
	return &TokenRepository{tokens: make(map[string]*domain.Token)}
}

func (r *TokenRepository) Save(token *domain.Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[token.Raw] = token
	return nil
}

func (r *TokenRepository) FindByRaw(raw string) (*domain.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	token, ok := r.tokens[raw]
	if !ok {
		return nil, fmt.Errorf("token not found")
	}
	return token, nil
}

func (r *TokenRepository) Delete(raw string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tokens, raw)
	return nil
}
