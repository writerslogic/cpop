// Registry manages timestamp provider registration and configuration.
//
// The registry allows users to enable/disable providers and configure
// them independently. Providers are opt-in and disabled by default.

package anchors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Registry manages timestamp providers.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
	enabled   map[string]bool
	configs   map[string]map[string]interface{}
}

// NewRegistry creates a new provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
		enabled:   make(map[string]bool),
		configs:   make(map[string]map[string]interface{}),
	}
}

// RegisterProvider adds a provider to the registry.
// Providers are disabled by default until explicitly enabled.
func (r *Registry) RegisterProvider(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name()] = p
}

// RegisterDefaults registers all built-in providers.
func (r *Registry) RegisterDefaults() {
	// Fully implemented providers
	r.RegisterProvider(NewOpenTimestampsProvider())
	r.RegisterProvider(NewFreeTSAProvider())
	r.RegisterProvider(NewDrandProvider())

	// Scaffolded providers (require configuration)
	r.RegisterProvider(NewEIDASProvider(EIDASConfig{}))
	r.RegisterProvider(NewCFCAProvider(CFCAConfig{}))
	r.RegisterProvider(NewICPBrasilProvider(ICPBrasilConfig{}))
	r.RegisterProvider(NewJNSAProvider(JNSAConfig{}))
	r.RegisterProvider(NewKISAProvider(KISAConfig{}))
	r.RegisterProvider(NewCCAProvider(CCAConfig{}))
	r.RegisterProvider(NewGOSTProvider(GOSTConfig{}))
	r.RegisterProvider(NewZertESProvider(ZertESConfig{}))
	r.RegisterProvider(NewESIGNProvider(ESIGNConfig{}))
	r.RegisterProvider(NewKeybaseProvider(KeybaseConfig{}))
}

// Enable activates a provider with optional configuration.
func (r *Registry) Enable(name string, config map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.providers[name]
	if !ok {
		return fmt.Errorf("unknown provider: %s", name)
	}

	if config != nil {
		if err := p.Configure(config); err != nil {
			return fmt.Errorf("failed to configure %s: %w", name, err)
		}
		r.configs[name] = config
	}

	r.enabled[name] = true
	return nil
}

// Disable deactivates a provider.
func (r *Registry) Disable(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled[name] = false
}

// IsEnabled checks if a provider is enabled.
func (r *Registry) IsEnabled(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled[name]
}

// Get returns a provider by name.
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// EnabledProviders returns all enabled providers.
func (r *Registry) EnabledProviders() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Provider
	for name, enabled := range r.enabled {
		if enabled {
			if p, ok := r.providers[name]; ok {
				result = append(result, p)
			}
		}
	}
	return result
}

// AllProviders returns all registered providers.
func (r *Registry) AllProviders() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		result = append(result, p)
	}
	return result
}

// Timestamp creates timestamps with all enabled providers.
func (r *Registry) Timestamp(ctx context.Context, hash [32]byte) ([]*Proof, error) {
	providers := r.EnabledProviders()
	if len(providers) == 0 {
		return nil, errors.New("no providers enabled")
	}

	var proofs []*Proof
	var errs []error

	for _, p := range providers {
		proof, err := p.Timestamp(ctx, hash)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
			continue
		}
		proofs = append(proofs, proof)
	}

	if len(proofs) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("all providers failed: %v", errs)
	}

	return proofs, nil
}

// TimestampWith creates a timestamp using a specific provider.
func (r *Registry) TimestampWith(ctx context.Context, providerName string, hash [32]byte) (*Proof, error) {
	r.mu.RLock()
	p, ok := r.providers[providerName]
	enabled := r.enabled[providerName]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}
	if !enabled {
		return nil, fmt.Errorf("provider not enabled: %s", providerName)
	}

	return p.Timestamp(ctx, hash)
}

// Verify checks a proof using the appropriate provider.
func (r *Registry) Verify(ctx context.Context, proof *Proof) (*VerifyResult, error) {
	r.mu.RLock()
	p, ok := r.providers[proof.Provider]
	r.mu.RUnlock()

	if !ok {
		// Try to find by prefix (e.g., "rfc3161-freetsa" -> "rfc3161")
		for name, provider := range r.providers {
			if len(proof.Provider) > len(name) && proof.Provider[:len(name)] == name {
				p = provider
				ok = true
				break
			}
		}
	}

	if !ok {
		return nil, fmt.Errorf("no provider found for: %s", proof.Provider)
	}

	return p.Verify(ctx, proof)
}

// Upgrade attempts to upgrade all pending proofs.
func (r *Registry) Upgrade(ctx context.Context, proofs []*Proof) ([]*Proof, error) {
	var upgraded []*Proof

	for _, proof := range proofs {
		if !proof.IsPending() {
			upgraded = append(upgraded, proof)
			continue
		}

		r.mu.RLock()
		p, ok := r.providers[proof.Provider]
		r.mu.RUnlock()

		if !ok {
			upgraded = append(upgraded, proof)
			continue
		}

		newProof, err := p.Upgrade(ctx, proof)
		if err != nil {
			// Keep the old proof if upgrade fails
			upgraded = append(upgraded, proof)
		} else {
			upgraded = append(upgraded, newProof)
		}
	}

	return upgraded, nil
}

// Status returns the status of all providers.
func (r *Registry) Status(ctx context.Context) map[string]*ProviderStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]*ProviderStatus)
	for name, p := range r.providers {
		status, err := p.Status(ctx)
		if err != nil {
			status = &ProviderStatus{
				Available:  false,
				Configured: false,
				LastCheck:  time.Now(),
				Message:    err.Error(),
			}
		}
		result[name] = status
	}

	return result
}

// RegistryConfig is the serializable configuration.
type RegistryConfig struct {
	Enabled map[string]bool                    `json:"enabled"`
	Configs map[string]map[string]interface{} `json:"configs"`
}

// SaveConfig persists the registry configuration.
func (r *Registry) SaveConfig(path string) error {
	r.mu.RLock()
	config := RegistryConfig{
		Enabled: make(map[string]bool),
		Configs: make(map[string]map[string]interface{}),
	}
	for name, enabled := range r.enabled {
		config.Enabled[name] = enabled
	}
	for name, cfg := range r.configs {
		config.Configs[name] = cfg
	}
	r.mu.RUnlock()

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// LoadConfig restores the registry configuration.
func (r *Registry) LoadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No config file is OK
		}
		return err
	}

	var config RegistryConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for name, enabled := range config.Enabled {
		r.enabled[name] = enabled
	}

	for name, cfg := range config.Configs {
		if p, ok := r.providers[name]; ok {
			p.Configure(cfg)
			r.configs[name] = cfg
		}
	}

	return nil
}

// ProvidersForRegion returns providers with legal standing in a region.
func (r *Registry) ProvidersForRegion(region string) []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Provider
	for _, p := range r.providers {
		regions := p.Regions()
		for _, r := range regions {
			if r == region || r == "GLOBAL" {
				result = append(result, p)
				break
			}
		}
	}
	return result
}

// FreeProviders returns providers that don't require payment.
func (r *Registry) FreeProviders() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Provider
	for _, p := range r.providers {
		if !p.RequiresPayment() {
			result = append(result, p)
		}
	}
	return result
}

// QualifiedProviders returns providers with qualified legal standing.
func (r *Registry) QualifiedProviders() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Provider
	for _, p := range r.providers {
		if p.LegalStanding() == StandingQualified {
			result = append(result, p)
		}
	}
	return result
}

// DefaultRegistry is the global registry instance.
var DefaultRegistry = func() *Registry {
	r := NewRegistry()
	r.RegisterDefaults()
	return r
}()
