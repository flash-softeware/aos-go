package initiator

import (
	"context"
	"fmt"
	"net/http"
)

func registerPlugins(ctx context.Context, cfg Config, pc *PluginContext) error {
	for _, plugin := range cfg.Plugins {
		if plugin == nil {
			continue
		}
		if err := plugin.Register(ctx, pc); err != nil {
			return fmt.Errorf("plugin %q: %w", plugin.Name(), err)
		}
	}
	return nil
}

func applyPluginMiddleware(base http.Handler, plugins []Plugin) http.Handler {
	h := base
	for i := len(plugins) - 1; i >= 0; i-- {
		if mp, ok := plugins[i].(MiddlewarePlugin); ok {
			h = mp.Middleware(h)
		}
	}
	return h
}
