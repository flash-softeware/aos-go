package storage

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// CacheRepository defines operations for Redis/Cache
type CacheRepository interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

type RedisStore struct {
	client *redis.Client
}

func NewRedisStore(address, password string, db int) CacheRepository {
	rdb := redis.NewClient(&redis.Options{
		Addr:     address,
		Password: password,
		DB:       db,
	})
	return &RedisStore{client: rdb}
}

func (r *RedisStore) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

func (r *RedisStore) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

func (r *RedisStore) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}
