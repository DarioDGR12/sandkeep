package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// OpenPostgres opens DATABASE_URL with pgx and returns a SQLSink that
// creates warden_audit on first write.
func OpenPostgres(dsn string) (*SQLSink, *sql.DB, error) {
	if dsn == "" {
		return nil, nil, fmt.Errorf("audit postgres: empty DSN")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("audit postgres: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("audit postgres ping: %w", err)
	}
	sink := &SQLSink{
		DB: StdSQL{Do: func(ctx context.Context, query string, args ...any) error {
			_, err := db.ExecContext(ctx, query, args...)
			return err
		}},
		EnsureSchema: true,
		Timeout:      5 * time.Second,
	}
	return sink, db, nil
}
