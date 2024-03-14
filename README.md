# shopifyx

## Database Migration

### Initialize db migration directory

```
mkdir db/migrations
```

### Create an sql migration file

```
migrate create -ext sql -dir db/migrations -seq add_user_table
```

another example:

```
migrate create -ext sql -dir db/migrations -seq alter_user_table
migrate create -ext sql -dir db/migrations -seq add_product_table
migrate create -ext sql -dir db/migrations -seq drop_user_table
```

### Migrate

migrate up:

```
migrate -database "postgres://postgres@localhost:5432/shopifyx_sprint?sslmode=disable" -path db/migrations up
```

migrate down:

```
migrate -database "postgres://postgres@localhost:5432/shopifyx_sprint?sslmode=disable" -path db/migrations down
```