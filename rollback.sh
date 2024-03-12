#!/usr/bin/env bash

migrate -database "postgres://postgres@localhost:5432/shopifyx_sprint?sslmode=disable" -path db/migrations down