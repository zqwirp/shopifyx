#!/usr/bin/env bash

if [[ -z "$var" ]]; then
    echo "please input your argument(migration name)!"
fi

migrate create -ext sql -dir db/migrations -seq $1