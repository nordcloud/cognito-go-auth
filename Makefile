build:
	env GOOS=linux go build -ldflags="-s -w" -o bin/cognito-auth main.go

run: build
	./bin/cognito-auth

