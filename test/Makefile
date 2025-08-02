.PHONY: run sshkey up down tests test

test: sshkey down up tests down

sshkey:
	rm ssh_key ssh_key.pub  || true
	ssh-keygen -t rsa -b 4096 -f ssh_key -P ""

up: sshkey
	docker compose up -d

down:
	docker compose down -v || true

tests:
	go test -v ./...


