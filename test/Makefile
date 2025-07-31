.PHONY: run sshkey up down

sshkey:
	rm ssh_key ssh_key.pub  || true
	ssh-keygen -t rsa -b 4096 -f ssh_key -P ""

up: sshkey
	docker compose up -d

down:
	docker compose down -v

test:
	go test ./...

run: sshkey up test down
