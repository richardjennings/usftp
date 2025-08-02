.PHONY: test

test:
	bash test.sh

test-setup:
	rm ssh_key ssh_key.pub  || true
	ssh-keygen -t rsa -b 4096 -f ssh_key -P ""
	docker compose down -v || true
	docker compose up -d

test-setdown:
	docker compose up -d || true
	rm ssh_key ssh_key.pub  || true
