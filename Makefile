.PHONY: up down logs ps health build clean

up:
	docker compose up -d db target capture platform

down:
	docker compose down

logs:
	docker compose logs -f

ps:
	docker compose ps

health:
	curl -sf http://localhost:8000/health && echo
	curl -sf http://localhost:8000/health/db && echo

build:
	docker compose build

# Removes containers AND volumes (db data, capture handoff file) — use deliberately
clean:
	docker compose down -v
