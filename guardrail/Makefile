COMPOSE = docker compose

.PHONY: up-registry up-app down logs clean

up-registry:
	$(COMPOSE) up -d registry

up-app:
	$(COMPOSE) up -d --build app

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

clean:
	$(COMPOSE) down -v --remove-orphans
