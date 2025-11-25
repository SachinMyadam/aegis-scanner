import os

# 1. docker-compose.yml (FIX: Removed sandbox volume mount to prevent hiding node_modules)
docker_compose_yml = """services:
  api:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: threat_scanner_api
    env_file:
      - .env
    ports:
      - "8000:8000"
    depends_on:
      - db
      - redis
      - sandbox
    restart: unless-stopped
    volumes:
      - ./backend:/app

  db:
    image: postgres:15-alpine
    container_name: threat_scanner_db
    env_file:
      - .env
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    restart: unless-stopped
    ports:
      - "5433:5432"

  redis:
    image: redis:7-alpine
    container_name: threat_scanner_redis
    ports:
      - "6379:6379"
    restart: unless-stopped

  sandbox:
    build:
      context: ./sandbox
      dockerfile: Dockerfile
    container_name: threat_scanner_sandbox
    restart: unless-stopped
    # FIX: We removed the 'volumes' mount here so the container uses
    # the internal node_modules we installed during build.

volumes:
  postgres_data:
"""

# Write the file
file_map = {
    "docker-compose.yml": docker_compose_yml,
}

print("Fixing docker-compose.yml...")
for path, content in file_map.items():
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Updated: {path}")

print("\nSuccess! Volume mount issue fixed.")
