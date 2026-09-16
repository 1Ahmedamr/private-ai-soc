# Installation

## Requirements
- Docker + Docker Compose (Docker Desktop on Mac/Windows)
- ~6GB free disk space for the qwen3:8b model

## Setup
1. Clone the repo
2. `cd docker && docker compose up -d --build`
3. Pull the AI model (one-time, ~5GB download):
   `docker exec -it soc_ollama ollama pull qwen3:8b`
4. Verify: `curl http://localhost:11434/api/tags` should list qwen3:8b

## What's automated vs manual
- Postgres: fully automated, starts with correct schema on first run
- Ollama: container starts automatically, but the MODEL must be pulled
  manually once (step 3) - this is a deliberate choice, not an
  oversight, since baking a 5GB model into the app image would make
  every build slow and bloated.

## Running the pipeline
- `docker exec -it docker-soc_app-1 python -m scripts.seed_dashboard_data`
- `docker exec -it docker-soc_app-1 python -m scripts.dashboard`


## Dashboard Authentication

The web dashboard requires HTTP Basic Auth. Set real credentials via
environment variables before running:

    export DASHBOARD_USERNAME=youranalystname
    export DASHBOARD_PASSWORD=a-real-password-not-changeme

If unset, defaults to username "analyst" / password "changeme" - this
default is for local development convenience ONLY and must be changed
before exposing the dashboard on any shared network.
