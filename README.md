# Login registration backend
## Installation
### Install Instructions
1. Clone this repository.
2. Install Docker Engine from [this link](https://docs.docker.com/engine/install/).
3. Install Docker Compose from [this link](https://docs.docker.com/compose/install/).

## Development
All commands in this section assume that you have installed `docker` and `docker-compose`.
### Running tests
Run the command `docker-compose -f docker-compose-test.yml up --build` at the project root to run the tests of this project.

### Deploying stages
Run the command `docker-compose -f [STAGE] up --build` at the project root to run the application.

Current stages:
1. development `[docker-compose-dev.yml]`
2. production `[docker-compose-prod.yml]`

## Accessing
You can access the API under [localhost:8080](http://localhost:8080).

You can access the PostgreSQL database directly under `localhost:5432`.
