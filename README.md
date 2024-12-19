# Aptos
Local development and tests how to

### Local development

#### Pre requisites

    - Geth

1. Navigate to `integration tests`
2. Run `go run main.go build`. This will build core locally and expose it as `chainlink-aptos:latest`
    - You can optionally set the `--dir` flag to overwrite the core directory and skip cloning it
    - Check `.example.env` for the requirements. You need `CORE_REPO` and `CORE_REF` exported or in `.env`
3. Run `go run main.go deploy`
    - This will deploy everything locally and explose the ports so you can access the nodes and logs
    - You need the env vars from `.example.env` with the information and images

### Integration tests
1. `cp .example.env .env`
2. `cd integration-tests/smoke`
3. `go test`

### Custom images on PRs
If you want to test the CI with a custom core image you need to specify in the PR body either the commit sha or branch name in the following format `core_ref:<sha>;` e.g `core_ref:develop;`. 
_Note:_ Develop does not work until the core aptos-init branch is merged
