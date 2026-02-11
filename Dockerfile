ARG BASE_IMAGE=chainlink:aptos

# Build image: Plugins
FROM golang:1.25.7-bookworm AS buildplugins
RUN go version

WORKDIR /build
COPY . .
RUN go install ./cmd/chainlink-aptos

# Use the BASE_IMAGE argument in the FROM instruction
FROM ${BASE_IMAGE}
COPY --from=buildplugins /go/bin/chainlink-aptos /usr/local/bin/
ENV CL_APTOS_CMD chainlink-aptos
