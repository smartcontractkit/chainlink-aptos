ARG BASE_IMAGE=chainlink:aptos

# Build image: Plugins
FROM golang:1.22-bullseye as buildplugins
RUN go version

WORKDIR /build
COPY relayer . 
RUN go install ./cmd/chainlink-aptos

# Use the BASE_IMAGE argument in the FROM instruction
FROM ${BASE_IMAGE}
COPY --from=buildplugins /go/bin/chainlink-aptos /usr/local/bin/
ENV CL_APTOS_CMD chainlink-aptos
