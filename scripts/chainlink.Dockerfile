ARG BASE_IMAGE=smartcontract/chainlink:aptos
ARG ROOT=.

# Build image: Plugins
FROM golang:1.22-bullseye as buildplugins
RUN go version

WORKDIR /build
RUN ls ${ROOT}
COPY ${ROOT}/relayer . 
RUN go install ./cmd/chainlink-aptos

# Use the BASE_IMAGE argument in the FROM instruction
FROM ${BASE_IMAGE}
COPY --from=buildplugins /go/bin/chainlink-aptos /usr/local/bin/
ENV CL_APTOS_CMD chainlink-aptos
