ARG BASE_IMAGE=795953128386.dkr.ecr.us-west-2.amazonaws.com/chainlink:b5e7d373d2ca65e6ada2214f0c67a0773ece1cab-plugins

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
