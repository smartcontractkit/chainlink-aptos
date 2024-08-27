# Build image: Plugins
FROM golang:1.22-bullseye as buildplugins
RUN go version

WORKDIR /build
COPY ./relayer . 
RUN go install ./cmd/chainlink-aptos

FROM smartcontract/chainlink:aptos
COPY --from=buildplugins /go/bin/chainlink-aptos /usr/local/bin/
ENV CL_APTOS_CMD=chainlink-aptos

