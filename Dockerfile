ARG PROG=verifier

FROM golang:1.15.5 AS build
ARG PROG
RUN apt-get update -y && apt-get install -y libtspi-dev
WORKDIR /go/src/RemoteAttestations
COPY . .
RUN mkdir output && \
    mkdir output/bin && \
    mkdir output/configs && \
    go build -o output/bin/$PROG github.com/xcaliburne/RemoteAttestations/cmd/$PROG && \
    cp configs/$PROG.yaml output/configs

FROM ubuntu:latest
ARG PROG
ENV PROG=$PROG
RUN apt-get update -y && apt-get install -y libtspi-dev
WORKDIR /opt/RemoteAttestation
COPY --from=build /go/src/RemoteAttestations/output .
ENTRYPOINT ./bin/${PROG}