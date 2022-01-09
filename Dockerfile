ARG BASE_REGISTRY=gcr.io
ARG BASE_IMAGE=distroless/static
ARG BASE_TAG=nonroot
ARG GO_VERSION=1.17.3

FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
ENV CGO_ENABLED=0
RUN go build ./cmd/authorizer

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

COPY --from=builder --chown=nonroot:nonroot src/authorizer /authorizer

USER nonroot:nonroot
ENTRYPOINT ["/authorizer"]

HEALTHCHECK NONE
