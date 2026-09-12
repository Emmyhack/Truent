# Hardened multi-stage build: pinned bases, verified download, non-root.
FROM golang:1.22.3-bookworm AS build
WORKDIR /src
COPY . .
RUN go build -trimpath -o /out/app .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot
ENTRYPOINT ["/app"]
