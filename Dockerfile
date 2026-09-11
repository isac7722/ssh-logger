FROM node:24-alpine@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81 AS web
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ ./internal/
COPY server/ ./server/
COPY agent/ ./agent/
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/server ./server && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/ssh-logger-agent ./agent

FROM scratch AS agent
COPY --from=go /out/ssh-logger-agent /ssh-logger-agent

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS runtime
RUN apk add --no-cache ca-certificates tzdata && addgroup -g 10001 app && adduser -D -u 10001 -G app app && mkdir -p /data /app && chown app:app /data && chmod 700 /data
WORKDIR /app
COPY --from=go /out/server /app/server
COPY --from=web /src/web/dist /app/web
USER 10001:10001
ENV DB_PATH=/data/sshlogger.db WEB_DIR=/app/web
EXPOSE 8080
ENTRYPOINT ["/app/server"]
