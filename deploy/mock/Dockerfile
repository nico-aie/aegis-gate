# Multi-protocol mock upstream — small static Go binary.
# Build context = deploy/mock/.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /aegis-mock .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /aegis-mock /usr/local/bin/aegis-mock
# http :9991 · ws :9992 · grpc :9993 · tcp :9994
EXPOSE 9991 9992 9993 9994
ENTRYPOINT ["/usr/local/bin/aegis-mock"]
CMD ["--http", ":9991", "--ws", ":9992", "--grpc", ":9993", "--tcp", ":9994"]
