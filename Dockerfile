FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /wt-lab .

FROM alpine:3.20
COPY --from=build /wt-lab /wt-lab
# secrets arrive as env; the chain lands on disk before boot
CMD ["sh", "-c", "printf '%s' \"$WT_CERT_PEM\" > /cert.pem && printf '%s' \"$WT_KEY_PEM\" > /key.pem && exec /wt-lab -wtcert le -cert /cert.pem -key /key.pem -bind fly-global-services -qlog /tmp/qlog"]
