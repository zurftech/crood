ARG APPNAME=accounts-manager
# builder image
FROM golang:1.17-alpine3.15 as builder
ARG APPNAME
ENV GO111MODULE=on
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o ${APPNAME} .


# generate clean, final image for end users
FROM alpine:3.11.3
ARG APPNAME

RUN apk update
RUN apk upgrade
RUN apk add ca-certificates && update-ca-certificates
RUN apk add --update tzdata

WORKDIR /app/
COPY --from=builder /build/${APPNAME} .

RUN rm -rf /var/cache/apk/*
# executable
ENTRYPOINT [ "./accounts-manager" ]
# arguments that can be overridden
CMD [ "serve" ]