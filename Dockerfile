FROM golang:1.21-alpine
WORKDIR /app
COPY . .
RUN cd backend/api-gateway && go mod tidy && go build -o main .
CMD ["./backend/api-gateway/main"]
