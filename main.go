package main

import (
	"context"
	"time"
)

func main() {
	mongo, err := NewMongoStore()
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	mongo.db.Connect(ctx)
	defer mongo.db.Disconnect(ctx)
	server := NewAPIServer(":8080", mongo)
	server.Run()
}
