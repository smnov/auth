package main

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)


func main() {
	mongo, err := NewMongoStore()
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	mongo.db.Connect(ctx)
	defer mongo.db.Disconnect(ctx)

	dbNames, err := mongo.db.ListDatabaseNames(ctx, bson.M{})
	if err != nil {
		panic(err)
	}
	fmt.Println(dbNames)
}
