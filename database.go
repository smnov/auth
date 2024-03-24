package main

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Storage interface {
	GetRefreshToken(ctx context.Context, refreshTokenString, id string) (string, error)
	SaveRefreshToken(ctx context.Context, token, id string) error
	ReplaceRefreshToken(ctx context.Context, token, id string) error
}

type MongoStore struct {
	db *mongo.Client
}

func (s *MongoStore) GetRefreshToken(ctx context.Context, refreshTokenString, id string) (string, error) {
	collection := s.db.Database("auth").Collection("refresh_tokens")
	var result struct {
		UserID    string `bson:"_id"`
		TokenHash string `bson:"payload"`
	}
	err := collection.FindOne(context.Background(), bson.M{"_id": id}).Decode(&result)
	if err != nil {
		return "", err
	}
	return result.TokenHash, nil
}

func (s *MongoStore) ReplaceRefreshToken(ctx context.Context, token, id string) error {
	collection := s.db.Database("auth").Collection("refresh_tokens")

	deleteFilter := bson.M{"_id": id}
	_, err := collection.DeleteOne(ctx, deleteFilter)
	if err != nil {
		return err
	}

	t := Token{UserID: id, Payload: token}
	filter := bson.M{"_id": id}
	_, err = collection.ReplaceOne(ctx, filter, t)
	if err != nil {
		return err
	}
	return nil
}

func (s *MongoStore) SaveRefreshToken(ctx context.Context, token, id string) error {
	collection := s.db.Database("auth").Collection("refresh_tokens")
	t := Token{UserID: id, Payload: token}
	_, err := collection.InsertOne(ctx, t)
	if err != nil {
		return err
	}
	return nil
}

func NewMongoStore() (*MongoStore, error) {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		return nil, err
	}
	return &MongoStore{
		db: client,
	}, nil
}
