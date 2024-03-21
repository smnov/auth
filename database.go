package main

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Storage interface {
	GetRefreshToken(ctx context.Context) (string, error)
}

type DBService struct {
	storage Storage
}

func NewDBService(s Storage) *DBService {
	return &DBService{
		storage: s,
	}
}

type MongoStore struct {
	db *mongo.Client
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

func (s *MongoStore) GetTokens(ctx context.Context) {

}

func (s *MongoStore) RefreshTokens(ctx context.Context) {

}
