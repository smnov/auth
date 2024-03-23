package main

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Storage interface {
	GetRefreshToken(ctx context.Context, id, refreshTokenString string) (string, string, error)
	SaveRefreshToken(ctx context.Context, token string) error
}

type MongoStore struct {
	db *mongo.Client
}

func (s *MongoStore) GetRefreshToken(ctx context.Context, id, refreshTokenString string) (string, string, error) {
	collection := s.db.Database("auth").Collection("refresh_tokens")
	var result struct {
		TokenHash string `bson:"token_hash"`
	}
	err := collection.FindOne(context.Background(), bson.M{"user_id": id}).Decode(&result)
	if err != nil {
		return "", "", err
	}
	err = bcrypt.CompareHashAndPassword([]byte(result.TokenHash), []byte(refreshTokenString))
	if err != nil {
		return "", "", err
	}
	accessToken, err := NewAccessToken(id)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := NewRefreshToken()
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func (s *MongoStore) SaveRefreshToken(ctx context.Context, token string) error {
	collection := s.db.Database("auth").Collection("refresh_tokens")
	t := Token{refresh: token}
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
