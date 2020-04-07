package database

import (
	"errors"
	"fmt"
)

const (
	graphName = "topology"
)

var (
	ErrKeyInvalid = errors.New("Error: Key value is invalid")
	ErrKeyChange  = errors.New("Error: Key value changed")
)

type DBObject interface {
	GetKey() (string, error)
	SetKey() error
	makeKey() (string, error)
	GetType() string
}

func GetID(i DBObject) (string, error) {
	k, err := i.GetKey()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s", i.GetType(), k), nil
}

type EdgeObject interface {
	//To, From
	SetEdge(DBObject, DBObject)
}
