package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"google.golang.org/appengine/log"
	"context"
)

type LogicError struct {
	Error string
}

func LogicException(ctx context.Context, w http.ResponseWriter, err error, statusCode int) {
	logicErrorParams := LogicError{}

	log.Errorf(ctx, "Error: %v", err)
	w.WriteHeader(statusCode)
	logicErrorParams.Error = err.Error()
	resultJson, _ := json.Marshal(logicErrorParams)
	fmt.Fprint(w, string(resultJson))
}