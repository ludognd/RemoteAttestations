package tests

import (
	"fmt"
	"testing"
)

func Failure(t *testing.T, got, want interface{}, explanation string) string {
	return fmt.Sprintf("%+v: Failed, got: %+v, wanted %+v, %v", t.Name(), got, want, explanation)
}
