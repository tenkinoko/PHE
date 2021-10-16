package test

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"

	. "18phe/client"
)

func Test_Client(t *testing.T){
	key, keyDec := RunClient()
	//fmt.Printf("key:%b \nkeyDec:%b\n", key, keyDec)
	fmt.Println(bytes.Equal(key, keyDec))
	require.Equal(t, key, keyDec)
}
