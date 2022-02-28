package phe

import (
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

func MarshalKeypair(publicKey, privateKey []byte) ([]byte, error) {
	kp := &Keypair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	return proto.Marshal(kp)
}

func UnmarshalKeypair(serverKeypair []byte) (kp *Keypair, err error) {

	kp = &Keypair{}
	err = proto.Unmarshal(serverKeypair, kp)
	if err != nil {
		return nil, errors.Wrap(err, "invalid keypair")
	}

	return
}