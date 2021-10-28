/*
 * Copyright (C) 2015-2019 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

package client

import (
	"crypto/sha512"
	"github.com/VirgilSecurity/virgil-phe-go/swu"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"

	. "18phe/utils"

	. "18phe/phe"
)

// ShadowClient is responsible for protecting & checking passwords at the client (website) side
type ShadowClient struct {
	clientPrivateKey      *big.Int
	ClientPrivateKeyBytes []byte
	serverPublicKey      *Point
	ServerPublicKeyBytes []byte
	negKey               *big.Int
	invKey                *big.Int
}

// GenerateClientKey creates a new random key used on the ShadowClient side
func GenerateClientKey() []byte {
	return RandomZ().Bytes()
}

//NewClient creates new client instance using client's private key and server's public key used for verification
func NewClient(serverPublicKey []byte, privateKey []byte) (*ShadowClient, error) {
	if len(privateKey) == 0 {
		return nil, errors.New("invalid private key")
	}

	pub, err := PointUnmarshal(serverPublicKey)

	if err != nil {
		return nil, errors.Wrap(err, "invalid public key")
	}

	sk := new(big.Int).SetBytes(privateKey)

	return &ShadowClient{
		clientPrivateKey:      sk,
		serverPublicKey:       pub,
		ClientPrivateKeyBytes: privateKey,
		ServerPublicKeyBytes:  serverPublicKey,
		negKey:                Gf.Neg(sk),
		invKey:                Gf.Inv(sk),
	}, nil

}

// EnrollAccount uses fresh Enrollment Response and user's password (or its hash) to create a new Enrollment Record which
// is then supposed to be stored in a database
// it also generates a random encryption key which can be used to protect user's data
func (sc *ShadowClient) EnrollAccount(password []byte, respBytes []byte) (rec []byte, key []byte, err error) {

	resp := &EnrollmentResponse{}

	if err = proto.Unmarshal(respBytes, resp); err != nil {
		return
	}

	c0, err := PointUnmarshal(resp.C0)
	if err != nil {
		return
	}

	c1, err := PointUnmarshal(resp.C1)
	if err != nil {
		return
	}

	proofValid := sc.validateProofOfSuccess(resp.Proof, resp.Ns, c0, c1, resp.C0, resp.C1)
	if !proofValid {
		err = errors.New("invalid proof")
		return
	}

	// client nonce and 2 points
	nc := make([]byte, PheNonceLen)
	RandRead(nc)
	hc0 := HashToPoint(Dhc0, nc, password)
	hc1 := HashToPoint(Dhc1, nc, password)

	// encryption key in a form of a random point
	mBuf := make([]byte, swu.PointHashLen)
	RandRead(mBuf)
	m := HashToPoint(mBuf)

	kdf := hkdf.New(sha512.New, m.Marshal(), nil, KdfInfoClientKey)
	key = make([]byte, PheClientKeyLen)
	_, err = kdf.Read(key)

	// calculate two enrollment points
	t0 := c0.Add(hc0.ScalarMultInt(sc.clientPrivateKey))
	t1 := c1.Add(hc1.ScalarMultInt(sc.clientPrivateKey)).Add(m.ScalarMultInt(sc.clientPrivateKey))

	rec, err = proto.Marshal(&EnrollmentRecord{
		Ns: resp.Ns,
		Nc: nc,
		T0: t0.Marshal(),
		T1: t1.Marshal(),
	})

	return
}

func (sc *ShadowClient) validateProofOfSuccess(proof *ProofOfSuccess, nonce []byte, c0 *Point, c1 *Point, c0b, c1b []byte) bool {

	term1, term2, term3, blindX, err := proof.Validate()

	if err != nil {
		return false
	}

	hs0 := HashToPoint(Dhs0, nonce)
	hs1 := HashToPoint(Dhs1, nonce)

	challenge := HashZ(ProofOk, sc.ServerPublicKeyBytes, CurveG, c0b, c1b, proof.Term1, proof.Term2, proof.Term3)

	//if term1 * (c0 ** challenge) != hs0 ** blind_x:
	// return False

	t1 := term1.Add(c0.ScalarMultInt(challenge))
	t2 := hs0.ScalarMultInt(blindX)

	if !t1.Equal(t2) {
		return false
	}

	// if term2 * (c1 ** challenge) != hs1 ** blind_x:
	// return False

	t1 = term2.Add(c1.ScalarMultInt(challenge))
	t2 = hs1.ScalarMultInt(blindX)

	if !t1.Equal(t2) {
		return false
	}

	//if term3 * (self.X ** challenge) != self.G ** blind_x:
	// return False

	t1 = term3.Add(sc.serverPublicKey.ScalarMultInt(challenge))
	t2 = new(Point).ScalarBaseMultInt(blindX)

	if !t1.Equal(t2) {
		return false
	}

	return true
}

//CreateVerifyPasswordRequest creates a request in a form of elliptic curve point which is then need to be validated at the server side
func (sc *ShadowClient) CreateVerifyPasswordRequest(password []byte, recBytes []byte) ([]byte, []byte, error) {

	rec := &EnrollmentRecord{}

	if err := proto.Unmarshal(recBytes, rec); err != nil {
		return nil, nil, nil
	}

	if rec == nil || len(rec.Nc) == 0 || len(rec.Ns) == 0 || len(rec.T0) == 0 {
		return nil, nil, errors.New("invalid client record")
	}

	hc0 := HashToPoint(Dhc0, rec.Nc, password)
	minusY := Gf.Neg(sc.clientPrivateKey)

	t0, err := PointUnmarshal(rec.T0)
	if err != nil {
		return nil, nil, errors.New("invalid proof")
	}

	c0 := t0.Add(hc0.ScalarMultInt(minusY))
	return c0.Marshal(), rec.Ns, nil
}

// CheckResponseAndDecrypt verifies server's answer and extracts data encryption key on success
func (sc *ShadowClient) CheckResponseAndDecrypt(password []byte, recBytes []byte, respBytes []byte) (key []byte, err error) {

	rec := &EnrollmentRecord{}

	if err = proto.Unmarshal(recBytes, rec); err != nil {
		return
	}

	resp := &VerifyPasswordResponse{}
	if err = proto.Unmarshal(respBytes, resp); err != nil {
		return
	}

	t0, t1, err := rec.Validate()
	if err != nil {
		return nil, errors.Wrap(err, "invalid record")
	}

	c1, err := PointUnmarshal(resp.C1)
	if err != nil {
		return nil, err
	}

	hc0 := HashToPoint(Dhc0, rec.Nc, password)
	hc1 := HashToPoint(Dhc1, rec.Nc, password)

	//c0 = t0 * (hc0 ** (-self.y))

	minusY := sc.negKey

	c0 := t0.Add(hc0.ScalarMultInt(minusY))

	if resp.Res {

		proof := resp.GetSuccess()

		if proof == nil {
			return nil, errors.New("result is ok but proof is empty")
		}

		if !sc.validateProofOfSuccess(proof, rec.Ns, c0, c1, c0.Marshal(), resp.C1) {
			return nil, errors.New("result is ok but proof is invalid")
		}

		//return ((t1 * (c1 ** (-1))) * (hc1 ** (-self.y))) ** (self.y ** (-1))

		m := (t1.Add(c1.Neg()).Add(hc1.ScalarMultInt(minusY))).ScalarMultInt(sc.invKey)

		kdf := hkdf.New(sha512.New, m.Marshal(), nil, KdfInfoClientKey)
		key = make([]byte, PheClientKeyLen)
		_, err = kdf.Read(key)

		return

	}

	hs0 := HashToPoint(Dhs0, rec.Ns)
	err = sc.validateProofOfFail(resp, c0, c1, hs0)

	return nil, err
}

func (sc *ShadowClient) validateProofOfFail(resp *VerifyPasswordResponse, c0, c1, hs0 *Point) error {

	proof := resp.GetFail()

	if proof == nil {
		return errors.New("result is ok but proof is invalid")
	}

	term1, term2, term3, term4, blindA, blindB, err := proof.Validate()
	if err != nil {
		return errors.New("invalid public key")
	}

	challenge := HashZ(ProofError, sc.ServerPublicKeyBytes, CurveG, c0.Marshal(), resp.C1, proof.Term1, proof.Term2, proof.Term3, proof.Term4)
	//if term1 * term2 * (c1 ** challenge) != (c0 ** blind_a) * (hs0 ** blind_b):
	//return False
	//
	//if term3 * term4 * (I ** challenge) != (self.X ** blind_a) * (self.G ** blind_b):
	//return False

	t1 := term1.Add(term2).Add(c1.ScalarMultInt(challenge))
	t2 := c0.ScalarMultInt(blindA).Add(hs0.ScalarMultInt(blindB))

	if !t1.Equal(t2) {
		return errors.New("proof verification failed")
	}

	t1 = term3.Add(term4)
	t2 = sc.serverPublicKey.ScalarMultInt(blindA).Add(new(Point).ScalarBaseMultInt(blindB))

	if !t1.Equal(t2) {
		return errors.New("verification failed")
	}
	return nil
}

// Rotate updates client's secret key and server's public key with server's update token
func (sc *ShadowClient) Rotate(tokenBytes []byte) error {

	newPriv, newPub, err := RotateClientKeys(sc.ServerPublicKeyBytes, sc.ClientPrivateKeyBytes, tokenBytes)
	if err != nil {
		return err
	}

	pub, err := PointUnmarshal(newPub)
	if err != nil {
		return err
	}

	sc.ClientPrivateKeyBytes = newPriv
	sc.clientPrivateKey = new(big.Int).SetBytes(newPriv)
	sc.ServerPublicKeyBytes = newPub
	sc.serverPublicKey = pub
	sc.negKey = Gf.Neg(sc.clientPrivateKey)
	sc.invKey = Gf.Inv(sc.clientPrivateKey)

	return nil
}

// UpdateRecord needs to be applied to every database record to correspond to new private and public keys
func UpdateRecord(recBytes []byte, tokenBytes []byte) (updRec []byte, err error) {

	rec := &EnrollmentRecord{}

	if err = proto.Unmarshal(recBytes, rec); err != nil {
		return
	}

	token := &UpdateToken{}
	if err = proto.Unmarshal(tokenBytes, token); err != nil {
		return
	}
	a, b, err := token.Validate()
	if err != nil {
		return nil, err
	}

	t0, t1, err := rec.Validate()
	if err != nil {
		return nil, err
	}

	hs0 := HashToPoint(Dhs0, rec.Ns)
	hs1 := HashToPoint(Dhs1, rec.Ns)

	t00 := t0.ScalarMultInt(a).Add(hs0.ScalarMultInt(b))
	t11 := t1.ScalarMultInt(a).Add(hs1.ScalarMultInt(b))

	return proto.Marshal(&EnrollmentRecord{
		T0: t00.Marshal(),
		T1: t11.Marshal(),
		Ns: rec.Ns,
		Nc: rec.Nc,
	})
}

// RotateClientKeys returns a new pair of keys given old keys and an update token
func RotateClientKeys(serverPublic, clientPrivate, tokenBytes []byte) (newClientPrivate, newServerPublic []byte, err error) {

	token := &UpdateToken{}
	if err = proto.Unmarshal(tokenBytes, token); err != nil {
		return
	}

	a, b, err := token.Validate()
	if err != nil {
		return
	}

	pub, err := PointUnmarshal(serverPublic)

	if err != nil {
		return
	}

	if len(clientPrivate) == 0 {
		err = errors.New("invalid private key")
		return
	}

	newClientPrivate = PadZ(Gf.MulBytes(clientPrivate, a).Bytes())
	pub = pub.ScalarMultInt(a).Add(new(Point).ScalarBaseMultInt(b))
	newServerPublic = pub.Marshal()
	return
}

//func RunClient()([]byte, []byte){
//	const datafile = "../credentials/"
//	_, filename, _, _ := runtime.Caller(1)
//	credpath := path.Join(path.Dir(filename), datafile)
//	// TLS Based on CA
//	cert, err := tls.LoadX509KeyPair(credpath + "/client.crt", credpath + "/client.key")
//	if err != nil {
//		log.Fatalf("tls.LoadX509KeyPair err: %v", err)
//	}
//	certPool := x509.NewCertPool()
//	ca, err := ioutil.ReadFile(credpath + "/ca.crt")
//	if err != nil {
//		log.Fatalf("ioutil.ReadFile err: %v", err)
//	}
//
//	if ok := certPool.AppendCertsFromPEM(ca); !ok {
//		log.Fatalf("certPool.AppendCertsFromPEM err")
//	}
//
//	cred := credentials.NewTLS(&tls.Config{
//		Certificates: []tls.Certificate{cert},
//		ServerName:   "localhost",
//		RootCAs:      certPool,
//	})
//
//	// Set up a connection to the server.
//	opts := []grpc.DialOption{
//		// credentials.
//		grpc.WithTransportCredentials(cred),
//	}
//
//	conn, err := grpc.Dial(address, opts...)
//	if err != nil {
//		log.Fatalf("did not connect: %v", err)
//	}
//	defer conn.Close()
//	c := NewPheWorkflowClient(conn)
//
//	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
//	defer cancel()
//
//	msg1 := "requestPublicKey"
//	r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
//	if err != nil {
//		log.Fatalf("could not request public key: %v", err)
//	}
//	log.Printf("ReceivePubkey Finish")
//	nc, _ := NewClient(r.GetPublicKey(), RandomZ().Bytes())
//
//	msg2 := "requestGenEnrollment"
//	r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
//	if err1 != nil {
//		log.Fatalf("could not request get enrollment: %v", err)
//	}
//	log.Printf("GetEnrollment Finish")
//	enrollment, _ := proto.Marshal(&EnrollmentResponse{
//		Ns:    r1.GetNs(),
//		C0:    r1.GetC0(),
//		C1:    r1.GetC1(),
//		Proof: r1.GetProof(),
//	})
//	rec, key, err := nc.EnrollAccount(pwd, enrollment)
//
//	msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd, rec)
//	r2, err2 := c.VerifyPassword(ctx, &VerifyPasswordRequest{
//		Ns: msg3b,
//		C0: msg3a,
//	})
//	if err2 != nil {
//		log.Fatalf("could not request verify password: %v", err)
//	}
//	log.Printf("VerifyPassword Finish")
//	res, _ := proto.Marshal(&VerifyPasswordResponse{
//		Res:   r2.GetRes(),
//		C1:    r2.GetC1(),
//		Proof: r2.GetProof(),
//	})
//
//	keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
//	return key, keyDec
//
//}
