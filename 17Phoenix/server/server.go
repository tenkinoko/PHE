package server

import (
	. "18phe/utils"
	"context"
	"github.com/pkg/errors"
	"log"

	. "18phe/phe"
)

var (
	serverKeypair []byte
)

type Server struct {
	UnimplementedPheWorkflowServer
}

func (s *Server) ReceivePubkey(ctx context.Context, in *PubkeyRecord) (*PubkeyResponse, error) {
	if in.Flag == "requestPublicKey" {
		serverKeypair1, _ := GenerateServerKeypair()
		serverKeypair = serverKeypair1
		pub, _ := GetPublicKey(serverKeypair)
		return &PubkeyResponse{PublicKey: pub}, nil
	} else {
		log.Printf("Wrong Flag At ReceivePubkey")
		return nil, nil
	}
}

// GenerateServerKeypair creates a new random Nist p-256 keypair
func GenerateServerKeypair() ([]byte, error) {
	privateKey := PadZ(RandomZ().Bytes())
	publicKey := new(Point).ScalarBaseMult(privateKey)

	return MarshalKeypair(publicKey.Marshal(), privateKey)

}

// GetEnrollment generates a new random enrollment record and a proof
func (s *Server) GetEnrollment(ctx context.Context, in *GetEnrollRecord) (*EnrollmentResponse, error) {

	kp, err := UnmarshalKeypair(serverKeypair)
	if err != nil {
		return nil, err
	}

	ns := make([]byte, PheNonceLen)
	RandRead(ns)
	hs0, hs1, c0, c1 := eval(kp, ns)
	proof := proveSuccess(kp, hs0, hs1, c0, c1)

	return &EnrollmentResponse{
		Ns:    ns,
		C0:    c0.Marshal(),
		C1:    c1.Marshal(),
		Proof: proof.Success,
	}, nil
}

// GetPublicKey returns server public key
func GetPublicKey(serverKeypair []byte) ([]byte, error) {
	key, err := UnmarshalKeypair(serverKeypair)
	if err != nil {
		return nil, err
	}

	return key.PublicKey, nil
}

// VerifyPassword compares password attempt to the one server would calculate itself using its private key
// and returns a zero knowledge proof of ether success or failure
func (s *Server)VerifyPassword(ctx context.Context, in *VerifyPasswordRequest) (*VerifyPasswordResponse, error) {

	response, _, err := VerifyPasswordExtended(ctx, in)
	return response, err
}

// VerifyPasswordExtended compares password attempt to the one server would calculate itself using its private key
// and returns a zero knowledge proof of ether success or failure
// and an object containing verify result & salt used for verification
func VerifyPasswordExtended(ctx context.Context, in *VerifyPasswordRequest) (*VerifyPasswordResponse, *VerifyPasswordResult, error) {
	req := in
	//if err = proto.Unmarshal(reqBytes, req); err != nil {
	//	return
	//}

	kp, err := UnmarshalKeypair(serverKeypair)
	if err != nil {
		return nil, nil, err
	}

	if req == nil || len(req.Ns) != PheNonceLen {
		err = errors.New("Invalid password verify request")
		return nil, nil, nil
	}

	ns := req.Ns

	c0, err := PointUnmarshal(req.C0)
	if err != nil {
		return nil, nil, nil
	}

	hs0 := HashToPoint(Dhs0, ns)
	hs1 := HashToPoint(Dhs1, ns)

	if hs0.ScalarMult(kp.PrivateKey).Equal(c0) {
		//password is ok

		c1 := hs1.ScalarMult(kp.PrivateKey)
		state := &VerifyPasswordResult{
			Res:  true,
			Salt: req.Ns,
		}
		return &VerifyPasswordResponse{
			Res:   true,
			C1:    c1.Marshal(),
			Proof: proveSuccess(kp, hs0, hs1, c0, c1),
		}, state, nil
	}

	//password is invalid

	c1, proof, err := proveFailure(kp, c0, hs0)
	if err != nil {
		return nil, nil, nil
	}
	state := &VerifyPasswordResult{
		Res:  false,
		Salt: req.Ns,
	}
	return &VerifyPasswordResponse{
		Res:   false,
		C1:    c1.Marshal(),
		Proof: proof,
	}, state, nil
}

func eval(kp *Keypair, ns []byte) (hs0, hs1, c0, c1 *Point) {
	hs0 = HashToPoint(Dhs0, ns)
	hs1 = HashToPoint(Dhs1, ns)

	c0 = hs0.ScalarMult(kp.PrivateKey)
	c1 = hs1.ScalarMult(kp.PrivateKey)
	return
}

func proveSuccess(kp *Keypair, hs0, hs1, c0, c1 *Point) *VerifyPasswordResponse_Success {
	blindX := RandomZ()

	term1 := hs0.ScalarMult(blindX.Bytes())
	term2 := hs1.ScalarMult(blindX.Bytes())
	term3 := new(Point).ScalarBaseMult(blindX.Bytes())

	//challenge = group.hash((self.X, self.G, c0, c1, term1, term2, term3), target_type=ZR)

	challenge := HashZ(ProofOk, kp.PublicKey, CurveG, c0.Marshal(), c1.Marshal(), term1.Marshal(), term2.Marshal(), term3.Marshal())
	res := Gf.Add(blindX, Gf.MulBytes(kp.PrivateKey, challenge))
	//log.Printf("Success")
	return &VerifyPasswordResponse_Success{
		Success: &ProofOfSuccess{
			Term1:  term1.Marshal(),
			Term2:  term2.Marshal(),
			Term3:  term3.Marshal(),
			BlindX: PadZ(res.Bytes()),
		},
	}
}

func proveFailure(kp *Keypair, c0, hs0 *Point) (c1 *Point, proof *VerifyPasswordResponse_Fail, err error) {
	r := RandomZ()
	minusR := Gf.Neg(r)
	minusRX := Gf.MulBytes(kp.PrivateKey, minusR)

	c1 = c0.ScalarMult(r.Bytes()).Add(hs0.ScalarMult(minusRX.Bytes()))

	a := r
	b := minusRX

	blindA := RandomZ().Bytes()
	blindB := RandomZ().Bytes()

	publicKey, err := PointUnmarshal(kp.PublicKey)
	if err != nil {
		return
	}

	// I = (self.X ** a) * (self.G ** b)
	// term1 = c0     ** blind_a
	// term2 = hs0    ** blind_b
	// term3 = self.X ** blind_a
	// term4 = self.G ** blind_b

	term1 := c0.ScalarMult(blindA)
	term2 := hs0.ScalarMult(blindB)
	term3 := publicKey.ScalarMult(blindA)
	term4 := new(Point).ScalarBaseMult(blindB)

	challenge := HashZ(ProofError, kp.PublicKey, CurveG, c0.Marshal(), c1.Marshal(), term1.Marshal(), term2.Marshal(), term3.Marshal(), term4.Marshal())
	pof := &ProofOfFail{
		Term1:  term1.Marshal(),
		Term2:  term2.Marshal(),
		Term3:  term3.Marshal(),
		Term4:  term4.Marshal(),
		BlindA: PadZ(Gf.AddBytes(blindA, Gf.Mul(challenge, a)).Bytes()),
		BlindB: PadZ(Gf.AddBytes(blindB, Gf.Mul(challenge, b)).Bytes()),
	}
	return c1, &VerifyPasswordResponse_Fail{
		Fail: pof,
	}, nil
}

//Rotate updates server's private and public keys and issues an update token for use on client's side
func(s *Server) Rotate(ctx context.Context, in *UpdateRequest) (*UpdateToken, error) {

	kp, err := UnmarshalKeypair(serverKeypair)
	if err != nil {
		return nil, nil
	}
	a, b := RandomZ(), RandomZ()
	newPrivate := PadZ(Gf.Add(Gf.MulBytes(kp.PrivateKey, a), b).Bytes())
	newPublic := new(Point).ScalarBaseMult(newPrivate)

	_, err = MarshalKeypair(newPublic.Marshal(), newPrivate)
	if err != nil {
		return nil, nil
	}

	return &UpdateToken{
		A: PadZ(a.Bytes()),
		B: PadZ(b.Bytes()),
	}, nil
}

//func RunServer(){
//	const datafile = "../credentials/"
//	_, filename, _, _ := runtime.Caller(1)
//	credpath := path.Join(path.Dir(filename), datafile)
//	// TLS Based on CA
//	cert, err := tls.LoadX509KeyPair(credpath + "/server.crt", credpath + "/server.key")
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
//	lis, err := net.Listen("tcp", port)
//	if err != nil {
//		log.Fatalf("failed to listen: %v", err)
//	}
//	s := grpc.NewServer(grpc.Creds(cred))
//
//	RegisterPheWorkflowServer(s, &server{})
//	log.Printf("server listening at %v", lis.Addr())
//	if err := s.Serve(lis); err != nil {
//		log.Fatalf("failed to serve: %v", err)
//	}
//}