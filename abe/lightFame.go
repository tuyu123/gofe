package abe

import (
	"math/big"

	"fmt"
	"strconv"

	"crypto/aes"
	cbc "crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"io"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

type LightFAMECipher struct {
	Ct     [][3]*bn256.G1
	Msp    *MSP
	SymEnc []byte // symmetric encryption of the message
	Iv     []byte // initialization vector for symmetric encryption
	S      data.Vector
	KeyGt  *bn256.GT
}

func genCt0(s data.Vector, pk *FAMEPubKey) [3]*bn256.G2 {
	ct0 := [3]*bn256.G2{new(bn256.G2).ScalarMult(pk.PartG2[0], s[0]),
		new(bn256.G2).ScalarMult(pk.PartG2[1], s[1]),
		new(bn256.G2).ScalarBaseMult(new(big.Int).Add(s[0], s[1]))}
	return ct0
}

func genCtPrime(s data.Vector, pk *FAMEPubKey, keyGt *bn256.GT) *bn256.GT {
	ctPrime := new(bn256.GT).ScalarMult(pk.PartGT[0], s[0])
	ctPrime.Add(ctPrime, new(bn256.GT).ScalarMult(pk.PartGT[1], s[1]))
	ctPrime.Add(ctPrime, keyGt)
	return ctPrime
}

func (a *FAME) LightEncrypt(msg []byte, msp *MSP, pk *FAMEPubKey) (*LightFAMECipher, error) {
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}

	attrib := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if attrib[i] {
			return nil, fmt.Errorf("some attributes correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		attrib[i] = true
	}

	// msg is encrypted using CBC, with a random key that is encapsulated
	// with FAME
	_, keyGt, err := bn256.RandomGT(rand.Reader)
	if err != nil {
		return nil, err
	}
	keyCBC := sha256.Sum256([]byte(keyGt.String()))

	c, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, c.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	encrypterCBC := cbc.NewCBCEncrypter(c, iv)

	msgByte := msg

	// message is padded according to pkcs7 standard
	padLen := c.BlockSize() - (len(msgByte) % c.BlockSize())
	msgPad := make([]byte, len(msgByte)+padLen)
	copy(msgPad, msgByte)
	for i := len(msgByte); i < len(msgPad); i++ {
		msgPad[i] = byte(padLen)
	}

	symEnc := make([]byte, len(msgPad))
	encrypterCBC.CryptBlocks(symEnc, msgPad)

	// encapsulate the key with FAME
	sampler := sample.NewUniform(a.P)
	s, err := data.NewRandomVector(2, sampler)
	if err != nil {
		return nil, err
	}

	ct := make([][3]*bn256.G1, len(msp.Mat))
	for i := 0; i < len(msp.Mat); i++ {
		for l := 0; l < 3; l++ {
			hs1, err := bn256.HashG1(msp.RowToAttrib[i] + " " + strconv.Itoa(l) + " 0")
			if err != nil {
				return nil, err
			}
			hs1.ScalarMult(hs1, s[0])

			hs2, err := bn256.HashG1(msp.RowToAttrib[i] + " " + strconv.Itoa(l) + " 1")
			if err != nil {
				return nil, err
			}
			hs2.ScalarMult(hs2, s[1])

			ct[i][l] = new(bn256.G1).Add(hs1, hs2)
			for j := 0; j < len(msp.Mat[0]); j++ {
				hs1, err = bn256.HashG1("0 " + strconv.Itoa(j) + " " + strconv.Itoa(l) + " 0")
				if err != nil {
					return nil, err
				}
				hs1.ScalarMult(hs1, s[0])

				hs2, err = bn256.HashG1("0 " + strconv.Itoa(j) + " " + strconv.Itoa(l) + " 1")
				if err != nil {
					return nil, err
				}
				hs2.ScalarMult(hs2, s[1])

				hsToM := new(bn256.G1).Add(hs1, hs2)
				pow := new(big.Int).Set(msp.Mat[i][j])
				if pow.Sign() == -1 {
					pow.Neg(pow)
					hsToM.ScalarMult(hsToM, pow)
					hsToM.Neg(hsToM)
				} else {
					hsToM.ScalarMult(hsToM, pow)
				}
				ct[i][l].Add(ct[i][l], hsToM)
			}
		}
	}

	return &LightFAMECipher{Ct: ct, Msp: msp, SymEnc: symEnc, Iv: iv, S: s, KeyGt: keyGt}, nil
}

func (a *FAME) LightDecrypt(cipher *LightFAMECipher, key *FAMEAttribKeys, pk *FAMEPubKey) ([]byte, error) {
	// find out which attributes are owned
	attribMap := make(map[string]bool)
	for k := range key.AttribToI {
		attribMap[k] = true
	}

	countAttrib := 0
	for i := 0; i < len(cipher.Msp.Mat); i++ {
		if attribMap[cipher.Msp.RowToAttrib[i]] {
			countAttrib++
		}
	}

	// create a matrix of needed keys
	preMatForKey := make([]data.Vector, countAttrib)
	ctForKey := make([][3]*bn256.G1, countAttrib)
	rowToAttrib := make([]string, countAttrib)
	countAttrib = 0
	for i := 0; i < len(cipher.Msp.Mat); i++ {
		if attribMap[cipher.Msp.RowToAttrib[i]] {
			preMatForKey[countAttrib] = cipher.Msp.Mat[i]
			ctForKey[countAttrib] = cipher.Ct[i]
			rowToAttrib[countAttrib] = cipher.Msp.RowToAttrib[i]
			countAttrib++
		}
	}

	matForKey, err := data.NewMatrix(preMatForKey)
	if err != nil {
		return nil, fmt.Errorf("the provided cipher is faulty")
	}

	// matForKey may have a len of 0 if there is a single condition
	if len(matForKey) == 0 {
		return nil, fmt.Errorf("provided key is not sufficient for decryption")
	}

	// get a combination alpha of keys needed to decrypt
	// matForKey may have a len of 0 if there is a single condition
	if len(matForKey) == 0 {
		return nil, fmt.Errorf("provided key is not sufficient for decryption")
	}
	oneVec := data.NewConstantVector(len(matForKey[0]), big.NewInt(0))
	oneVec[0].SetInt64(1)
	alpha, err := data.GaussianEliminationSolver(matForKey.Transpose(), oneVec, a.P)
	if err != nil {
		return nil, fmt.Errorf("provided key is not sufficient for decryption")
	}

	// get a CBC key needed for the decryption of msg
	ctPrime := genCtPrime(cipher.S, pk, cipher.KeyGt)
	keyGt := new(bn256.GT).Set(ctPrime)

	ctProd := new([3]*bn256.G1)
	keyProd := new([3]*bn256.G1)
	ct0 := genCt0(cipher.S, pk)
	for j := 0; j < 3; j++ {
		ctProd[j] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
		keyProd[j] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
		for i, e := range rowToAttrib {
			ctProd[j].Add(ctProd[j], new(bn256.G1).ScalarMult(ctForKey[i][j], alpha[i]))
			keyProd[j].Add(keyProd[j], new(bn256.G1).ScalarMult(key.K[key.AttribToI[e]][j], alpha[i]))
		}
		keyProd[j].Add(keyProd[j], key.KPrime[j])
		ctPairing := bn256.Pair(ctProd[j], key.K0[j])
		keyPairing := bn256.Pair(keyProd[j], ct0[j])
		keyPairing.Neg(keyPairing)
		keyGt.Add(keyGt, ctPairing)
		keyGt.Add(keyGt, keyPairing)
	}

	keyCBC := sha256.Sum256([]byte(keyGt.String()))

	c, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return nil, err
	}

	msgPad := make([]byte, len(cipher.SymEnc))
	decrypter := cbc.NewCBCDecrypter(c, cipher.Iv)
	decrypter.CryptBlocks(msgPad, cipher.SymEnc)

	// unpad the message
	padLen := int(msgPad[len(msgPad)-1])
	if (len(msgPad) - padLen) < 0 {
		return nil, fmt.Errorf("failed to decrypt")
	}
	msgByte := msgPad[0:(len(msgPad) - padLen)]

	return msgByte, nil
}
