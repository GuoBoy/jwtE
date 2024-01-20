package jwtE

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type something struct {
	ExpiresAt time.Time `json:"expires_at"`
}

type JwtE struct {
	Header    header      `json:"header"`
	Payload   interface{} `json:"payload"`
	Something something
	Signature string `json:"signature"`
}

func (j *JwtE) SignWithSecretString(sec string) (res string, err error) {
	secret := strMd5(sec)
	headerSign, err := base64encode(j.Header)
	if err != nil {
		return
	}
	payloadSign, err := aesEncrypt(j.Payload, secret)
	if err != nil {
		return
	}
	somethingSign, err := base64encode(j.Something)
	if err != nil {
		return
	}
	temp := fmt.Sprintf("%s.%s.%s", headerSign, payloadSign, somethingSign)
	j.Signature, err = hmacWithSha256(temp, secret)
	if err != nil {
		return
	}
	res = fmt.Sprintf("%s.%s", temp, j.Signature)
	return
}

func (j *JwtE) Expired() bool {
	return j.Something.ExpiresAt.Before(time.Now())
}

func NewJwtEWithExpires(payload any, expires time.Time) *JwtE {
	return &JwtE{
		Header: header{
			Alg: "HS256",
			Typ: "JWT",
		},
		Something: something{ExpiresAt: expires},
		Payload:   payload,
	}
}

func Validate(a string, sec string) (bool, error) {
	secret := strMd5(sec)
	if len(a) == 0 {
		return false, errors.New("invade token none")
	}
	li := strings.Split(a, ".")
	if len(li) != 4 {
		return false, errors.New("invade token length")
	}
	headerSign, payloadSign, somethingSign, signature := li[0], li[1], li[2], li[3]
	temp := fmt.Sprintf("%s.%s.%s", headerSign, payloadSign, somethingSign)
	sig, err := hmacWithSha256(temp, secret)
	if err != nil {
		return false, err
	}
	if sig != signature {
		return false, errors.New("invade token signature")
	}
	return true, nil
}

func Parse[T interface{}](a string, sec string) (*JwtE, error) {
	secret := strMd5(sec)
	if len(a) == 0 {
		return nil, errors.New("invade token none")
	}
	li := strings.Split(a, ".")
	if len(li) != 4 {
		return nil, errors.New("invade token length")
	}
	headerSign, payloadSign, somethingSign, signature := li[0], li[1], li[2], li[3]
	temp := fmt.Sprintf("%s.%s.%s", headerSign, payloadSign, somethingSign)
	sig, err := hmacWithSha256(temp, secret)
	if err != nil {
		return nil, err
	}
	if sig != signature {
		return nil, errors.New("invade token signature")
	}
	payload, err := aesDecrypt[T](payloadSign, secret)
	if err != nil {
		return nil, err
	}
	st, err := base64decode[something](somethingSign)
	if err != nil {
		return nil, err
	}
	return &JwtE{
		Header: header{
			Alg: "HS256",
			Typ: "JWT",
		},
		Payload:   payload,
		Something: st,
		Signature: signature,
	}, nil
}

//func ParsePayload(a string, sec string) {
//}
