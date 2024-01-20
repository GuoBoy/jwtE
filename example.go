package jwtE

import (
	"fmt"
	"log"
)

func example1() {
	type ExpPld struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	pld := ExpPld{
		ID:   "xdf001",
		Name: "GuoBoy",
	}
	secret := "66.66.66.66.66"
	j := NewJwtEWithExpires(pld, NewExpiresTime(OneDay))
	fmt.Println(j)
	token, err := j.SignWithSecretString(secret)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)
	je, err := Parse[ExpPld](token, secret)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(je, je.Expired())
}
