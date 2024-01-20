# jwtE

[Get more](https://github.com/GuoBoy/jwtE) 

> A go library based on jwt and jwe with some encryption algorithm.

## Example

```go
package main

import (
	"fmt"
	"github.com/GuoBoy/jwtE"
	"log"
)

type ExpPld struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func main() {
	// new token
	pld := ExpPld{
		ID:   "xdf001",
		Name: "GuoBoy",
	}
	secret := "66.66.66.66.66"
	j := jwtE.NewJwtEWithExpires(pld, jwtE.NewExpiresTime(jwtE.OneDay))
	fmt.Println(j)
	token, err := j.SignWithSecretString(secret)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)
	
	/**
	    parse and validate
	*/
	je, err := jwtE.Parse[ExpPld](token, secret)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(je)
	fmt.Println(je.Expired())
}
```

## Read More

Todo

