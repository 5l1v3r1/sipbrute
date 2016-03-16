package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/packetassailant/sipbrute/models"
	"github.com/packetassailant/sipbrute/utils"
)

func main() {
	path := flag.String("path", "", "the SIP register UAC response file")
	dict := flag.String("dict", "", "the dictionary wordlist")
	verbose := flag.Bool("verbose", false, "stdout every derivation attempt")
	flag.Parse()

	if *path == "" {
		log.Fatal("the location of a SIP register UAC response file is required")
	}

	if *dict == "" {
		log.Fatal("the location of a dictionary file is required")
	}

	um := utils.UtilMarshaller{}

	result, err := um.ParseResponse(*path)
	if err != nil {
		log.Fatal(err)
	}

	ah := um.ParseAuthHeader(result)

	sps := new(models.SIPStruct)
	sps.Method = "REGISTER"
	for k, v := range ah {
		switch k {
		case "username":
			sps.Username = v
		case "realm":
			sps.Realm = v
		case "uri":
			sps.URI = v
		case "nonce":
			sps.Nonce = v
		case "response":
			sps.Response = v
		}
	}

	crackResult, err := um.CrackHash(sps, *dict, *verbose)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(crackResult)
}
