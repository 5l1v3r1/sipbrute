package utils

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/packetassailant/sipbrute/models"
)

// UtilMarshaller wraps class to protect global namespace
type UtilMarshaller struct{}

var keywords = []string{
	"Via",
	"From",
	"To",
	"Call-ID",
	"Max-Forwards",
	"CSeq",
	"User-Agent",
	"Contact",
	"Authorization",
	"Content-Length",
	"Expires",
}

// ParseResponse extracts params from SIP reponse body
func (um *UtilMarshaller) ParseResponse(path string) (map[string]string, error) {
	headerMap := make(map[string]string)

	pathBuf, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer pathBuf.Close()

	pathScanner := bufio.NewScanner(pathBuf)
	for pathScanner.Scan() {
		lineBuf := string(pathScanner.Text())
		lineArr := strings.SplitN(lineBuf, ":", 2)
		result := contains(lineArr[0], keywords)
		if result {
			headerMap[lineArr[0]] = lineArr[1]
		}
	}
	if err := pathScanner.Err(); err != nil {
		return nil, err
	}
	return headerMap, nil
}

// ParseAuthHeader to extract header value
func (um *UtilMarshaller) ParseAuthHeader(hdr map[string]string) map[string]string {
	var value string
	attrMap := make(map[string]string)
	for k, v := range hdr {
		if k == "Authorization" {
			value = strings.TrimSpace(v)
			authSlice := strings.SplitN(value, " ", 2)
			attrSlice := strings.Split(authSlice[1], ",")
			for _, v := range attrSlice {
				compSlice := strings.Split(v, "=")
				attrMap[compSlice[0]] = strings.Replace(compSlice[1], "\"", "", -1)
			}
		}
	}
	return attrMap
}

// CrackHash is a setter to attempt hash collisions
func (um *UtilMarshaller) CrackHash(s *models.SIPStruct, dict string, verbose bool) (string, error) {
	dictBuf, err := os.Open(dict)
	if err != nil {
		return "", err
	}
	defer dictBuf.Close()

	var crackStatus = fmt.Sprintf("No password match found for hash: %s", s.Response)

	dictScanner := bufio.NewScanner(dictBuf)
	if err := dictScanner.Err(); err != nil {
		return "", err
	}

	fmt.Printf("Starting crack of hash: %s\n", s.Response)

	workercount := runtime.NumCPU()
	passwds := make(chan string, workercount)
	isClosed := false
	wg := &sync.WaitGroup{}
	// This lock is needed to ensure we don't close a closed channel.
	// This can happen if there are two matching passwords in a list.
	lk := sync.RWMutex{}

	ha2 := getMD5Hash(s.Method + ":" + s.URI)
	for i := 0; i < workercount; i++ {
		go func(s *models.SIPStruct, ha2 string) {
			for passwd := range passwds {
				ha1 := getMD5Hash(s.Username + ":" + s.Realm + ":" + passwd)
				ha3 := getMD5Hash(ha1 + ":" + s.Nonce + ":" + ha2)

				if verbose {
					fmt.Printf("Attempting hash crack: %s\n", passwd)
					fmt.Printf("Created hash format ha1: %s\n", ha1)
					fmt.Printf("Created hash format ha2: %s\n", ha2)
					fmt.Printf("Created hash format ha3: %s\n", ha3)
				}

				if ha3 == s.Response {
					lk.Lock()
					crackStatus = fmt.Sprintf("Password match: %s on hash %s", passwd, ha3)
					if !isClosed {
						isClosed = true
						close(passwds)
					}
					lk.Unlock()
				}
				wg.Done()
			}
		}(s, ha2)
	}

	for dictScanner.Scan() {
		lk.RLock()
		if !isClosed {
			wg.Add(1)
			passwds <- strings.TrimSpace(dictScanner.Text())
		}
		lk.RUnlock()
	}

	wg.Wait()

	lk.Lock()
	if !isClosed {
		close(passwds)
	}
	lk.Unlock()

	return crackStatus, nil
}

func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func contains(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}
