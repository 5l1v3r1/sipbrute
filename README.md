# sipbrute

## Objective
```
A utility to perform dictionary attacks against the VoIP SIP Register hash (MD5)
```

## Handshake w/ Authentication
```
Step 1. The User Agent Client (UAC) initiates a request to Register with the User Agent Server (UAS)
Step 2. The UAS responds with a 401 including a **WWW-Authenticate** header
Step 3. The UAC responds with another Register request including an **Authorization** header
Step 4. The UAS authenticates the UAC and passes a 200 response
```

## Vulnerability
```
Using the following UAC response (Step 3), we can deduce a few items of relevance. Specifically,
via RFC 3261 we know that the _username_, _realm_, _uri_, and _nonce_ are all used through a series
of MD5 hash operations in order to create the value contained with the _response_ attribute.

The hash chain follows:
H1 = username + ":" + realm + ":" + passphrase
H2 = method + ":" + uri
H3 = H1 + ":" + nonce + ":" H2

This same process is repeated on the UAS to compare and match the H3 value provided by the UAC.
We can then deduce that anyone who has possession of the data within the authorization header can
derive the original passphrase value using either dictionary wordlists or brute-force keyspace attacks.

REGISTER sip:192.168.1.10 SIP/2.0
Via: SIP/2.0/UDP 192.168.1.118:5061;branch=z9hG4bK5f0808d1
From: <sip:100@192.168.1.10>;tag=001200a65ed20002553c39ec-1fe32660
To: <sip:100@192.168.1.10>
Call-ID: 001200a6-5ed20002-1b3eb454-1f3bd705@192.168.1.118
Max-Forwards: 70
CSeq: 102 REGISTER
User-Agent: Cisco-CP7960G/8.0
Contact: <sip:100@192.168.1.118:5061;user=phone;transport=udp>;+sip.instance="<urn:uuid:00000000-0000-0000-0000-001200a65ed2>";+u.sip!model.ccm.cisco.com="7"
Authorization: Digest **username="100"**,**realm="asterisk"**,**uri="sip:192.168.1.10**",response="c692e989178c5cdca7dc577abfa467d2",**nonce="4914d427"**,algorithm=MD5
Content-Length: 0
Expires: 3600
```

## Usage
```
$ ./sipbrute -h
Usage of ./sipbrute:
  -dict string
    	the dictionary wordlist
  -path string
    	the SIP register UAC response file
  -verbose
    	stdout every derivation attempt
```

## Installation
```
Installation
---------------------------------------------------
Install GO (tested on 1.5.2)
Git clone this repo (git clone https://github.com/packetassailant/sipbrute.git)
cd into the repo and type go build (you will now have a **sipbrute** binary)
```

## Sample Run - CSV Output
```
$ time ./sipbrute -path samples/register.txt -dict 384000wordlist.txt
Starting crack of hash: c692e989178c5cdca7dc577abfa467d2
Password match: Test1234 on hash c692e989178c5cdca7dc577abfa467d2

real	0m0.016s
user	0m0.015s
sys	0m0.005s

```

## Developing
```
Alpha code under active development
```

## Contact
```
# Author: Chris Patten
# Contact (Email): cpatten[t.a.]packetresearch[t.o.d]com
# Contact (Twitter): packetassailant
```
