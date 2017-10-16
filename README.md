# cf_jwt

A ColdFusion CFC to manage the encoding and decoding of JWTs (JSON Web Tokens)

[![cfmlbadges](https://cfmlbadges.monkehworks.com/images/badges/tested-with-testbox.svg)](https://cfmlbadges.monkehworks.com)
[![cfmlbadges](https://cfmlbadges.monkehworks.com/images/badges/compatibility-coldfusion-9.svg)](https://cfmlbadges.monkehworks.com)
[![cfmlbadges](https://cfmlbadges.monkehworks.com/images/badges/compatibility-coldfusion-10.svg)](https://cfmlbadges.monkehworks.com)
[![cfmlbadges](https://cfmlbadges.monkehworks.com/images/badges/compatibility-lucee-45.svg)](https://cfmlbadges.monkehworks.com)
[![cfmlbadges](https://cfmlbadges.monkehworks.com/images/badges/compatibility-lucee-5.svg)](https://cfmlbadges.monkehworks.com)

## Getting Started

Instantiate the component and pass in the required properties like so:

```
var secretKey = createUUID();
var clientId  = 'BF23473E-A6AA-477D-ADDEB3A6DC24D28E';
var issuer    = 'https://test.monkehserver.com/oauth/token';

var oCFJWT = new cf_jwt(
	secretKey = secretKey,
	issuer    = issuer,
	audience  = clientId
);
```

You then need to build your payload and send it to be encoded:

```
var payload = {
	"sub"  : 1000,
	"iss"  : issuer,
	"aud"  : clientId,
	"iat"  : 1470002703,
	"exp"  : 1602839647,
	"scope": "read write"
};

var sEncode = oCFJWT.encode( payload );
```

The above payload example uses the same `issuer` and `clientId` value being sent through to the `CF_JWT` object. These are used for validation within the object to ensure the values set are the same contained within the payload.

`sEncode` contains the JSON Web Token string value.

To decode the JWT string, simply pass it through like so:

```
var stuDecodedData = oCFJWT.decode( sEncode );
```


Testing
----------------
The component has been tested on Adobe ColdFusion 9 and 10, Lucee 4.5 and Lucee 5.


Thanks
----------------

This component is based upon the original https://github.com/jsteinshouer/cf-jwt-simple


Download
----------------
[OAuth2 CFC ](https://github.com/coldfumonkeh/cf_jwt/downloads)


### 1.0.0 - October 16, 2017

- Commit: Initial Release


MIT License

Copyright (c) 2012 Matt Gifford (Monkeh Works Ltd)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
