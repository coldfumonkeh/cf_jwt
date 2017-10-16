/**
* @displayname cf_jwt
* @output false
* @hint The cf_jwt object.
* @author Matt Gifford
* @website https://www.monkehworks.com
* @purpose A ColdFusion Component to manage the encoding and decoding of JSON Web Tokens (JWT). This is a cfscript port of the cf-jwt-simple component with a little more flexibility as it allows expiration dates to be excluded (useful for refresh_tokens when dealing with OAuth2)
**/
component accessors="true"{

	property name="secretKey" type="string";
	property name="issuer" type="string";
	property name="audience" type="string";
	property name="algMap" type="struct";
	
	/**
	* Constructor
	* @secretKey The secret key to use when signing
	* @issuer The issuer (the token endpoint)
	* @audience The audience (the client ID that generated the token)
	*/
	function init(
		required string secretKey,
		required string issuer,
		required string audience
	){
		setSecretKey( arguments.secretKey );
		setIssuer( arguments.issuer );
		setAudience( arguments.audience );
		setAlgMap( {
			"HS256" = "HmacSHA256",
			"HS384" = "HmacSHA384",
			"HS512" = "HmacSHA512"
		} );
		return this;
	}


	/**
	* Encodes the JWT
	* @payload The structure containing the data to encrypt
	* @algorithm The algorithm to use when encoding. Defaults to 'HS256'
	*/
	public function encode(
		required struct payload,
		string algorithm = 'HS256'
	){
		var stuAlgMap = getAlgMap();
		var segments = '';
		// Add Header - typ and alg fields
		segments = listAppend( 
			segments,
			base64UrlEscape(
				toBase64(
					serializeJSON(
						{
							"typ" =  "JWT",
							"alg" = arguments.algorithm
						}
					)
				)
			),
		"." );
		// Add payload
		segments = listAppend(
			segments,
			base64UrlEscape(
				toBase64(
					serializeJSON( arguments.payload )
				)
			),
		"." );
		segments = listAppend(
			segments,
			sign( segments, stuAlgMap[ arguments.algorithm ] ),
		"." );
		return segments;
	}

	/**
	* Decodes the given JWT
	*/
	public function decode( required string token ){
		if( listLen( arguments.token, "." ) neq 3 ){
			cfthrow( type="Invalid Token" message="Token should contain 3 segments" );
		}
		var algorithmMap = getAlgMap();
		var header    = deserializeJSON( base64UrlDecode( listGetAt( arguments.token, 1, "." ) ) );
		var payload   = deserializeJSON( base64UrlDecode( listGetAt( arguments.token, 2, "." ) ) );
		var signature = listGetAt( arguments.token, 3, "." );

		// Make sure the algorithm listed in the header is supported
		if( !listFindNoCase( structKeyList( algorithmMap ), header[ 'alg' ] ) ){
			cfthrow( type="Invalid Token" message="Algorithm not supported" );
		}
		// Verify claims
		if( structKeyExists( payload, "exp" ) ){
			if( epochTimeToLocalDate( payload.exp ) lt now() ){
				cfthrow( type="Invalid Token" message="Signature verification failed: Token expired" );
			}
		}
		if( structKeyExists( payload, "nbf" ) and epochTimeToLocalDate( payload.nbf ) gt now() ){
			cfthrow( type="Invalid Token" message="Signature verification failed: Token not yet active" );
		}
		if( structKeyExists( payload, "iss" ) and getIssuer() neq "" and payload.iss neq getIssuer() ){
			cfthrow( type="Invalid Token" message="Signature verification failed: Issuer does not match" );
		}
		if( structKeyExists( payload, "aud" ) and getAudience() neq "" and payload.aud neq getAudience() ){
			cfthrow( type="Invalid Token" message="Signature verification failed: Audience does not match" );
		}
		// Verify signature
		var signInput = listGetAt( arguments.token, 1, "." ) & "." & listGetAt( arguments.token, 2,"." );
		if( signature neq sign( signInput, algorithmMap[header.alg] ) ){
			cfthrow( type="Invalid Token" message="Signature verification failed: Invalid key" );
		}
		return payload;
	}



	/**
	* Escapes unsafe url characters from a base64 string
	* @value The string to manipulate
	*/
	private function base64UrlEscape( required string value ){
		return reReplace( reReplace( reReplace( arguments.value, "\+", "-", "all" ), "\/", "_", "all" ) ,"=", "", "all" )
	}

	/**
	* restore base64 characters from an url escaped string 
	* @value The string to manipulate
	*/
	private function base64UrlUnescape( required string value ){
		var base64String = reReplace( reReplace( arguments.value, "\-", "+", "all" ), "\_", "/", "all" );
		var padding = repeatstring( "=", 4 - len( base64String ) mod 4 );
		return base64String & padding;
	}

		/**
	* Decode a url encoded base64 string
	* @value The string to manipulate
	*/
	private function base64UrlDecode( required string value ){
		return toString( toBinary( base64UrlUnescape( arguments.value ) ) );
	}


	/**
	* Create an MHAC of provided string using the secret key and algorithm
	* @msg The message to sign
	* @algorithm The algorithm to use for the signing. Defaults to 'HS256'
	*/
	private function sign(
		required string msg,
		string algorithm = 'HS256'
	){
		var key = createObject( "java", "javax.crypto.spec.SecretKeySpec" ).init( getSecretKey().getBytes(), arguments.algorithm );
		var mac = createObject( "java", "javax.crypto.Mac" ).getInstance( arguments.algorithm );
		mac.init( key );
		return base64UrlEscape( toBase64( mac.doFinal( msg.getBytes() ) ) );
	}


	/**
	* Converts Epoch datetime to local date
	* @epoch Seconds from Jan 1, 1970
	*/
	private function epochTimeToLocalDate( required numeric epoch ){
		return createObject( "java", "java.util.Date" ).init( epoch * 1000 );
	}


	/**
	* Returns the properties as a struct
	*/
	public struct function getMemento(){
		var result = {};
		for( var thisProp in getMetaData( this ).properties ){
			if( structKeyExists( variables, thisProp[ 'name' ] ) ){
				result[ thisProp[ 'name' ] ] = variables[ thisProp[ 'name' ] ];
			}
		}
		return result;
	}

}