component extends='testbox.system.BaseSpec'{
	
	/*********************************** BDD SUITES ***********************************/
	
	function beforeAll(){

		secretKey = createUUID();
		clientId  = 'BF23473E-A6AA-477D-ADDEB3A6DC24D28E';
		issuer    = 'https://test.monkehserver.com/oauth/token';
		oCFJWT = new cf_jwt(
			secretKey = secretKey,
			issuer    = issuer,
			audience  = clientId
		);

		payload = {
			"sub"  : 1000,
			"iss"  : issuer,
			"aud"  : clientId,
			"iat"  : 1470002703,
			"exp"  : 1602839647,
			"scope": "read write"
		};
	}


	function run(){

		describe( 'CF_JWT Component Suite', function(){
			
			it( 'should return the correct object', function(){

				expect( oCFJWT ).toBeInstanceOf( 'cf_jwt' );
				expect( oCFJWT ).toBeTypeOf( 'component' );

			});

			it( 'should have the correct properties', function() {

				var sMemento = oCFJWT.getMemento();

				expect( sMemento ).toBeStruct().toHaveLength( 4 );

				expect( sMemento ).toHaveKey( 'secretKey' );
				expect( sMemento ).toHaveKey( 'issuer' );
				expect( sMemento ).toHaveKey( 'audience' );
				expect( sMemento ).toHaveKey( 'algMap' );

			} );

			it( 'should have the correct public methods', function() {

				expect( oCFJWT ).toHaveKey( 'init' );
				expect( oCFJWT ).toHaveKey( 'encode' );
				expect( oCFJWT ).toHaveKey( 'decode' );
				expect( oCFJWT ).toHaveKey( 'getMemento' );

			} );

			it( 'should contain the correct default algorithms', function() {

				var stuAlgs = oCFJWT.getAlgMap();

				expect( stuAlgs )
					.toBeStruct()
					.toHaveLength( 3 )
					.toHaveKey( 'HS256' )
					.toHaveKey( 'HS384' )
					.toHaveKey( 'HS512' );

			} );


			it( 'should encode the payload properly', function() {

				sEncode = oCFJWT.encode( payload );

				expect( sEncode ).toBeString();
				expect( listLen( sEncode, '.' ) ).toBe( 3 );

			} );

			it( 'should decode the payload properly', function() {

				var stuDecode = oCFJWT.decode( sEncode );

				expect( stuDecode )
					.toBeStruct()
					.toHaveLength( 6 )
					.toHaveKey( 'iat' )
					.toHaveKey( 'iss' )
					.toHaveKey( 'sub' )
					.toHaveKey( 'exp' )
					.toHaveKey( 'scope' )
					.toHaveKey( 'aud' );

				expect( stuDecode[ 'iat' ] ).toBe( payload[ 'iat' ] );
				expect( stuDecode[ 'iss' ] ).toBe( payload[ 'iss' ] );
				expect( stuDecode[ 'sub' ] ).toBe( payload[ 'sub' ] );
				expect( stuDecode[ 'exp' ] ).toBe( payload[ 'exp' ] );
				expect( stuDecode[ 'scope' ] ).toBe( payload[ 'scope' ]);
				expect( stuDecode[ 'aud' ] ).toBe( payload[ 'aud' ] );

			} );

		});

	}
	
}
