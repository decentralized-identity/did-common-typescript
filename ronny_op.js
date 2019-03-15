// ronny_op.js

var PairwiseKey_1 = require('./dist/lib/crypto/PairwiseKey.js');
var pairwiseKey = new PairwiseKey_1.default('did:test:7b713cce-f252-4df1-8239-16bc551d05b0', 'did:test:7b713cce-f252-4df1-8239-16bc551d05b1');
var alg1 = {
	name: 'ECDSA',
	namedCurve: 'P-256',
	hash: {
		name: 'SHA-256'
	}
};

var alg2 = {
	name: 'ECDH',
	namedCurve: 'K-256'
};

var pairwiseResult;
var didMasterKey = Buffer.alloc(32, 1);
pairwiseKey.generate(didMasterKey, crypto, alg1, 'EC', 'sig', exportable = true)
.then(result => {
	return result.jwkKey;
}, err => {
	var foo = err;
})
.then(result =>{
	var foo = result;
}, err => {
	throw err;
})

/*
randomSeed()
.then(didMasterKey => {
	return pairwiseKey.generate(didMasterKey, crypto, alg2, 'EC', 'sig', exportable = true);
}, err => {
	throw err;
})
.then(result => {
	pairwiseResult = result;
}, err => {
	throw err;
})


function randomSeed() {
	if (typeof window === 'undefined'){
	    return new Promise((resolve, reject) => {
	    	pk.crypto.randomBytes(48, function(err, buf){
	    		if (err){
	    			reject(err);
	    		} else {
	    			resolve(base64url.encode(buf));
	    		}
	    	});
	    });		
	}
	else {     
		var vector1 = crypto.getRandomValues(new Uint8Array(16));
		var vector2 = crypto.getRandomValues(new Uint8Array(16));
		var result = concatTypedArrays(vector1, vector2);
		return Promise.resolve(result);
	}
}

function concatTypedArrays(a, b) { // a, b TypedArray of same type
    var c = new (a.constructor)(a.length + b.length);
    c.set(a, 0);
    c.set(b, a.length);
    return c;
}
*/