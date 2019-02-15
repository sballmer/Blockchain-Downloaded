// callable from a string composed of hex char and return an uint8Array
// example: "1234567890abcdef".toUint8Array()  ->  Uint8Array(8) [ 18, 52, 86, 120, 144, 171, 205, 239 ]
String.prototype.toUint8Array = function(base=16) {
	return new Uint8Array(this.match(/.{1,2}/g).map(byte => parseInt(byte, base)));
}

// callable from a UInt8Array return a hex string
// example: new Uint8Array([1,5,9,13,50,254]).toHexString() -> "0105090d32fe"
Uint8Array.prototype.toHexString = function() {
	return this.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

// callable from a string composed of hex char and return the ascii string
// example: "6578616d706c65".toAscii() = "example"
String.prototype.toAscii = function() {
  return this.match(/.{1,2}/g).map(function(v){
      return String.fromCharCode(parseInt(v, 16));
    }).join('');
}

// AES-GCM encryption
//	iv: 		Uint8Array with binary initialize vector 
//	key: 		CryptoKey format
//	data: 		Uint8Array with the binary data to encrypt
//	func_then: 	function to execute when encryption successfully done, with uint8array encrypted data
//	func_err: 	function to execute when encryption failed with error
function encrypt(iv, key, data,  func_then, func_err)
{
	window.crypto.subtle.encrypt({
		/* algo name */		name: "AES-GCM",
		/* init vector */	iv: iv,
		/* tag length */	tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
		},
		key,
		data.buffer

	).then(function(encrypted){
		func_then(new Uint8Array(encrypted));

	}).catch(func_err);
}

// AES-GCM decryption
//	iv: 		Uint8Array with binary initialize vector 
//	key: 		CryptoKey format
//	data: 		Uint8Array with the binary data to decrypt
//	func_then: 	function to execute when encryption successfully done, with uint8array decrypted data
//	func_err: 	function to execute when encryption failed with error
function decrypt(iv, key, data, func_then, func_err)
{
	window.crypto.subtle.decrypt({
		/* algo name */		name: "AES-GCM",
		/* init vector */	iv: iv,
		/* tag length */	tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
		},
		key,
		data.buffer

	).then(function(decrypted){
		func_then(new Uint8Array(decrypted));

	}).catch(func_err);
}

// set pdf data with id, from uint8array data
function set_pdf_data(raw_data, filename, iframe_id='myPdf')
{
	// get pdf div
	var pdf = document.getElementById(iframe_id);

	// show it
	pdf.style.display = "";

	// create blob object
	var newBlob = new Blob([raw_data], {type: 'application/pdf'});
	newBlob.name = filename;

	// attached data
	const data = window.URL.createObjectURL(newBlob);

	// set data
	pdf.src = data;
}

function download_data(tx, web3, func_then, func_err, hex_data = "", filename_hex= "")
{
	// download tx
	web3.eth.getTransaction(tx).then(function(data) {

		// extract lowercase hexadecimal
		raw_hex = data.input.toLowerCase();

		console.log("successfully loaded tx", tx, "of length", raw_hex.length / 2, "bytes");

		// little check on the data and version
		if (raw_hex.slice(2,4) == 'ff' && raw_hex.slice(-2) == 'ff' && raw_hex.slice(4, 6) == '00')
		{    // header, ender and version checked !

			// first part of the message with filename
			if (raw_hex.slice(6,8) == '00')
			{
				// | FF | VERSION | HEADER | NAME_SIZE | NAME | NEXT_TX | DATA | FF | 
				// | 1B |    1B   |   1B   |   2B      |  NB  |   32B   |  XB  | 1B | 

				// extract filename size
				filename_size = parseInt(raw_hex.slice(8,12), 16);

				// extract filename_hex_encrypted
				filename_hex = raw_hex.slice(12,12+filename_size*2)

				// extract next tx hash
				tx = '0x' + raw_hex.slice(12+filename_size*2, 12+filename_size*2+64);

				// extract hex data
				hex_data += raw_hex.slice(12+filename_size*2+64, -2);

				// recursion if tx != 0
				if (tx != '0x0000000000000000000000000000000000000000000000000000000000000000')
				{
					download_data(tx, web3, func_then, func_err, hex_data, filename_hex);
				}
			}

			// mid message
			else if (raw_hex.slice(6,8) == '01')
			{
				// | FF | VERSION | HEADER | NEXT_TX | DATA | FF | 
				// | 1B |    1B   |   1B   |   32B   |  XB  | 1B | 				

				// extract next tx
				tx = '0x' + raw_hex.slice(8, 72);

				// extract data
				hex_data += raw_hex.slice(72, -2);

				// recursion
				download_data(tx, web3, func_then, func_err, hex_data, filename_hex);
			}

			// last message
			else if (raw_hex.slice(6,8) == '02')
			{
				// | FF | VERSION | HEADER | DATA | FF | 
				// | 1B |    1B   |   1B   |  XB  | 1B | 	

				// extract data
				hex_data += raw_hex.slice(8, -2);

				// no more recursion, returns filename and data !
				func_then(hex_data.toUint8Array(), filename_hex.toUint8Array());
			}

			else
			{
				func_err("Unknown header: " + raw_hex.slice(0, 50) + " " + raw_hex.slice(-50));
			}
		}
		else
		{
			func_err("an error occured in the block:" + raw_hex.slice(0, 50) + " " + raw_hex.slice(-50));
		}

	}).catch(function(err){
		func_err("Web3 error: " + err);
	});
}

function btn_click()
{
	var loading = document.getElementById('loading_gif');
	loading.style.display = "";

	// init vector = binary for "Stephane Ballmer"
	const iv = '5374657068616e652042616c6c6d6572'.toUint8Array();

	w3 = new Web3(document.getElementById('node_url').value);

	var tx = validate_hash('tx_hash', 64);
	if (tx == null)
	{
		console.error("tx hash is invalid")
		alert("The tx hash is invalid.")
		return;
	}

	var dec_key = validate_hash('dec_key', 32);
	if (dec_key == null)
	{
		console.error("dec key is invalid")
		alert("The decryption key is invalid.")
		return;
	} 

	// raw data
	download_data("0x" + tx, w3,
		function(data, filename){
			console.log("All data loaded, data size:", data.length, "bytes");

			// import key
			window.crypto.subtle.importKey(
				/* data type*/		"raw", 
				/* private key*/	dec_key.toUint8Array().buffer, 
				/* algo */			{ name: 'AES-GCM', iv: iv }, 
				/* extractable */	false, 
				/* key usage */		["encrypt", "decrypt"]
			).then(function (key) {
				// decrypt filename
				decrypt(iv, key, filename,
					function(decipher_filename) {

						// extract and show filename
						filename_clear = decipher_filename.toHexString().toAscii()
						console.log("filename decrypted:", filename_clear);
						document.getElementById('filename').innerHTML = filename_clear;
						document.getElementById('filename').style.display = "";

						// decrypt full file
						decrypt(iv, key, data, 
							function(decipher) {
								set_pdf_data(decipher, filename_clear); 
								loading.style.display = "none";
							}, 
							function (err) {
								console.log(err);
								loading.style.display = "none";
							});
					}, 
					function (err) {
						console.log(err);
						loading.style.display = "none";
					});
			});
		},
		function(err){
			loading.style.display = "none";
			console.error(err);
		});
}

// returns the digest in format 0123456789abcdef from an input id and correct the input if necessary
function validate_hash(id, size)
{
	// hex checker
	var re = /[0-9A-Fa-f]{6}/g;

	// get digest
	digest = document.getElementById(id).value.trim();

	// check if digest is in format 0x...
	if (digest.length == (2+size) && digest.startsWith("0x") && re.test(digest.slice(2)))
	{
		document.getElementById(id).value = digest.toLowerCase();
		return digest.slice(2);
	}

	// check if digest is still valid but without 0x
	else if (digest.length == size && re.test(digest))
	{
		document.getElementById(id).value = "0x" + digest.toLowerCase();
		return digest;
	}

	// error
	else
	{
		return null;
	}
}

$(document).ready(function() {
	// tx: 0xd9dea9dfcea80768902cd73d1528fe2d38f0c90aa703283ad403f99649476c73

	var query = new URLSearchParams(window.location.search);

	if (query.get('key') != null)
	{
		document.getElementById('dec_key').value = query.get('key').trim();
		validate_hash('dec_key', 32);
	}

	if (query.get('tx') != null)
	{
		document.getElementById('tx_hash').value = query.get('tx').trim();
		validate_hash('tx_hash', 64);
	}

	if (query.get('url') != null)
	{
		node_url = document.getElementById('node_url')
		node_url.value = query.get('url').trim();

		if ( !(node_url.value.startsWith('http')) && !(node_url.value.startsWith('https')))
			node_url.value = 'https://' + node_url.value;
	}

	if (query.get('start') != null)
	{
		btn_click();
	}

});