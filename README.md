new tinyssl but using libcrypto 1.1.1 and no more libeay</br>

TinySSL, aka playing with openssl library (libeay32) for digest, cipher and certificate matters.

--cn= cn
--alt= alternate name
--ca= true|false (default: false)
--password= password
--privatekey= path to a privatekey file
--cert= path to a certificate
--algo= use list_cipher or list_digest
--key= optional, used by decrypt/encrypt
--iv= optional, used by decrypt/encrypt
--utf16= true|false (default: false)
--debug= true|false (default: false)
--filename= local filename
--s_client will retrieve ssl information from remote host, cn=host
--print_cert print cert details from cert
--print_private print cert details from privatekey
--print_request print request details from filename
--genkey generate rsa keys public.pem and private.pem
--hash hash password, using algo
--base64encode encode password to base64
--base64decode decode password to base64
--decrypt crypt password (hexa), using algo and optional key
--encrypt crypt password, using algo and optional key
--list_cipher list all ciphers
--list_digest list all digests
--tohexa convert a password string to hexa
--fromhexa convert a password hexa to string
--encrypt_pub encrypt a file using public.pem, read from filename
--decrypt_priv decrypt a file using private.pem, read from filename
--mkcert make a self sign root cert, read from privatekey (option) & write to filename.crt and
filename.key
--mkreq make a certificate service request, read from privatekey & write to filename.csr
filename.key (if privatekey not specified)
--signreq make a certificate from a csr, read from filename and cert, write to filename.crt
--set_password read from privatekey and creates a new private key with a different password - if no
password provided, will remove the existing password
--dertopem convert a binary/der private key or cert to base 64 pem format, read from cert or
privatekey, write to cert.crt or privatekey.key
--pemtoder convert a base 64 pem format to binary/der private key or cert, read from cert or
privatekey, write to cert.der or privatekey.der
--p12topem convert a pfx to pem, read from cert, write to cert.crt and cert.key
--pemtop12 convert a pem to pfx, read from cert and privatekey, write to cert.pfx
--p7topem convert a p7b to pem, read from cert, write to cert.crt
--pemtop7 convert a pem to p7b, read from cert, write to cert.p7b


Example : create a root ca (reusing a previous key), create a csr (reusing a previous key) and generate a certificate (that will work in latest chrome).

rem if you want to reuse an existing key and therefore renew instead of recreate
tinySSL.exe --mkcert --debug=true --privatekey=ca.key --password=password --filename=ca.crt --ca=true
rem recreate, not renew
rem tinySSL.exe --mkcert --debug=true --filename=ca.crt --ca=true
rem renew, not recreate
tinySSL.exe --mkreq --debug=true --filename=request.csr --privatekey=request.key
rem recreate, not renew
rem tinySSL.exe --mkreq --debug=true --filename=request.csr
tinySSL.exe --signreq --debug=true --alt="DNS:*.groupe.fr" --password=password --filename=request.csr --cert=ca.crt

Example : turn a cert file (pem format) into a pfx
tinyssl --pemtop12 --cert=request.crt --privatekey=request.key
Back to crt
tinyssl --p12topem --cert=request.pfx

