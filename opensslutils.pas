unit opensslutils;

{$mode objfpc}{$H+}

interface

uses
  windows,Classes, SysUtils,OpenSSL.Api_11,utils,inifiles,math,dateutils,sockets;

procedure LoadSSL;
procedure FreeSSL;
//function generate_rsa_key:boolean;
function generate_rsa_key_2:boolean;
function mkcert(filename:string;cn:string;privatekey:string='';read_password:string='';serial:string='';ca:boolean=false):boolean;
function mkreq(cn:string;keyfile,csrfile:string):boolean;
function signreq(filename:string;cert:string;read_password:string='';alt:string='';ca:boolean=false):boolean;
//function selfsign(filename:string;subject:string):boolean;

function set_password(filename,password:string):boolean;

function P7B2PEM(filename:string):boolean;
function PEM2P7B(filename:string):boolean;

function PFX2PEM(filename,export_pwd:string):boolean;
function PEM2PFX(export_pwd,privatekey,cert:string):boolean;

function PVTDER2PEM(filename:string):boolean;
function PVTPEM2DER(filename:string):boolean;

function X509DER2PEM(filename:string):boolean;
function X509PEM2DER(filename:string):boolean;

function print_cert(filename:string):boolean;
function print_private(filename:string;password:string=''):boolean;
function print_req(filename:string):boolean;

function Encrypt_Pub(sometext:string;var encrypted:string):boolean;
function Decrypt_Priv(ACryptedData:string):boolean;

function hash(algo:string;input:array of byte):boolean;
function crypt(algo,input:string;keystr:string='';ivstr:string='';enc:integer=1):boolean;
function list_ciphers:boolean;
function list_hashes:boolean;
function Base64Encode(message:array of byte):boolean;
function Base64Decode(message:string;utf16:boolean=false):boolean;

function getDN(pDn: pX509_NAME): String;
function getTime(asn1_time: pASN1_TIME): TDateTime;
function getSerialNumber(x509:px509): String;

function PrintSSHKey(filename:string):boolean;

type PCharacter = PAnsiChar;
type pSTACK_OFX509 = pointer;
type TC_INT   = LongInt;

implementation


procedure LoadSSL;
begin
  {
  OpenSSL_add_all_algorithms;
  OpenSSL_add_all_ciphers;
  OpenSSL_add_all_digests;
  }
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS or OPENSSL_INIT_ADD_ALL_DIGESTS, nil); //OPENSSL_config() ? //OPENSSL_init_ssl()?
  ERR_load_crypto_strings;
  ERR_load_RSA_strings;
end;



procedure FreeSSL;
begin
  {
  EVP_cleanup;
  ERR_free_strings;
  }
end;

procedure bio_flush(bp:pbio);
begin
  Bio_ctrl(bp,BIO_CTRL_FLUSH,0,nil);
end;

procedure bio_reset(bp:pbio);
begin
  Bio_ctrl(bp,BIO_CTRL_reset,0,nil);
end;

function LoadPublicKey(KeyFile: string) :pEVP_PKEY ;
var
  mem: pBIO;
  k: pEVP_PKEY=nil;
  rc:integer=0;
begin
  log('LoadPublicKey: '+KeyFile);
  //mem := BIO_new(BIO_s_file()); //BIO типа файл
  //rc:=BIO_read_filename(mem, PAnsiChar(KeyFile)); // чтение файла ключа в BIO
  //log(inttostr(rc));
  mem := BIO_new_file(pchar(KeyFile), 'r+');
  try
    log('PEM_read_bio_PUBKEY');
    result := PEM_read_bio_PUBKEY(mem, k, nil, nil); //преобразование BIO  в структуру pEVP_PKEY, третий параметр указан nil, означает для ключа не нужно запрашивать пароль
  finally
    BIO_free_all(mem);
  end;
end;

function PassphraseCallback(buf: PAnsiChar; size: Integer; rwflag: Integer; udata: Pointer): Integer; cdecl;
var
  pass: PAnsiChar;
  len: Integer;
begin
  Result := 0;
  if udata = nil then Exit;

  pass := PAnsiChar(udata);
  len := Length(pass);
  if len > size then len := size;

  Move(pass^, buf^, len);
  Result := len;
end;

function LoadPrivateKey(KeyFile: string; password: string = ''): pEVP_PKEY;
var
  mem: pBIO;
begin
  Result := nil;
  log('LoadPrivateKey: ' + KeyFile);

  // Opening in read-only mode 'r' instead of 'r+'
  mem := BIO_new_file(PChar(KeyFile), 'r');
  if mem = nil then
  begin
    log('Erreur: impossible d''ouvrir le fichier ' + KeyFile);
    Exit;
  end;

  try
    log('PEM_read_bio_PrivateKey');
    if password <> '' then
    begin
      // Custom callback to prevent any interactive prompt
      Result := PEM_read_bio_PrivateKey(mem, nil, @PassphraseCallback, PAnsiChar(AnsiString(password)));
    end
    else
    begin
      // Passing a dummy callback returning 0 disables the interactive console prompt
      Result := PEM_read_bio_PrivateKey(mem, nil, nil, nil);
    end;

    if Result = nil then
      log('Erreur: echec de chargement de la cle privee (mot de passe incorrect ou format invalide)');
  finally
    BIO_free_all(mem);
  end;
end;

function PEM2P7B(filename:string):boolean;
var
p7: pPKCS7=nil;
certs:pSTACK_OFX509 = nil;
bp:pBIO;
x509_cert:pX509=nil;
begin

  result:=false;

log('PEM2P7B');
log('filename:'+filename);

  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509');
  certs := openssl_sk_new_null();
    while 1=1 do
    begin
         x509_cert := PEM_read_bio_X509(bp, nil, nil, nil);
         if x509_cert =nil then break;
         openssl_sk_push(certs, x509_cert);
    end;
    BIO_free(bp);
  x509_cert :=openssl_sk_value(certs,0);
  if x509_cert=nil then
     begin
     writeln('PEM_read_bio_X509 failed');
     exit;
     end;

  //log('i2d_PKCS7_bio');
  //result:=i2d_PKCS7_bio (bp,p7)<>-1; //der
  //if result=false then writeln('i2d_X509_bio failed');
  //https://www.openssl.org/docs/man1.0.2/man3/PKCS7_sign.html
  //if signcert and pkey are NULL then a certificates only PKCS#7 structure is output.
  p7 := PKCS7_sign(nil, nil, certs, nil, PKCS7_BINARY);
  if p7=nil then writeln('PKCS7_sign failed');
  //finalize the structure
  log('PEM_write_bio_PKCS7');
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.p7b')), 'w+');
  PEM_write_bio_PKCS7(bp,p7);
  BIO_free(bp);
  openssl_sk_free(certs);
  result:=true;
end;

function P7B2PEM(filename:string):boolean;
var
bp:pBIO;
p7: pPKCS7;
i:byte;
err: Cardinal;
begin
  result:=false;
  log('P7B2PEM');
  log('filename:'+filename);
  result:=false;
  bp := BIO_new_file(pchar(filename), 'r+');
  log('d2i_PKCS7_bio');
  //decode
  //p7:=d2i_PKCS7_bio(bp, nil); //d2i_PKCS7_bio expect a binary der PKCS7
  p7:=PEM_read_bio_PKCS7(bp,nil,nil,nil); //if your input is in a pem format you should call PEM_read_bio_PKCS7 instead
  BIO_free(bp);
  if p7 = nil then
     begin
     err := ERR_get_error;
     		repeat
     			writeln(string(ERR_error_string(err, nil)));
     			err := ERR_get_error;
     		until err = 0;
     exit;
     end;

  //OBJ_obj2nid(p7^.type) should give us the type of p7b : NID_pkcs7_signed or NID_pkcs7_signedAndEnveloped
  //sk_num should give us number of certs // if more than one we should sk_X509_shift or sk_X509_value(certs, i)

  if (p7^.d.sign^.cert <> nil) then
  begin
       bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.crt')), 'w+');
       log('PEM_write_bio_X509');
		for i:=0 to openssl_sk_num(p7^.d.sign^.cert) -1 do
           begin
           //PEM_write_bio_X509(bp,sk_X509_value(p7^.sign^.cert, 0));
           PEM_write_bio_X509(bp,openssl_sk_value(p7^.d.sign^.cert, i));
           end;
       BIO_free(bp);
       result:=true;
  end;
end;

function PFX2PEM(filename,export_pwd:string):boolean;
const
  PKCS12_R_MAC_VERIFY_FAILURE =113;
var
    p12_cert:pPKCS12 = nil;
    pkey:pEVP_PKEY=nil;
    x509_cert:pX509=nil;
    additional_certs:pSTACK_OFX509 = nil;
    bp:pBIO;
    err_reason:integer;
begin
  result:=false;
  log('Convert2PEM');
  log('filename:'+filename);
  result:=false;
  bp := BIO_new_file(pchar(filename), 'rb'); //rb not r+
  log('d2i_PKCS12_bio');
  //decode
  p12_cert:=d2i_PKCS12_bio(bp, nil);
  if p12_cert = nil then exit;
  log('PKCS12_parse');
  //this is the export password, not the private key password
  err_reason:=PKCS12_parse(p12_cert, pchar(export_pwd), @pkey, @x509_cert, @additional_certs);
  //if err_reason<>0 then
  log(inttostr(err_reason));
  BIO_free(bp);
  if err_reason =0 then exit;

  //
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.crt')), 'w+');
  log('PEM_write_bio_X509');
  PEM_write_bio_X509(bp,x509_cert);
  BIO_free(bp);
  if pkey=nil then exit;
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.key')), 'w+');
  log('PEM_write_bio_PrivateKey');
  log('no password...');
  //the private key will have no password
  PEM_write_bio_PrivateKey(bp,pkey,nil{EVP_des_ede3_cbc()},nil,0,nil,nil);
  BIO_free(bp);
  //

  if x509_cert<>nil then X509_free(x509_cert); x509_cert := nil;
  if pkey<>nil then EVP_PKEY_free(pkey); pkey := nil;
  ERR_clear_error();
  PKCS12_free(p12_cert);
  result:=true;
end;

function PEM2PFX(export_pwd,privatekey,cert:string):boolean;
var
  err_reason:integer;
  bp:pBIO=nil;
  p12_cert:pPKCS12 = nil;
  pkey:pEVP_PKEY = nil;
  x509_cert:pX509 = nil;
  certs:pSTACK_OFX509 = nil;
begin
  result:=false;
  log('Convert2PKCS12');
  log('cert:'+cert);
  log('privatekey:'+privatekey);
  bp := BIO_new_file(pchar(privatekey), 'r+');
  log('PEM_read_bio_PrivateKey');
  //password will be prompted
  pkey:=PEM_read_bio_PrivateKey(bp,nil,nil,nil);
  BIO_free(bp);
  if pkey=nil then
     begin
     writeln('PEM_read_bio_PrivateKey failed');
     exit;
     end;

  bp := BIO_new_file(pchar(cert), 'r+');
  log('PEM_read_bio_X509');
  //x509_cert:=PEM_read_bio_X509(bp,nil,nil,nil);
  certs := openssl_sk_new_null();
    while 1=1 do
    begin
         x509_cert := PEM_read_bio_X509(bp, nil, nil, nil);
         if x509_cert =nil then break;
         openssl_sk_push(certs, x509_cert);
    end;
  BIO_free(bp);
  x509_cert :=openssl_sk_value(certs,0);
  if x509_cert=nil then
     begin
     writeln('PEM_read_bio_X509 failed');
     exit;
     end;

  log('PKCS12_new');
  p12_cert := PKCS12_new();
  if p12_cert=nil then exit;


  log('PKCS12_create');
  p12_cert := PKCS12_create(pchar(export_pwd), nil, pkey, nil, certs, 0, 0, 0, 0, 0);
  if p12_cert = nil then
     begin
     writeln('PKCS12_create failed, '+inttohex(ERR_peek_error,8));
     //(SSL: error:0B080074:x509 certificate routines: X509_check_private_key:key values mismatch)
     exit;
     end;

  log('i2d_PKCS12_bio');
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(cert,'.pfx')), 'wb'); //I eventually found that I had to add 'b' to the mode for binary. I suspect it will also work for the other methods that use BIO
  err_reason:=i2d_PKCS12_bio(bp, p12_cert);
  if err_reason<=0 then log('err_reason:'+inttostr(err_reason));
  BIO_free(bp);


  if x509_cert<>nil then X509_free(x509_cert); x509_cert := nil;
  if pkey<>nil then EVP_PKEY_free(pkey); pkey := nil;
  ERR_clear_error();
  PKCS12_free(p12_cert);
  result:=err_reason<>0;
end;

function X509PEM2DER(filename:string):boolean;
var
x509_cert:pX509=nil;
bp:pBIO;
begin
result:=false;

log('X509PEM2DER');
log('filename:'+filename);

  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509');
  x509_cert:=PEM_read_bio_X509(bp,nil,nil,nil);
  BIO_free(bp);
  if x509_cert=nil then
     begin
     writeln('PEM_read_bio_X509 failed');
     exit;
     end;

  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.der')), 'wb'); //binary
  result:= i2d_X509_bio (bp,x509_cert )<>-1;
  if result=false then writeln('i2d_X509_bio failed');
  BIO_free(bp);

end;

function X509DER2PEM(filename:string):boolean;
var
hfile_:thandle=thandle(-1);
mem_:array[0..8192-1] of char;
size_:dword=0;
//
pemX509Bio,bp:pBIO;
X509Key:pX509=nil;
begin
  result:=false;
  //
  hfile_ := CreateFile(pchar(filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
  if hfile_=thandle(-1) then begin log('invalid handle',1);exit;end;
  ReadFile (hfile_,mem_[0],sizeof(mem_),size_,nil);
  closehandle(hfile_);
  //
  pemX509Bio := BIO_new(BIO_s_mem());
  BIO_write(pemX509Bio, @mem_[0], size_);
  Bio_flush(pemX509Bio);
  X509Key := d2i_X509_bio (pemX509Bio, @X509Key);
  if X509Key=nil then exit;
  //
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.crt')), 'w+');
  log('PEM_write_bio_X509');
  PEM_write_bio_X509 (bp,X509Key);
  BIO_free(bp);
  //
  result:=true;
end;

function PVTDER2PEM(filename:string):boolean;
var
hfile_:thandle=thandle(-1);
mem_:array[0..8192-1] of char;
size_:dword=0;
//
pemPrivKeyBio,bp:pBIO;
privKey:pEVP_PKEY=nil;
begin
  result:=false;
  //
  hfile_ := CreateFile(pchar(filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
  if hfile_=thandle(-1) then begin log('invalid handle',1);exit;end;
  ReadFile (hfile_,mem_[0],sizeof(mem_),size_,nil);
  closehandle(hfile_);
  //
  pemPrivKeyBio := BIO_new(BIO_s_mem());
  BIO_write(pemPrivKeyBio, @mem_[0], size_);
  BIO_flush(pemPrivKeyBio);
  //BIO_read_filename easier?;
  privKey := d2i_PrivateKey_bio(pemPrivKeyBio, privKey {nil?});
  if privkey=nil then exit;
  //
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.key')), 'w+');
  log('PEM_write_bio_PrivateKey');
  log('no password...');
  //the private key will have no password
  PEM_write_bio_PrivateKey(bp,privKey,nil{EVP_des_ede3_cbc()},nil,0,nil,nil);
  BIO_free(bp);
  //
  result:=true;
end;

function PVTPEM2DER(filename:string):boolean;
var
p:pEVP_PKEY =nil;
bp:pBIO;
begin
result:=false;

log('PVTPEM2DER');
log('filename:'+filename);

p:=LoadPrivateKey(filename);
  if p=nil then
     begin
     writeln('LoadPrivateKey failed');
     exit;
     end;

  bp := BIO_new_file(pchar(GetCurrentDir+'\'+changefileext(filename,'.der')), 'w+');
  result:= i2d_PrivateKey_bio  (bp,p )<>-1;
  if result=false then writeln('i2d_X509_bio failed');
  BIO_free(bp);

end;

function name_add_entry(section: string; name: px509_name): boolean;
var
  ini: TIniFile;
  ident: TStrings;
  s: string;
  i: integer;
begin
  log('name_add_entry');
  result := false;

  if (name = nil) or not FileExists('tinyssl.ini') then Exit;

  ini := TIniFile.Create('tinyssl.ini');
  ident := TStringList.Create;
  try
    try
      ini.ReadSection(section, ident);
      for i := 0 to ident.Count - 1 do
      begin
        s := ini.ReadString(section, ident[i], '');
        if s <> '' then
        begin
          log('X509_NAME_add_entry_by_txt: ' + ident[i] + '=' + s);
          // On passe ident[i] en PChar et on vérifie le retour d'OpenSSL
          if X509_NAME_add_entry_by_txt(name, PChar(ident[i]), MBSTRING_ASC, PChar(s), -1, -1, 0) <> 1 then
            log('Erreur OpenSSL sur la cle: ' + ident[i], 1);
        end;
      end;
      result := true;
    except
      on e: Exception do
        log('Exception name_add_entry: ' + e.Message, 1);
    end;
  finally
    ident.Free;
    ini.Free;
  end;
end;

function ini_readstring(section,ident:string):string;
var
//
ini:TIniFile;
begin
  //log('ini_readstring');
  result:='';
  if FileExists ('tinyssl.ini') then
   begin
   try
   ini:=tinifile.Create ('tinyssl.ini');
   result:=ini.ReadString (section,ident,'');
   except
   on e:exception do;
   end;
   end; //if FileExists ('tinyssl.ini') then
end;

function add_ext(cert: PX509; nid: TC_INT; value: PAnsiChar): Boolean;
var ex: PX509_EXTENSION=nil;
    ctx: X509V3_CTX;
begin
  log('add_ext '+strpas(value));
  Result := false;
  ctx.db := nil;
  log('X509V3_set_ctx');
  X509V3_set_ctx(@ctx, cert, cert, nil, nil, 0);
  log('X509V3_EXT_conf_nid');
  ex := X509V3_EXT_conf_nid(nil, @ctx, nid, value);
  if ex <> nil then
  begin
    log('X509_add_ext');
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    Result := True;
  end;

end;

// sign cert
function do_X509_sign(cert:pX509; pkey:pEVP_PKEY;const md:pEVP_MD):integer;
var
rv:integer;
mctx:PEVP_MD_CTX; //EVP_MD_CTX;
pkctx:pEVP_PKEY_CTX = nil;
begin
        log('EVP_MD_CTX_init');
	//EVP_MD_CTX_init(@mctx);
        mctx := EVP_MD_CTX_create();
        log('EVP_DigestSignInit');
	rv := EVP_DigestSignInit(mctx, @pkctx, md, nil, pkey);
        log('X509_sign_ctx');
	if (rv > 0) then rv := X509_sign_ctx(cert, mctx);
        log('EVP_MD_CTX_cleanup');
	//EVP_MD_CTX_cleanup(mctx);
        EVP_MD_CTX_destroy(mctx);
	if rv > 0 then result:= 1 else result:= 0;
end;

function BN_num_bytes(bits:integer):integer;
begin
  result:=ceil(bits / 8);
  log('BN_num_bytes:'+inttostr(result));
end;

//openssl x509 -noout -fingerprint -in ca.crt
//openssl x509 -noout -pubkey -in ca.crt | openssl pkey -pubin -outform DER | openssl dgst -SHA1 -c
function hash_pubkey(x509_cert:pX509):boolean;
const
  X509V3_ADD_DEFAULT =0;
var
ret:integer = 0;
rsa:pRSA=nil;
digest:array[0..63] of byte;
size,i:cardinal;
subjectKeyIdentifier:pASN1_OCTET_STRING;
bin:pointer;
e:pbignum;
begin
       result:=false;
       rsa:=EVP_PKEY_get1_RSA(X509_get_pubkey (x509_cert));
       //Writeln('BN_bn2hex E: ', BN_bn2hex(rsa^.e ));
       //bin:=getmem(BN_num_bytes(rsa^.e));
       e:=rsa_get0_e(rsa);
       bin:=getmem(BN_num_bytes(BN_num_bits(e)));
       BN_bn2bin(e,bin);
       //X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len); // not in openssl 1.x
       ret:=evp_digest(bin , BN_num_bytes(BN_num_bits(e)),@digest[0],@size,EVP_sha1(),nil);
       if ret=1 then
         begin
         //write('hash sha1:');
         //for i:=0 to size -1 do write(inttohex(digest[i],2));
         //writeln;
         subjectKeyIdentifier := ASN1_OCTET_STRING_new;
         ASN1_OCTET_STRING_set(subjectKeyIdentifier, @digest[0], SHA_DIGEST_LENGTH);
         log('X509_add1_ext_i2d');
         X509_add1_ext_i2d(x509_cert, NID_subject_key_identifier, subjectKeyIdentifier, 0, X509V3_ADD_DEFAULT);
         ASN1_OCTET_STRING_free(subjectKeyIdentifier);
         result:=true;
         end;
end;

//the private key of the resulting cert is the request.key
function signreq(filename:string;cert:string;read_password:string='';alt:string='';ca:boolean=false):boolean;
const
   LN_commonName=                   'commonName';
   //NID_commonName=                  13;
   X509V3_ADD_DEFAULT =0;
var
ret:integer = 0;
pkey:PEVP_PKEY=nil;
pktmp:PEVP_PKEY=nil;
rsa:pRSA=nil;
cert_rsa:pRSA=nil;
x509_ca:pX509=nil;
x509_cert:pX509=nil;
X509_REQ:pX509_REQ=nil;
bp:pBIO;
serial:integer = 1;
days:long = 365 * 24 * 3600; // 1 year
subject:pX509_NAME = nil;
tmpname:pX509_NAME = nil;
//test
cert_entry:pX509_NAME_ENTRY=nil;
entryData:pASN1_STRING;
cn:ppansichar;
//
value:string;
digest:array[0..63] of byte;
size,i:cardinal;
subjectKeyIdentifier:pASN1_OCTET_STRING;
bin:pointer;
label free_all;
begin
  log('signreq');
  log('filename:'+filename);
  log('cert:'+cert);
  result:=false;
  // load ca
  bp := BIO_new_file(pchar(cert), 'r+');
  log('PEM_read_bio_X509');
  x509_ca:=PEM_read_bio_X509(bp,nil,nil,nil);
  BIO_free(bp);
  if x509_ca=nil then goto free_all;

  //loadCAPrivateKey
  try
  //rsa:=RSAOpenSSLPrivateKey(ChangeFileExt (cert,'.key'),read_password);
  pkey:=LoadPrivateKey (ChangeFileExt (cert,'.key'),read_password);
  if pkey=nil then exception.Create ('pkey is nul');
  except
  on e:exception do begin log(e.message,1);exit;end;
  end; //try

  //generate key
  {
  log('EVP_PKEY_new');
  pkey := EVP_PKEY_new();
  log('EVP_PKEY_assign_RSA');
  EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
  }

  // load X509 Req
  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509_REQ');
  X509_REQ := PEM_read_bio_X509_REQ(bp, nil, nil, nil);
  BIO_free(bp);
  if X509_REQ=nil then goto free_all;
  //
  x509_cert := X509_new();
  // set version to X509 v3 certificate
  log('X509_set_version');
  X509_set_version(x509_cert,2);
  // set serial
  log('X509_get_serialNumber');
  ASN1_INTEGER_set(X509_get_serialNumber(x509_cert), serial);
  // set issuer name frome ca
  log('X509_set_issuer_name');
  X509_set_issuer_name(x509_cert, X509_get_subject_name(x509_ca ));
  //test ok
  {
  cert_entry := X509_NAME_get_entry(X509_get_subject_name(x509_ca ),X509_NAME_get_index_by_NID(X509_get_subject_name(x509_ca ), NID_commonName, 0));
  entryData := X509_NAME_ENTRY_get_data( cert_entry );
  ASN1_STRING_to_UTF8(CN, entryData);
  writeln(strpas(cn^));
  }
  // set time
  X509_gmtime_adj(X509_get_notBefore(x509_cert), 0);
  X509_gmtime_adj(X509_get_notAfter(x509_cert), days);
  //log('X509_NAME_add_entry_by_txt');
  //X509_NAME_add_entry_by_txt(subject, 'CN', MBSTRING_ASC,pchar('localhost'), -1, -1, 0);
  log('X509_set_subject_name'); //from req -> CN
  X509_set_subject_name(x509_cert, X509_REQ_get_subject_name(X509_REQ));
  //X509_NAME_add_entry_by_NID(X509_get_subject_name(X509_cert), NID_pkcs9_emailAddress, MBSTRING_ASC, pchar('me@domain.com'), -1, -1, 0);
  // set pubkey from req
  pktmp := X509_REQ_get_pubkey(X509_REQ);
  log('X509_set_pubkey');
  ret := X509_set_pubkey(x509_cert, pktmp);
  EVP_PKEY_free(pktmp);
  //

  if ca=true then add_ext(x509_cert, NID_basic_constraints, 'critical,CA:true');
  if alt<>'' then add_ext(x509_cert, NID_subject_alt_name,pchar(alt)); //'DNS:localhost'

  //rfc 5280 - key_usage
  value:=ini_readstring('req_ext','key_usage');
  if value<>'' then add_ext(x509_cert, NID_key_usage, pchar(value)); //'critical,digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment'
  value:=ini_readstring('req_ext','subject_key_identifier');
  //if value<>'' then add_ext(x509_cert, NID_subject_key_identifier, pchar(value)); //'hash'
  if value='hash' then hash_pubkey (x509_cert);
  //not ready, see https://github.com/warmlab/study/blob/master/openssl/x509.c
  //value:=ini_readstring('req_ext','authority_key_identifier');
  //if value<>'' then add_ext(x509_cert, NID_authority_key_identifier, pchar(value)); //'keyid:always,issuer:always'
  value:=ini_readstring('req_ext','ext_key_usage');
  if value<>'' then add_ext(x509_cert, NID_ext_key_usage, pchar(value)); //'critical, clientAuth, serverAuth'

  //do_X509_sign;
  log('do_X509_sign');
  do_X509_sign(x509_cert, pkey, EVP_sha256 ());
  //or simpler?
  //X509_sign(x509_cert, pkey,EVP_sha256());
  //

  {
  cert_rsa := EVP_PKEY_get1_RSA(pkey);
  bp := BIO_new_file(pchar('signed.key'), 'w+');
  log('PEM_write_bio_RSAPrivateKey');
  PEM_write_bio_RSAPrivateKey(bp, cert_rsa,nil {EVP_des_ede3_cbc}, nil, 0, nil, nil);
  BIO_free(bp);
  RSA_free(cert_rsa);
  }
  {
  bp := BIO_new_file(pchar('signed.key'), 'w+');
  log('PEM_write_bio_PrivateKey');
  PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);
  BIO_free(bp);
  }

  //save cert
  bp := BIO_new_file(pchar(ChangeFileExt (filename,'.crt') ), 'w+');
  log('PEM_write_bio_X509');
  PEM_write_bio_X509(bp,x509_cert);
  BIO_free(bp);
  //
  free_all:

  	X509_free(x509_cert);
  	//BIO_free_all(out);

  	X509_REQ_free(X509_REQ);
  	X509_free(x509_ca);
  	EVP_PKEY_free(pkey);

  	result:= ret = 1;

end;


{
PEM Format
Most CAs (Certificate Authority) provide certificates in PEM format in Base64 ASCII encoded files.
The certificate file types can be .pem, .crt, .cer, or .key.
The .pem file can include the server certificate, the intermediate certificate and the private key in a single file.
The server certificate and intermediate certificate can also be in a separate .crt or .cer file.
The private key can be in a .key file.

PKCS#12 Format
The PKCS#12 certificates are in binary form, contained in .pfx or .p12 files.
The PKCS#12 can store the server certificate, the intermediate certificate and the private key in a single .pfx file with password protection.
These certificates are mainly used on the Windows platform.
}

//openssl pkcs12 -inkey priv.key -in cert.crt -export -out cert.pfx
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -nodes -> no encrypted private key
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -> encrypted private key
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.key -nodes -nocerts -> private key only
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -nokeys -> cert only
function mkcert(filename:string;cn:string;privatekey:string='';read_password:string='';serial:string='';ca:boolean=false):boolean;
var
    pkey:PEVP_PKEY=nil;
    rsa:pRSA=nil;
    x509:pX509=nil;
    name:pX509_NAME=nil;
    hfile:thandle=thandle(-1);
    f:file;
    bp:pBIO;
    ret:integer;
    days:long = 5 * 365 * 24 * 3600; // 5 years
    //
    bc:pBASIC_CONSTRAINTS;
    iserial:integer=1;
    asn1:pASN1_INTEGER =nil;
    p:pBIGNUM=nil;
    ctx:pBN_CTX=nil ;
    //
    value:string;
begin
  log('mkCAcert');
  log('filename:'+filename);
  log('cn:'+cn);
  log('privatekey:'+privatekey);
result:=false;

  if privatekey='' then
  begin
  log('RSA_generate_key');
  rsa := RSA_generate_key(
    2048,   //* number of bits for the key - 2048 is a sensible value */
    RSA_F4, //* exponent - RSA_F4 is defined as 0x10001L */
    nil,   //* callback - can be NULL if we aren't displaying progress */
    nil    //* callback argument - not needed in this case */
    );
  //generate key
  //OpenSSL provides the EVP_PKEY structure for storing an algorithm-independent private key in memory
  log('EVP_PKEY_new');
  pkey := EVP_PKEY_new();
  //assign key to our struct
  //log('EVP_PKEY_assign_RSA');
  //EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
  log('EVP_PKEY_set1_RSA');
  EVP_PKEY_set1_RSA (pkey,rsa);
  end
  else
  begin
  log('Reusing '+privatekey+'...',1);
  try
  //rsa:=RSAOpenSSLPrivateKey(privatekey,read_password); //password will be prompted
  pkey:=LoadPrivateKey (privatekey,read_password);
  if pkey=nil then exception.Create ('pkey is nul');
  except
  on e:exception do begin log(e.message,1);exit;end;
  end; //try
  end;



//OpenSSL uses the X509 structure to represent an x509 certificate in memory
log('X509_new');
x509 := X509_new();
// set version to X509 v3 certificate
log('X509_set_version');
X509_set_version(x509,2);
//Now we need to set a few properties of the certificate
if serial='' then  ASN1_INTEGER_set (X509_get_serialNumber(x509), iserial);
if serial<>'' then
begin
ctx := BN_CTX_new();
p := BN_new();
BN_hex2bn(p, @serial[1]);
//openssl x509 -noout -serial -in ca.crt
//Writeln('BN_bn2hex: ', strpas(BN_bn2hex(p )));
asn1:=BN_to_ASN1_INTEGER (p,nil);
X509_set_serialNumber(x509,asn1);
end;
//
X509_gmtime_adj(X509_get_notBefore(x509), 0);
X509_gmtime_adj(X509_get_notAfter(x509), days);
//Now we need to set the public key for our certificate using the key we generated earlier
log('X509_set_pubkey');
X509_set_pubkey(x509, pkey);
//Since this is a self-signed certificate, we set the name of the issuer to the name of the subject
log('X509_NAME_new');
name := X509_NAME_new ; //X509_get_subject_name(x509);
//
name_add_entry('cert',name);
//
log('X509_NAME_add_entry_by_txt');
X509_NAME_add_entry_by_txt(name, 'CN', MBSTRING_ASC,pchar(cn), -1, -1, 0);
//
log('X509_set_subject_name');
ret:=X509_set_subject_name(x509, name);
//Now we can actually set the issuer name:
log('X509_set_issuer_name');
X509_set_issuer_name(x509, name);

{
bc:=BASIC_CONSTRAINTS_new;
bc^.ca :=1;
X509_add1_ext_i2d(x509, NID_basic_constraints,bc,1,0 ); //'critical,CA:TRUE'
}

//https://www.openssl.org/docs/man1.1.1/man3/X509V3_EXT_d2i.html
if ca=true then add_ext(x509, NID_basic_constraints, 'critical,CA:TRUE');
value:=ini_readstring('cert_ext','key_usage');
if value='' then value:='digitalSignature';
if value<>'' then add_ext(x509, NID_key_usage, pchar(value)); //'critical,keyCertSign,cRLSign'
value:=ini_readstring('cert_ext','subject_key_identifier');
//if value<>'' then add_ext(x509, NID_subject_key_identifier, pchar(value)); //'hash'
if value='hash' then hash_pubkey (x509);
//value:=ini_readstring('cert_ext','authority_key_identifier');
//if value<>'' then add_ext(x509, NID_authority_key_identifier, pchar(value)); //'keyid:always,issuer:always'
value:=ini_readstring('cert_ext','ext_key_usage');
if value<>'' then add_ext(x509, NID_ext_key_usage, pchar(value)); //'critical, clientAuth, serverAuth'

//And finally we are ready to perform the signing process. We call X509_sign with the key we generated earlier. The code for this is painfully simple:
log('X509_sign');
X509_sign(x509, pkey, EVP_sha256());

//write out to disk
//if we loaded an existing private key, we could skip the below
if privatekey='' then
begin
  bp := BIO_new_file(pchar(GetCurrentDir+'\'+ChangeFileExt (filename,'.key')), 'w+');
  //PEM_write_bio_PrivateKey(bp,pkey,nil,nil,0,nil,nil);
  //if you want a prompt for passphrase
  log('PEM_write_bio_PrivateKey');
  ret:= PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil); //not saving as RSA key??
  BIO_free(bp);
  if ret=0 then exit;
end;

bp := BIO_new_file(pchar(GetCurrentDir+'\'+filename), 'w+');
log('PEM_write_bio_X509');
ret:=PEM_write_bio_X509(bp,x509);
BIO_free(bp);
if ret=0 then exit;

//or a bundle
{
bp := BIO_new_file(pchar(GetCurrentDir+'\cert.crt'), 'w+');
PEM_write_bio_X509(bp,x509);
PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);
BIO_free(bp);
}
//free
X509_free(x509);
EVP_PKEY_free(pkey);
RSA_free(rsa);
//
result:=true;
end;

//to sign a csr
//openssl x509 -req -in device.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out device.crt -days 500 -sha256
function mkreq(cn: string; keyfile, csrfile: string): boolean;
var
  ret: integer;
  rsa: pRSA;
  bne: pBIGNUM;
  bp: pBIO;
  req: pX509_REQ;
  key: pEVP_PKEY;
  name: pX509_NAME;
  basePath: string;
begin
  log('mkreq');
  log('csrfile:' + csrfile);
  log('privatekey:' + keyfile);
  log('cn:' + cn);

  result := false;
  key := nil;
  req := nil;
  basePath := IncludeTrailingPathDelimiter(GetCurrentDir);

  // 1. Obtention de la clé privée
  if keyfile = '' then
  begin
    log('Génération nouvelle clé RSA...');
    RAND_poll;
    bne := BN_new();
    if bne = nil then Exit;

    try
      BN_set_word(bne, RSA_F4);
      rsa := RSA_new();
      if rsa = nil then Exit;

      if RSA_generate_key_ex(rsa, 2048, bne, nil) <> 1 then
      begin
        RSA_free(rsa);
        Exit;
      end;

      key := EVP_PKEY_new();
      if (key = nil) or (EVP_PKEY_assign(key, EVP_PKEY_RSA, PChar(rsa)) <> 1) then
      begin
        if key <> nil then EVP_PKEY_free(key) else RSA_free(rsa);
        Exit;
      end;
    finally
      BN_free(bne);
    end;
  end
  else
  begin
    log('Reusing ' + keyfile + '...', 1);
    key := LoadPrivateKey(keyfile);
    if key = nil then
    begin
      log('Erreur: Impossible de charger la cle ' + keyfile, 1);
      Exit; // Annule proprement au lieu de continuer avec un pointeur nil
    end;
  end;

  try
    // 2. Création de la requête X509
    log('X509_REQ_new');
    req := X509_REQ_new();
    if req = nil then Exit;

    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, key);

    log('X509_NAME_new');
    name := X509_NAME_new();
    if name <> nil then
    begin
      name_add_entry('req', name);
      log('X509_NAME_add_entry_by_txt');
      X509_NAME_add_entry_by_txt(name, 'CN', MBSTRING_ASC, PChar(cn), -1, -1, 0);
      log('X509_REQ_set_subject_name');
      X509_REQ_set_subject_name(req, name);
      X509_NAME_free(name);
    end;

    log('X509_REQ_sign');
    if X509_REQ_sign(req, key, EVP_sha256()) = 0 then Exit;

    // 3. Sauvegarde de la clé si elle a été générée
    if keyfile = '' then
    begin
      bp := BIO_new_file(PChar(basePath + ChangeFileExt(csrfile, '.key')), 'w+');
      if bp <> nil then
      begin
        log('PEM_write_bio_PrivateKey (no password)');
        PEM_write_bio_PrivateKey(bp, key, nil, nil, 0, nil, nil);
        BIO_free(bp);
      end;
    end;

    // 4. Sauvegarde de la requête CSR
    bp := BIO_new_file(PChar(basePath + csrfile), 'w+');
    if bp <> nil then
    begin
      log('PEM_write_bio_X509_REQ');
      PEM_write_bio_X509_REQ(bp, req);
      BIO_free(bp);
      result := true;
    end;

  finally
    // Toujours libérer key et req, quelle que soit leur provenance
    if req <> nil then X509_REQ_free(req);
    if key <> nil then EVP_PKEY_free(key);
  end;
end;



//PKCS#8
function generate_rsa_key_2: boolean;
label
  cleanup;
var
  ret: integer;
  rsa: pRSA;
  bne: pBIGNUM;
  bp_public: pBIO;
  bp_private: pBIO;
  bits: integer;
  e: ulong;
  pkey: PEVP_PKEY;
  success: boolean;
  basePath: string;
begin
  result := false;
  success := false;
  rsa := nil;
  bne := nil;
  bp_public := nil;
  bp_private := nil;
  pkey := nil;
  bits := 2048;
  e := RSA_F4;
  basePath := IncludeTrailingPathDelimiter(GetCurrentDir);

  // 1. Initialisation du PRNG et BIGNUM
  RAND_poll;
  bne := BN_new();
  if bne = nil then goto cleanup;

  if BN_set_word(bne, e) <> 1 then goto cleanup;

  // 2. Génération RSA
  rsa := RSA_new();
  if rsa = nil then goto cleanup;

  log('1. generate rsa key');
  if RSA_generate_key_ex(rsa, bits, bne, nil) <> 1 then goto cleanup;

  log('EVP_PKEY_new');
  pkey := EVP_PKEY_new();
  if pkey = nil then goto cleanup;

  log('EVP_PKEY_assign');
  // EVP_PKEY_assign transfère la propriété de rsa vers pkey
  if EVP_PKEY_assign(pkey, EVP_PKEY_RSA, PChar(rsa)) <> 1 then goto cleanup;

  // rsa est désormais géré par pkey, on évite le RSA_free direct
  rsa := nil;

  // 3. Sauvegarde clé publique PEM
  bp_public := BIO_new_file(PChar(basePath + 'public.pem'), 'w+');
  if bp_public = nil then goto cleanup;

  log('2. save public key OK');
  if PEM_write_bio_PUBKEY(bp_public, pkey) <> 1 then goto cleanup;

  // 4. Sauvegarde clé privée PEM
  bp_private := BIO_new_file(PChar(basePath + 'private.pem'), 'w+');
  if bp_private = nil then goto cleanup;

  log('3. save private key (no password)');
  if PEM_write_bio_PrivateKey(bp_private, pkey, nil, nil, 0, nil, nil) <> 1 then goto cleanup;

  success := true;

cleanup:
  log('free_all');
  if bp_public <> nil then BIO_free_all(bp_public);
  if bp_private <> nil then BIO_free_all(bp_private);
  if rsa <> nil then RSA_free(rsa);
  if bne <> nil then BN_free(bne);
  if pkey <> nil then EVP_PKEY_free(pkey);

  result := success;
end;

//RSA_public_encrypt, RSA_private_decrypt - RSA public key cryptography
//versus
//RSA_private_encrypt, RSA_public_decrypt - low-level signature operations ... using the private key rsa
function Encrypt_Pub(sometext:string;var encrypted:string):boolean;
var
	rsa: pRSA=nil; 
	size: Integer;
	FCryptedBuffer: pointer; // Выходной буфер
	b64, bio_mem,bio: pBIO;
	str, data: AnsiString;
	len, b64len,written: Integer;
	penc64: PAnsiChar=nil;
	err: Cardinal;
        //
        //FPublicKey: pEVP_PKEY;
        FKey: pEVP_PKEY=nil;

begin
  result:=false;
  FKey := LoadPublicKey('public.pem');

  //load the private key but then you lose the benefit of private/public key...
  //unless you want both end to encrypt/decrypt with a unique private key
  //FKey := LoadPrivateKey('private.pem');

  //
  if FKey=nil then exit;
  //
	rsa := EVP_PKEY_get1_RSA(FKey);
	EVP_PKEY_free(FKey);
	size := RSA_size(rsa);
    log('RSA_size:'+inttostr(size));
	GetMem(FCryptedBuffer, size);
	str := AnsiString(sometext);

	//RSA_public_encrypt
	len := RSA_public_encrypt(Length(str),
	                          PByte(@str[1]),
				  FCryptedBuffer,
				  rsa,
				  RSA_PKCS1_PADDING);
     log('RSA_public_encrypt:'+inttostr(len));
     
	if len > 0 then 
	  begin
	  // configure base64 filter to decode
		b64 := BIO_new(BIO_f_base64); // BIO base64
                BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
                // configure a memory bio & chain bios
                bio_mem:=BIO_new(BIO_s_mem);
		bio := BIO_push(b64, bio_mem);
		try
                        // write to target chain and flush
                        log('BIO_write');
			written:=BIO_write(bio, pbyte(FCryptedBuffer), len); // Запись в Stream бинарного выходного буфера
                        log('BIO_write:'+inttostr(written));
                        //written := ((written div 3) * 4) + 1;b64len:=written;
			//BIO_flush(mem); //deprecated?
                        Bio_flush(bio);
                        // reap memory buffer
                        log('BIO_read');
                        setlength(data,1024);
                        b64len:=BIO_read(bio_mem, @data[1], 1024); //works
                        //b64len:=bio_read(bio,pbyte(data),1024);  //does not work
                        log('bio_read:'+inttostr(b64len));
                        //b64len := BIO_get_mem_data(mem, penc64); //получаем размер строки в base64
			//SetLength(data, b64len); // задаем размер выходному буферу
			//Move(penc64^, PAnsiChar(data)^, b64len); // Перечитываем в буфер data строку в base64
                        setlength(encrypted,b64len);
                        copymemory(@encrypted[1],@data[1],b64len);
		finally
			BIO_free(bio_mem);
		end;
	  end
	  else
	  begin // читаем ошибку, если длина шифрованной строки -1
		err := ERR_get_error;
		repeat
			log(string(ERR_error_string(err, nil)),1);
			err := ERR_get_error;
		until err = 0;
	  end;
	RSA_free(rsa);
        result:=true;
end;

{
-Generate private key
openssl genrsa 2048 > private2.pem
-Generate public key from private
openssl rsa -in private2.pem -pubout > public2.pem
}
function Decrypt_Priv(ACryptedData:string):boolean;
var
  rsa: pRSA=nil;
  out_: AnsiString;
  str, data: PAnsiChar;
  len, b64len: Integer;
  penc64: PAnsiChar;
  b64, mem, bio_out, bio: pBIO;
  size: Integer;
  err: Cardinal;
  //
  FKey: pEVP_PKEY=nil;
  bp:pBIO;
  x: pEVP_PKEY;
begin

        //FKey:=LoadPublicKey('public.pem');
        FKey:=LoadPrivateKey('private.pem');
        if FKey = nil then
        begin
        	err := ERR_get_error;
        	repeat
        		log(string(ERR_error_string(err, nil)),1);
        		err := ERR_get_error;
        	until err = 0;
                exit;
        	end;

        //
        log('EVP_PKEY_get1_RSA');
	rsa := EVP_PKEY_get1_RSA(FKey);
        EVP_PKEY_free(FKey);
        if rsa=nil then exit;


        //we could load the rsa directly from the private key as well
        {
        bp := BIO_new_file(pchar('private.pem'), 'r+');
        log('PEM_read_bio_RSAPrivateKey');
        rsa:=PEM_read_bio_RSAPrivateKey   (bp,nil,nil,nil);
        BIO_free(bp);
        if rsa=nil then exit;
        }

        log('RSA_size');
        size := RSA_size(rsa);
        log('RSA_size:'+inttostr(size));
	GetMem(data, 1024);  // Определяем размер выходному буферу дешифрованной строки
	GetMem(str, 1024); // Определяем размер шифрованному буферу после конвертации из base64

	//Decode base64
        log('Length(ACryptedData):'+inttostr(Length(ACryptedData)));
	b64 := BIO_new(BIO_f_base64);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	mem := BIO_new_mem_buf(PAnsiChar(ACryptedData), Length(ACryptedData));
	//BIO_flush(mem); //deprecated? //not needed when reading
	mem := BIO_push(b64, mem);
        log('BIO_read');
	len:=BIO_read(mem, pbyte(str) , Length(ACryptedData)); // Получаем шифрованную строку в бинарном виде
        log('BIO_read:'+inttostr(len));
	BIO_free_all(mem);
	// Дешифрование
        log('RSA_private_decrypt');
	len := RSA_private_decrypt(size, pbyte(str), pbyte(data), rsa, RSA_PKCS1_PADDING);
        log(inttostr(len));
        if len > 0 then
	begin
	// в буфер data данные расшифровываются с «мусором» в конца, очищаем, определяем размер переменной out_ и переписываем в нее нужное количество байт из data
		SetLength(out_, len);
		Move(data^, PAnsiChar(out_ )^, len);
                writeln(out_);
	end
	else
        begin // читаем ошибку, если длина шифрованной строки -1
		err := ERR_get_error;
		repeat
			writeln(string(ERR_error_string(err, nil)));
			err := ERR_get_error;
		until err = 0;
	end;
end;

procedure PrintFingerprint(cert: PX509);
var
md: array[0..EVP_MAX_MD_SIZE - 1] of Byte;
md_len: Cardinal; i: Integer;
begin
        if X509_digest(cert, EVP_sha1(), @md, @md_len) = 0 then
        begin
        WriteLn('Error computing fingerprint');
        Exit;
        end;
        Write('Fingerprint (SHA-1): ');
        for i := 0 to md_len - 1 do Write(IntToHex(md[i], 2)); WriteLn;
end;

function print_req(filename:string):boolean;
var
 bp:pbio;
 X509_REQ:pX509_REQ;
 name:pX509_NAME=nil;
 b64len,key_len,i,size:cardinal;
 key:pEVP_PKEY;
 bio_mem,bio_base64,bio:pBIO;
 data:array [0..4095] of char;
 key_buf,pb:pbyte;
 digest:array [0..EVP_MAX_MD_SIZE-1] of byte;
begin
  result:=false;
  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509_REQ');
  X509_REQ := PEM_read_bio_X509_REQ(bp, nil, nil, nil);
  BIO_free(bp);

  log('X509_REQ_get_subject_name');
  NAME:=X509_REQ_get_subject_name(X509_REQ);
  writeln('subject_name:'+getdn(name));

  log('X509_REQ_get_pubkey');
  key:=X509_REQ_get_pubkey (X509_REQ);
  //lets display the pubkey
  bio_mem := BIO_new(BIO_s_mem());
  bio_base64 := BIO_new(BIO_f_base64());
  bio:=BIO_push(bio_base64, bio_mem);
  //write to bio
  PEM_write_bio_PUBKEY(bio_base64, key );
  Bio_flush(bio_base64);
  //read from bio
  b64len:=BIO_read(bio_base64, @data[0], sizeof(data)-1);
  writeln();
  data[b64len] := #0;
  writeln('Public key base64:');
  writeln(data);
  //EVP_PKEY_free(key);
  BIO_free_all(bio_base64);//BIO_free(bio_base64);BIO_free(bio_mem);

  key_len := i2d_PUBKEY(key, nil);
  GetMem(key_buf, key_len);
  pb:=key_buf ; //https://stackoverflow.com/questions/50952528/get-publickey-certificate-in-der-format-with-openssl-in-c
  key_len := i2d_PUBKEY(key, @key_buf);
  writeln('Public key hex:');
  for i := 0 to key_len - 1 do Write(IntToHex(pb[i], 2));
  writeln;

  if evp_digest(pb , key_len,@digest[0],@size,EVP_sha1(),nil)=1 then
     begin
     writeln('Public key hash (sha1):');
     for i:=0 to size -1 do write(inttohex(digest[i],2));
     writeln;
     end;

  result:=true;
end;

//openssl rsa -noout -text -in ca.key
function print_private(filename:string;password:string=''):boolean;
var
   rsa:pRSA=nil;
   pkey:pEVP_PKEY ;
   bin:pointer;
   size,i,b64len,key_len:cardinal;
   digest:array [0..EVP_MAX_MD_SIZE-1] of byte;
   modulus:pbignum;
   bio_mem,bio_base64,bio:pbio;
   data:array [0..4095] of char;
   pb,key_buf:pbyte;
begin
  result:=false;
  //rsa:=RSAOpenSSLPrivateKey (filename,password); //password will be prompted
  pkey:=LoadPrivateKey (filename,password);
  if pkey=nil then exit;

  //lets display the pubkey
  bio_mem := BIO_new(BIO_s_mem());
  bio_base64 := BIO_new(BIO_f_base64());
  bio:=BIO_push(bio_base64, bio_mem);
  //write to bio
  PEM_write_bio_PUBKEY(bio_base64, pkey );
  Bio_flush(bio_base64);
  //read from bio
  b64len:=BIO_read(bio_base64, @data[0], sizeof(data)-1);
  writeln();
  data[b64len] := #0;
  writeln('Public key base64:');
  writeln(data);
  //EVP_PKEY_free(key);
  BIO_free(bio);//BIO_free(bio_base64);BIO_free(bio_mem);

  key_len := i2d_PUBKEY(pkey, nil);
  GetMem(key_buf, key_len);
  pb:=key_buf ; //https://stackoverflow.com/questions/50952528/get-publickey-certificate-in-der-format-with-openssl-in-c
  key_len := i2d_PUBKEY(pkey, @key_buf);
  writeln('Public key hex:');
  for i := 0 to key_len - 1 do Write(IntToHex(pb[i], 2));
  writeln;

  if evp_digest(pb , key_len,@digest[0],@size,EVP_sha1(),nil)=1 then
          begin
          writeln('Public key hash (sha1):');
          for i:=0 to size -1 do write(inttohex(digest[i],2));
          writeln;
          end;
  rsa:=EVP_PKEY_get1_RSA(pkey);
  modulus:=rsa_get0_n(rsa);
  //try if rsa<>nil then Writeln('BN_bn2hex N: ', strpas(BN_bn2hex(rsa^.n )));except end;
  //try if rsa<>nil then Writeln('BN_bn2hex D: ', strpas(BN_bn2hex(rsa^.d  )));except end; //exponent
  writeln();
  Writeln('Modulo:');
  try if rsa<>nil then Writeln(BN_bn2hex(modulus ));except end;
  //
  bin:=getmem(BN_num_bytes(BN_num_bits(modulus)));
  BN_bn2bin(modulus,bin);
  if evp_digest(bin , BN_num_bytes(BN_num_bits(modulus)),@digest[0],@size,EVP_sha1(),nil)=1 then
     begin
     write('hash sha1:');
     for i:=0 to size -1 do write(inttohex(digest[i],2));
     writeln;
     end;

  //try if rsa<>nil then Writeln('BN_bn2hex P: ', strpas(BN_bn2hex(rsa^.p   )));except end;
  //try if rsa<>nil then Writeln('BN_bn2hex Q: ', strpas(BN_bn2hex(rsa^.q   )));except end;
   result:=true;
end;

function getSerialNumber(x509:px509): String;
var
   Buffer : array [0..31] of char;
   v: pASN1_OCTET_STRING ;
   b:byte;
begin
  result:='';
   v := X509_get_serialNumber(x509);
   //StrLCopy(pansichar(@buffer), v^.data, v^.length);
   for b:=0 to v^.length-1 do result:=result+inttohex(pbyte(v^.data)[b],2); //to be checked
   //Result:=Buffer;
end;

function getDN(pDn: pX509_NAME): String;
var
  buffer: array [0..1023] of char;
begin
X509_NAME_oneline(pDn, @buffer, SizeOf(buffer));
result := StrPas(@buffer);
end;

// Extract a ASN1 time

function getTime(asn1_time: pASN1_TIME): TDateTime;
var
  buffer: array [0..31] of char;
  tz, Y, M, D, h, n, s: integer;
//  tmpbio: pBIO;
  function Char2Int(d, u: char): integer;
  begin
  if (d < '0') or (d > '9') or (u < '0') or (u > '9') then
    raise exception.Create('Invalid ASN1 date format (invalid char).');
  result := (Ord(d) - Ord('0'))*10 + Ord(u) - Ord('0');
  end;
begin
{
i2d_ASN1_TIME(asn1_time, @buffer2);
if buffer='' then
  result := time
else
  result := 0;
}

if (asn1_time^.&type <> V_ASN1_UTCTIME)
    and (asn1_time^.&type <> V_ASN1_GENERALIZEDTIME) then
  raise exception.Create('Invalid ASN1 date format.');

tz := 0;
s := 0;

//StrLCopy(@buffer, asn1_time^.data, asn1_time^.length);
copymemory(@buffer, asn1_time^.data, asn1_time^.length);

if asn1_time^.&type = V_ASN1_UTCTIME then
  begin
  if asn1_time^.length < 10 then
    raise exception.Create('Invalid ASN1 UTC date format (too short).');
	Y := Char2Int(buffer[0], buffer[1]);
    if Y < 50 then
      Y := Y + 100;
    Y := Y + 1900;
    M := Char2Int(buffer[2], buffer[3]);
    D := Char2Int(buffer[4], buffer[5]);
    h := Char2Int(buffer[6], buffer[7]);
    n := Char2Int(buffer[8], buffer[9]);
    if (buffer[10] >= '0') and (buffer[10] <= '9')
        and (buffer[11] >= '0') and (buffer[11] <= '9') then
      s := Char2Int(buffer[10], buffer[11]);
    if buffer[asn1_time^.length-1] = 'Z' then
      tz := 1;
  end
else if asn1_time^.&type = V_ASN1_GENERALIZEDTIME then
  begin
  if asn1_time^.length < 12 then
    raise exception.Create('Invalid ASN1 generic date format (too short).');
    Y := Char2Int(buffer[0], buffer[1])*100 + Char2Int(buffer[2], buffer[3]);;
    M := Char2Int(buffer[4], buffer[5]);
    D := Char2Int(buffer[6], buffer[7]);
    h := Char2Int(buffer[8], buffer[9]);
    n := Char2Int(buffer[10], buffer[11]);
    if (buffer[12] >= '0') and (buffer[12] <= '9')
        and (buffer[13] >= '0') and (buffer[13] <= '9') then
      s := Char2Int(buffer[12], buffer[13]);
    if buffer[asn1_time^.length-1] = 'Z' then
      tz := 1;
  end;
if tz > 0 then
  result := IncHour(EncodeDateTime(Y, M, D, h+tz, n, s, 0), tz)
else
  result := EncodeDateTime(Y, M, D, h, n, s, 0);
{tmpbio := BIO_new(BIO_s_mem());
ASN1_TIME_print(tmpbio, asn1_time);
BIO_read(tmpbio, @buffer, SizeOf(buffer));
BIO_free_all(tmpbio);
if buffer = '' then
  result := time
else
  result := time}
end;


//openssl x509 -noout -text -in ca.crt
//openssl pkey -in ca.key -pubout -outform pem
//openssl x509 -in certificate.crt -pubkey -noout -outform pem
function print_cert(filename:string):boolean;
var
    rsa:pRSA=nil;
    //
    ctx:pBN_CTX;
    p:pBIGNUM;
    bp:pBIO=nil;
    n:integer=0;
    x509:pX509 ;
    key:pEVP_PKEY ;
    digest:array [0..EVP_MAX_MD_SIZE-1] of byte;
    size,i,num,b64len,key_len:cardinal;
    context:PEVP_MD_CTX;
    bin:pointer;
    name:pX509_NAME=nil;
    usage:PASN1_STRING;
    modulus:pbignum=nil;
    certs:pSTACK_OFX509;
    bio_mem,bio_base64,bio:pBIO;
    data:array [0..4095] of char;
    key_buf,pb:pbyte;
begin
  result:=false;
  //rsa:=RSAOpenSSLCert(filename);

  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509_REQ');
  certs := openssl_sk_new_null();
  while 1=1 do
  begin
       X509 := PEM_read_bio_X509(bp, nil, nil, nil);
       if x509 =nil then break;
       openssl_sk_push(certs, X509);
  end;
  BIO_free(bp);
  //

  for num:=0 to openssl_sk_num (certs) -1 do
  begin
  x509:=openssl_sk_value(certs,num);
  writeln('***********************************************');
  //
  log('X509_get_subject_name');
  NAME:=X509_get_subject_name(x509);
  writeln('subject_name:'+getdn(name));
  //
  log('X509_get_issuer_name');
  NAME:=X509_get_issuer_name(x509);
  writeln('issuer_name:'+getdn(name));
  //
  log('X509_get_pubkey');
  key:=X509_get_pubkey (x509);
  //lets display the pubkey
  bio_mem := BIO_new(BIO_s_mem());
  bio_base64 := BIO_new(BIO_f_base64());
  bio:=BIO_push(bio_base64, bio_mem);
  //write to bio
  PEM_write_bio_PUBKEY(bio_base64, key );
  Bio_flush(bio_base64);
  //read from bio
  b64len:=BIO_read(bio_base64, @data[0], sizeof(data)-1);
  writeln();
  data[b64len] := #0;
  writeln('Public key base64:');
  writeln(data);
  //EVP_PKEY_free(key);
  BIO_free(bio);//BIO_free(bio_base64);BIO_free(bio_mem);
  key_len := i2d_PUBKEY(key, nil);
  GetMem(key_buf, key_len);
  pb:=key_buf ; //https://stackoverflow.com/questions/50952528/get-publickey-certificate-in-der-format-with-openssl-in-c
  key_len := i2d_PUBKEY(key, @key_buf);
  writeln('Public key hex:');
  for i := 0 to key_len - 1 do Write(IntToHex(pb[i], 2));
  writeln;

  if evp_digest(pb , key_len,@digest[0],@size,EVP_sha1(),nil)=1 then
          begin
          writeln('Public key hash (sha1):');
          for i:=0 to size -1 do write(inttohex(digest[i],2));
          writeln;
          end;

  //key:=LoadCertPublicKey(filename);
  rsa:=EVP_PKEY_get1_RSA(key);
  if rsa=nil then log('rsa=nil');
  modulus:=rsa_get0_n(rsa);
  
  
  
  
  
  writeln();
  Writeln('Modulo: ', lowercase(BN_bn2hex(modulus)));

  //
  bin:=getmem(BN_num_bytes(BN_num_bits(modulus)));
  BN_bn2bin(modulus,bin);
  {
  size:=0;
  context := EVP_MD_CTX_create();
  EVP_DigestInit(context,EVP_sha1());
  EVP_DigestUpdate(context, bin, BN_num_bytes(rsa^.e));
  EVP_DigestFinal(context, @digest[0], size);
  EVP_MD_CTX_destroy (context);
  }
  //
  if evp_digest(bin , BN_num_bytes(BN_num_bits(modulus)),@digest[0],@size,EVP_sha1(),nil)=1 then
     begin
     writeln('Modulo hash (sha1):');
     for i:=0 to size -1 do write(inttohex(digest[i],2));
     writeln;
     end;
  //try if rsa<>nil then Writeln('BN_bn2hex P: ', strpas(BN_bn2hex(rsa^.p   )));except end;
  //try if rsa<>nil then Writeln('BN_bn2hex Q: ', strpas(BN_bn2hex(rsa^.q   )));except end;

  writeln();
  writeln('key_usage:');
  usage := X509_get_ext_d2i(x509, NID_key_usage, nil, nil);
  if (byte(usage^.data^) and $80)=$80 then writeln('  digitalSignature');
  if (byte(usage^.data^) and $40)=$40 then writeln('  nonrepudiation ');
  if (byte(usage^.data^) and $20)=$20 then writeln('  keyEncipherment ');
  if (byte(usage^.data^) and $10)=$10 then writeln('  dataEncipherment');
  if (byte(usage^.data^) and $08)=$08 then writeln('  keyAgreement');
  if (byte(usage^.data^) and $04)=$04 then writeln('  keyCertSign');
  if (byte(usage^.data^) and $02)=$02 then writeln('  cRLSign');

  {
  //todo
  usage:=X509_get_ext_d2i(x509, NID_ext_key_usage,nil, nil);
  }

  writeln;
  try
  log('X509_get_notBefore');
  writeln('notBefore:'+DateTimeToStr (getTime (X509_get_notBefore(x509))));
  log('X509_get_notAfter');
  writeln('notAfter:'+DateTimeToStr (getTime (X509_get_notAfter (x509))));
  except
  on e:exception do writeln(e.message);
  end;

  writeln;
  PrintFingerprint(x509);

  end; //for i...

  {
  bp := BIO_new_file(pchar(filename), 'r+');
  log('PEM_read_bio_X509');
  x509:=PEM_read_bio_X509(bp,nil,nil,nil);
  key:=X509_get_pubkey(x509);
  BIO_free(bp);
  }

  //or
  {
  bp := BIO_new(BIO_s_mem);
  log('BN_print');
  BN_print(bp, rsa^.e);
  log('BIO_ReadAnsiString');
  Writeln('BN_print: ',BIO_ReadAnsiString(bp));
  BIO_free(bp);
  }
  //test ok
  {
  ctx := BN_CTX_new();
  p := BN_new();
  BN_hex2bn(p, 'F7E75FDC469067FFDC4E847C51F452DF');
  Writeln('BN_bn2hex: ', strpas(BN_bn2hex(p )));
  }
  //
  result:=true;
end;

function set_password(filename,password:string):boolean;
var
pkey:pEVP_PKEY ;
bp:pBio;
begin
result:=false;
pkey:=LoadPrivateKey (filename);
if pkey=nil then
           begin
           writeln('LoadPrivateKey failed');
           exit;
           end;

  bp := BIO_new_file(pchar(GetCurrentDir+'\'+'new_'+filename), 'w+');
  log('PEM_write_bio_PrivateKey');
  //with or without a password
  if password=''
     then result:=PEM_write_bio_PrivateKey(bp,pkey,nil,nil,0,nil,nil)<>-1
     else result:=PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc,pbyte(password),length(password),nil,nil)<>-1;

  BIO_free(bp);

end;

procedure ciphers_sorted(cipher:pEVP_CIPHER; from:pchar;_to:pchar; x:pointer); cdecl;
begin
  log('ciphers');
  if cipher<>nil then writeln(strpas(OBJ_nid2sn(EVP_CIPHER_nid(cipher))));
end;

procedure ciphers(cipher:pEVP_CIPHER; x:pointer); cdecl;
begin
  log('ciphers');
  if cipher<>nil then writeln(strpas(OBJ_nid2sn(EVP_CIPHER_nid(cipher))));
end;

function list_ciphers:boolean;
begin
  result:=false;
  log('list_ciphers');
  EVP_CIPHER_do_all_sorted (@ciphers_sorted, nil);
  result:=true;
end;

procedure hashes_sorted(hash:pEVP_MD; from:pchar;_to:pchar; x:pointer); cdecl;
begin
  log('hashes');
  if hash<>nil then writeln(strpas(OBJ_nid2sn(EVP_MD_type(hash))));
end;

function list_hashes:boolean;
begin
  result:=false;
  log('list_hashes');
  EVP_MD_do_all_sorted (@hashes_sorted, nil);
  result:=true;
end;

function crypt(algo,input:string;keystr:string='';ivstr:string='';enc:integer=1):boolean;
const EVP_MAX_MD_SIZE=64;
const MD5_DIGEST_LENGTH=16;
      //key:array[0..15] of byte=($11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11,$11);
      //iv:array[0..7] of byte=($22,$22,$22,$22,$22,$22,$22,$22);
var
context:PEVP_CIPHER_CTX=nil ;
cipher :pEVP_CIPHER=nil;
buffer:array [0..EVP_MAX_MD_SIZE -1] of byte;
buffer_len:cardinal=0;
i:byte;
ret,remain:integer;
//
//key:array [0..7] of char;
//iv:array [0..7] of char;
digest:array [0..MD5_DIGEST_LENGTH-1] of byte;
key,iv,encrypted:array of byte;
begin

   result:=false;

   log('input:'+input);
   log('algo:'+algo);

   log('EVP_CIPHER_CTX_new');
   context:=EVP_CIPHER_CTX_new ;

   //cbc requires iv
   //ecb does not require iv
   log('EVP_CIPHER_CTX_init');
   //EVP_CIPHER_CTX_init (context);
   context := EVP_CIPHER_CTX_new();
   //
   //DES uses a key length of 8 bytes (64 bits).
   //DES uses an IV length of 8 bytes (64 bits).
   //Triple DES uses a key length of 24 bytes (192 bits).
   {
   if lowercase(algo)='des-ecb' then cipher := EVP_des_ecb(); //ok
   if lowercase(algo)='des-cbc' then cipher := EVP_des_cbc(); //ok
   //
   if lowercase(algo)='des-ede3-ecb' then cipher := EVP_des_ede3_ecb (); //ok
   if lowercase(algo)='des-ede3-cbc' then cipher := EVP_des_ede3_cbc(); //ok
   //
   if lowercase(algo)='rc4' then cipher := EVP_rc4(); //ok
   if lowercase(algo)='rc2-ecb' then cipher := EVP_rc2_ecb (); //ok
   if lowercase(algo)='rc2-cbc' then cipher := EVP_rc2_cbc (); //ok

   //The following algorithms will be used based on the size of the key:
   //16 bytes = AES-128
   //24 bytes = AES-192
   //32 bytes = AES-256
   if lowercase(algo)='aes-128-ecb' then cipher := EVP_aes_128_ecb(); //ok
   if lowercase(algo)='aes-192-ecb' then cipher := EVP_aes_192_ecb(); //ok
   if lowercase(algo)='aes-256-ecb' then cipher := EVP_aes_256_ecb(); //ok
   }

   cipher:=EVP_get_cipherbyname(pchar(algo));

   if cipher=nil then
      begin
      writeln('cipher=nil');
      exit;
      end;

   log('cipher:'+strpas(OBJ_nid2sn(EVP_CIPHER_nid(cipher))));

   //lets retrieve some cipher details (key and iv length)
   ret:=EVP_CipherInit_ex(context, cipher, nil, nil, nil,enc);
   if ret<>1 then raise exception.Create ('EVP_CipherInit_ex failed');
   log('key_length:'+inttostr(EVP_CIPHER_CTX_key_length(context)));
   log('iv_length:'+inttostr(EVP_CIPHER_CTX_iv_length(context)));
   log('block_size:'+inttostr(EVP_CIPHER_block_size(cipher)));

   //lets md5 hash our key (which will give us 16 bytes so not fit for all algo's)
   //this is optional : all we need is a 16 bytes buffer acting as a key
   //md5 digest in one go thanks to EVP_Digest
   {
   log('EVP_Digest');
   ret:=EVP_Digest(@key[0],sizeof(key),@digest,buffer_len,evp_md5,nil);
   if ret<>1 then raise exception.Create ('EVP_Digest failed');
   //writeln(buffer_len);
   write('key:');
   for i:=0 to buffer_len -1 do write(inttohex(digest[i],2));
   writeln;
   }

   //key was supplied
   if keystr<>'' then
   begin
   key:=HexaStringToByte2 (keystr);
   write('key:');
   for i:=0 to length(key) -1 do write(inttohex(key[i],2));
   writeln;
   end;

   //iv was supplied
   if ivstr<>'' then
   begin
   iv:=HexaStringToByte2 (ivstr);
   write('iv:');
   for i:=0 to length(iv) -1 do write(inttohex(iv[i],2));
   writeln;
   end;
  
   //a key was NOT supplied : use a random key with size N (rather than digest md5 hash)
   if (EVP_CIPHER_CTX_key_length(context)>0) and (keystr='') then
   begin
   writeln('random key');
   setlength(key,EVP_CIPHER_CTX_key_length(context));
   RAND_bytes(@key[0],length(key));
   write('key:');
   for i:=0 to length(key) -1 do write(inttohex(key[i],2));
   writeln;
   end;

   //random iv
   if (EVP_CIPHER_CTX_iv_length(context)>0) and (ivstr='') then
   begin
   writeln('random iv');
   setlength(iv,EVP_CIPHER_CTX_iv_length(context));
   RAND_bytes(@iv[0],length(iv));
   write('iv:');
   for i:=0 to length(iv) -1 do write(inttohex(iv[i],2));
   writeln;
   end;

   log('***********************************');
   log('key_length:'+inttostr(EVP_CIPHER_CTX_key_length(context)));
   log('iv_length:'+inttostr(EVP_CIPHER_CTX_iv_length(context)));
   log('block_size:'+inttostr(EVP_CIPHER_block_size(cipher)));
   log('***********************************');


   if length(key)<> EVP_CIPHER_CTX_key_length(context) then
      begin
      writeln('key length incorrect:'+inttostr(length(key)));
      exit;
      end;

   if (EVP_CIPHER_CTX_iv_length(context)>0) and (length(iv)<> EVP_CIPHER_CTX_iv_length(context)) then
      begin
      writeln('iv length incorrect:'+inttostr(length(iv)));
      exit;
      end;

   //EVP_CIPHER_CTX_set_key_length(context, length(key)); // RC2 is an algorithm with variable key size. Therefore the key size must generally be set.

   //It should be set to 1 for encryption, 0 for decryption
   log('EVP_CipherInit_ex');
   //if pos('cbc',lowercase(algo))>0
   if EVP_CIPHER_ctx_iv_length(context)>0
      then ret:=EVP_CipherInit_ex(context, cipher, nil, @key[0], @iv[0],-1)  //or digest for hash
      else ret:=EVP_CipherInit_ex(context, cipher, nil, @key[0], nil,-1); //-1 use the previous value
   if ret<>1 then raise exception.Create ('EVP_CipherInit_ex failed');

   log('EVP_CipherUpdate');
   if enc=0
      then
      begin
      encrypted:=HexaStringToByte2 (input);
      ret:=EVP_CipherUpdate(context,@buffer[0],@buffer_len,@encrypted[0],length(encrypted));
      end
      else ret:=EVP_CipherUpdate(context,@buffer[0],@buffer_len,pbyte(input),length(input));
   if ret<>1 then raise exception.Create ('EVP_CipherUpdate failed');
   //writeln(buffer_len);

   log('EVP_CipherFinal_ex');
   remain:=0;
   ret:=EVP_CipherFinal_ex(context, @buffer[buffer_len], @remain);
   if ret<>1 then raise exception.Create ('EVP_CipherFinal_ex failed');
   inc(buffer_len,remain);
   //writeln(remain);

   log('EVP_CIPHER_CTX_free');
   EVP_CIPHER_CTX_free (context);

   if buffer_len<=0 then exit;
   for i:=0 to buffer_len -1 do write(inttohex(buffer[i],2));
   writeln;

   if enc=0
      then
      begin
      for i:=0 to buffer_len -1 do write(chr(buffer[i]));
      writeln;
      end;

   result:=true;
end;

function hash(algo:string;input:array of byte):boolean;
const EVP_MAX_MD_SIZE=64;
var
context:pEVP_MD_CTX;
md :pEVP_MD;
digest:array [0..EVP_MAX_MD_SIZE -1] of byte;
digest_len:cardinal=0;
i:byte;
begin
   result:=false;
   context := EVP_MD_CTX_create();

   md:=EVP_get_digestbyname(pchar(algo));

   if md=nil then
   begin
   writeln('md=nil');
   exit;
   end;

   log('digest:'+strpas(OBJ_nid2sn(EVP_MD_type(md))));
   log('length(input):'+inttostr(length(input)));

   EVP_DigestInit(context,md);
   EVP_DigestUpdate(context, @input[0], length(input));
   EVP_DigestFinal(context, @digest[0], @digest_len);
   EVP_MD_CTX_destroy (context);

   if digest_len<=0 then exit;
   for i:=0 to digest_len -1 do write(inttohex(digest[i],2));
   writeln;
   result:=true;
end;

function Base64Encode(message:array of byte):boolean;
var
bio_mem,bio_base64,bio:pbio;
b64len:integer=0;
data:array [0..8192-1] of char;
ret:integer;
begin
  result:=false;
  bio_base64 := BIO_new(BIO_f_base64());
  //BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  bio_mem := BIO_new(BIO_s_mem());
  bio:=BIO_push(bio_base64, bio_mem);
  //write to bio
  ret:=bio_write(bio, @message[0],length(message) );
  log('bio_write:'+inttostr(ret));
  Bio_flush(bio);
  //read from bio
  b64len:=BIO_read(bio_mem, @data[0], sizeof(data)); //sizeof(data)-1?
  log('BIO_read:'+inttostr(b64len));
  data[b64len] := #0;
  writeln(data);
  //
  bio_free_all(bio);
  result:=b64len<>0;
end;

function Base64Decode(message:string;utf16:boolean=false):boolean;
var
  bio_mem,bio_base64,bio:pbio;
  encodedSize:integer;
  data:array [0..8192-1] of byte;
  ret:integer;
begin
  result:=false;
  encodedSize := 4*ceil(float(length(message) / 3));
  //log('encodedSize:'+inttostr(encodedSize));
  log('message:'+inttostr(length(message)));

  {
  //works but not with big inputs - to be reviewed
  ret:=EVP_DecodeBlock(@data[0],@message[1],length(message));
  log('EVP_DecodeBlock:'+inttostr(ret));
  }


  bio_base64 := BIO_new(BIO_f_base64());
  bio_mem := BIO_new_mem_buf(@message[1], length(message));
  bio := BIO_push(bio_base64, bio_mem);
  //BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  ret:=BIO_read(bio, @data[0] , length(data));
  log('BIO_read:'+inttostr(ret));

  if ret=0 then
     begin
     BIO_reset (bio);
     log('set flags BIO_FLAGS_BASE64_NO_NL');
     BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
     ret:=BIO_read(bio, @data[0] , length(data));
     log('BIO_read:'+inttostr(ret));
     end;

  BIO_free_all(bio);

  data[ret] := 0;
  if utf16=true
     then writeln(ansistring(TEncoding.Unicode.GetString(data,0,ret)))
     else writeln(strpas(@data[0]));

  result:=true;
end;

function PrintSSHKey(filename:string):boolean;
var
  rsa: PRSA;
  n, e: PBIGNUM;
  bio_mem,bio_base64: PBIO;
  key_buf: array[0..4095] of Char;
  key_len, len: Integer;
  buf: TBytes;
  pubkey:pEVP_PKEY;
begin
  result:=false;

  pubkey:=LoadPublicKey(filename);

  rsa := EVP_PKEY_get0_RSA(pubkey);
  if rsa = nil then
  begin
    WriteLn('Public key is not RSA');
    Exit;
  end;

  // Get modulus and exponent
  n := RSA_get0_n(rsa);
  e := RSA_get0_e(rsa);
  writeln(BN_num_bytes(bn_num_bits(e)));
  writeln(BN_num_bytes(bn_num_bits(n)));

  // Allocate buffer for modulus and exponent
  SetLength(buf, BN_num_bytes(bn_num_bits(n)) + BN_num_bytes(bn_num_bits(e)) + 2 * SizeOf(Integer));


  // Write exponent
  writeln('exponent');
  len := htonl(BN_num_bytes(bn_num_bits(e)));
  writeln('htonl:'+inttostr(len));
  Move(len, buf[0], SizeOf(Integer));
  key_len := SizeOf(Integer);
  key_len := key_len + BN_bn2binpad(e, @buf[key_len], BN_num_bytes(bn_num_bits(e)));
  writeln(key_len);

  // Write modulus
  writeln('modulus');
  len := htonl(BN_num_bytes(bn_num_bits(n)));
  writeln('htonl:'+inttostr(len));
  Move(len, buf[key_len], SizeOf(Integer));
  key_len := key_len + SizeOf(Integer);
  key_len := key_len + BN_bn2binpad(n, @buf[key_len], BN_num_bytes(bn_num_bits(n)));
  writeln(key_len);

  // Base64 encode
  writeln('base64');
  bio_mem := BIO_new(BIO_s_mem());
  bio_base64 := BIO_new(BIO_f_base64());
  BIO_push(bio_base64, bio_mem);
  BIO_write(bio_base64, @buf[0], key_len);
  BIO_flush(bio_base64);

  key_len := BIO_read(bio_base64, @key_buf[0], SizeOf(key_buf) - 1);
  writeln(key_len);
  if key_len > 0 then
  begin
    key_buf[key_len] := #0;
    WriteLn('ssh-rsa ', key_buf);
  end
  else
    WriteLn('Error reading from BIO');

  BIO_free_all(bio_mem);
  result:=true;
end;

end.

