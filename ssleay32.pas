unit ssleay32;

{$mode delphi}{$H+}

interface

uses
    windows,sysutils,winsock,
    OpenSSL.Api_11,opensslutils,
    utils;

procedure s_client(host:string);


implementation

function init_socket(host:string;port:dword;var sock_:tsocket):boolean;
var
wsadata:TWSADATA;
err:longint;
hostaddr:u_long;
sin:sockaddr_in;
HostEnt:winsock.PHostEnt;
begin
  result:=false;
  //
  err := WSAStartup(MAKEWORD(2, 0), wsadata);
  if(err <> 0) then raise exception.Create ('WSAStartup failed with error: '+inttostr(err));
  //
  hostaddr := inet_addr(pchar(host));
  //not an ip? lets try to resolve hostname
  if hostaddr = INADDR_NONE then
    begin
    HostEnt:=gethostbyname(pchar(host));
    if HostEnt <> nil then hostaddr:=Integer(Pointer(HostEnt^.h_addr^)^);
    end;
  //
  //
  sock_ := socket(AF_INET, SOCK_STREAM, 0);
  //
  sin.sin_family := AF_INET;
  sin.sin_port := htons(port);
  sin.sin_addr.s_addr := hostaddr;
  if connect(sock_, tsockaddr(sin), sizeof(sockaddr_in)) <> 0
     then raise exception.Create ('failed to connect');
  //
  result:=true;

end;

procedure s_client(host:string);
var
sock:tsocket;
err:cardinal;
ssl:pointer=nil; //PSSL;
ctx:pointer=nil;
server_cert:PX509=nil;
str:pchar;
name:pX509_NAME=nil;
certs:pSTACK_OFX509 =nil;
b:byte;
ip, port: string;
colonPos: Integer;
begin

   colonPos := Pos(':', host);
   ip := Copy(host, 1, colonPos - 1);
   port := Copy(host, colonPos + 1, Length(host) - colonPos);
   log('Adresse IP : '+ ip);
   log('Port : '+port);

   //log('SSL_library_init');
   //SSL_library_init;

   //OpenSSL_add_all_algorithms();
   //SSL_load_error_strings();

   log('SSL_CTX_new');
   ctx:=SSL_CTX_new(SSLv23_method );
   if ctx=nil then exit;

   //log('SSL_CTX_set_options');
   //SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 or SSL_OP_NO_TLSv1 or SSL_OP_NO_TLSv1_1 or SSL_OP_NO_TLSv1_2 );
   //log('SSL_CTX_set_min_proto_version');
   //if SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION)=0 then log('SSL_CTX_set_min_proto_version failed');


   log('SSL_new');
   ssl := SSL_new (ctx);
   if ssl =nil then exit;

   log('init_socket');
   init_socket (ip,strtoint(port),sock);

   log('SSL_set_fd');
   SSL_set_fd (ssl, sock);

   log('SSL_connect');
   err := SSL_connect (ssl);
   //if (err < 0) ...
   //writeln ('SSL connection using ' + SSL_get_cipher (ssl));

   log('SSL_get_peer_certificate');
   //server_cert := SSL_get_peer_certificate (ssl);
   certs:=SSL_get_peer_cert_chain (ssl);
   writeln('sk_num:'+inttostr(openssl_sk_num(Certs)));

   writeln('********************************');
   for b:=0 to openssl_sk_num(Certs) -1 do
   begin
   server_cert:=openssl_sk_value(Certs, b);

   //
     log('X509_get_subject_name');
     NAME:=X509_get_subject_name(server_cert);
     writeln('subject_name:'+getdn(name));
     //
     //
     log('X509_get_issuer_name');
     NAME:=X509_get_issuer_name(server_cert);
     writeln('issuer_name:'+getdn(name));
     //

     try
       log('X509_get_notBefore');
       writeln('notBefore:'+DateTimeToStr (getTime (X509_get_notBefore(server_cert))));
       log('X509_get_notAfter');
       writeln('notAfter:'+DateTimeToStr (getTime (X509_get_notAfter (server_cert))));
       except
       on e:exception do writeln(e.message);
       end;

       writeln('SerialNumber:'+getSerialNumber(server_cert));

       writeln('********************************');
    end;   //for b:=0 to sk_num(Certs) -1 do


     SSL_shutdown (ssl);
     SSL_free (ssl);
     closesocket (sock);
end;



initialization




end.

