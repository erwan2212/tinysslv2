program test_opensslutils;

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, fpcunit, testregistry, consoletestrunner, opensslutils;

const
  TEST_PASSPHRASE = '1234';

type
  TOpenSSLUtilsTests = class(TTestCase)
  private
    FTestDir: string;
    procedure CleanTestFiles;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure Test_01_LoadAndFreeSSL;
    procedure Test_02_GenerateRSAKey;
    procedure Test_03_MakeCertAndReq;
    procedure Test_04_SignReq;
    procedure Test_05_ConversionsX509;
    procedure Test_06_ConversionsPKCS12;
    procedure Test_07_RSAEncryptDecrypt;
    procedure Test_08_CryptoAndHashes;
    procedure Test_09_Base64;
  end;

{ TOpenSSLUtilsTests }

procedure TOpenSSLUtilsTests.CleanTestFiles;
var
  SR: TSearchRec;
  Exts: array[0..6] of string = ('.key', '.crt', '.csr', '.der', '.pfx', '.p7b', '.pem');
  i: Integer;
begin
  //exit;
  for i := Low(Exts) to High(Exts) do
  begin
    if FindFirst(FTestDir + '*' + Exts[i], faAnyFile, SR) = 0 then
    begin
      repeat
        DeleteFile(FTestDir + SR.Name);
      until FindNext(SR) <> 0;
      FindClose(SR);
    end;
  end;
end;

procedure TOpenSSLUtilsTests.SetUp;
begin
  inherited SetUp;
  FTestDir := IncludeTrailingPathDelimiter(GetCurrentDir);
  LoadSSL;
  CleanTestFiles;
end;

procedure TOpenSSLUtilsTests.TearDown;
begin
  CleanTestFiles;
  FreeSSL;
  inherited TearDown;
end;

procedure TOpenSSLUtilsTests.Test_01_LoadAndFreeSSL;
begin
  AssertTrue('L initialisation SSL doit s exécuter sans erreur', true);
end;

procedure TOpenSSLUtilsTests.Test_02_GenerateRSAKey;
begin
  AssertTrue('La génération d une clé RSA a échoué', generate_rsa_key_2);
  AssertTrue('Le fichier public.pem doit exister', FileExists(FTestDir + 'public.pem'));
  AssertTrue('Le fichier private.pem doit exister', FileExists(FTestDir + 'private.pem'));
end;

procedure TOpenSSLUtilsTests.Test_03_MakeCertAndReq;
begin
  // Génération du CA Racine (ca.crt + ca.key)
  AssertTrue('Génération du certificat racine auto-signé',
    mkcert('ca.crt', 'Test CA', '', TEST_PASSPHRASE, '01', true));
  AssertTrue('Le fichier ca.crt doit exister', FileExists(FTestDir + 'ca.crt'));

  // Génération de la demande CSR (client.csr + client.key)
  // '' indique à mkreq de générer une nouvelle clé
  AssertTrue('Génération de la demande CSR',
    mkreq('client.local', '', 'client.csr'));
  AssertTrue('Le fichier client.csr doit exister', FileExists(FTestDir + 'client.csr'));
end;

procedure TOpenSSLUtilsTests.Test_04_SignReq;
begin
  // Préparation : Certificat CA et Demande CSR
  AssertTrue('Création du CA', mkcert('ca.crt', 'Test CA', '', TEST_PASSPHRASE, '01', true));

  // '' indique à mkreq de générer une nouvelle clé
  AssertTrue('Création du CSR', mkreq('client.local', '', 'client.csr'));

  // Signature de la demande CSR avec le mot de passe de la clé CA
  AssertTrue('Signature du CSR', signreq('client.csr', 'ca.crt', TEST_PASSPHRASE, '', false));
  AssertTrue('Le certificat signé client.crt doit exister', FileExists(FTestDir + 'client.crt'));
end;

procedure TOpenSSLUtilsTests.Test_05_ConversionsX509;
begin
  AssertTrue('Création certificat initial', mkcert('cert.crt', 'Test Conv', '', TEST_PASSPHRASE, '01', false));

  AssertTrue('Conversion PEM vers DER', X509PEM2DER('cert.crt'));
  AssertTrue('Le fichier cert.der doit exister', FileExists(FTestDir + 'cert.der'));

  DeleteFile(FTestDir + 'cert.crt');
  AssertTrue('Conversion DER vers PEM', X509DER2PEM('cert.der'));
  AssertTrue('Le fichier cert.crt doit être recréé', FileExists(FTestDir + 'cert.crt'));
end;

procedure TOpenSSLUtilsTests.Test_06_ConversionsPKCS12;
begin
  AssertTrue('Création cert', mkcert('app.crt', 'Test PFX', '', TEST_PASSPHRASE, '01', false));

  AssertTrue('Export en PFX', PEM2PFX(TEST_PASSPHRASE, 'app.key', 'app.crt'));
  AssertTrue('Le fichier app.pfx doit exister', FileExists(FTestDir + 'app.pfx'));

  DeleteFile(FTestDir + 'app.crt');
  DeleteFile(FTestDir + 'app.key');

  AssertTrue('Import depuis PFX', PFX2PEM('app.pfx', TEST_PASSPHRASE));
  AssertTrue('Le fichier app.crt doit être extrait', FileExists(FTestDir + 'app.crt'));
  AssertTrue('Le fichier app.key doit être extrait', FileExists(FTestDir + 'app.key'));
end;

procedure TOpenSSLUtilsTests.Test_07_RSAEncryptDecrypt;
var
  OriginalText: string;
  EncryptedText: string;
begin
  AssertTrue('Génération paire de clés RSA', generate_rsa_key_2);

  OriginalText := 'Message secret de test 12345';
  EncryptedText := '';
  AssertTrue('Chiffrement RSA public', Encrypt_Pub(OriginalText, EncryptedText));
  AssertFalse('Le texte chiffré ne doit pas être vide', EncryptedText = '');

  AssertTrue('Déchiffrement RSA privé', Decrypt_Priv(EncryptedText));
end;

procedure TOpenSSLUtilsTests.Test_08_CryptoAndHashes;
var
  Data: array[0..4] of byte = ($54, $65, $73, $74, $73);
begin
  AssertTrue('Calcul de hash SHA256', hash('sha256', Data));
  AssertTrue('Chiffrement AES-256-CBC', crypt('aes-256-cbc', 'Hello OpenSSL', '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF', '000102030405060708090A0B0C0D0E0F', 1));
end;

procedure TOpenSSLUtilsTests.Test_09_Base64;
var
  Data: array[0..3] of byte = (1, 2, 3, 4);
begin
  AssertTrue('Encodage Base64', Base64Encode(Data));
  AssertTrue('Décodage Base64', Base64Decode('AQIDBA=='));
end;

var
  Application: TTestRunner;
begin
  RegisterTest(TOpenSSLUtilsTests);
  Application := TTestRunner.Create(nil);
  try
    Application.Initialize;
    Application.Run;
  finally
    Application.Free;
  end;
end.
