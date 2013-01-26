<?php

/* The tests which require phpseclib */

require_once dirname(__FILE__).'/../lib/openpgp.php';
require_once dirname(__FILE__).'/../lib/openpgp_crypt_rsa.php';
require_once dirname(__FILE__).'/../lib/openpgp_crypt_aes_tripledes.php';

class MessageVerification extends PHPUnit_Framework_TestCase {
  public function oneMessageRSA($pkey, $path) {
    $pkeyM = OpenPGP_Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $pkey));
    $m = OpenPGP_Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $path));
    $verify = new OpenPGP_Crypt_RSA($pkeyM);
    $this->assertSame($verify->verify($m), $m->signatures());
  }

  public function testUncompressedOpsRSA() {
    $this->oneMessageRSA('pubring.gpg', 'uncompressed-ops-rsa.gpg');
  }

  public function testCompressedSig() {
    $this->oneMessageRSA('pubring.gpg', 'compressedsig.gpg');
  }

  public function testCompressedSigZLIB() {
    $this->oneMessageRSA('pubring.gpg', 'compressedsig-zlib.gpg');
  }

  public function testCompressedSigBzip2() {
    $this->oneMessageRSA('pubring.gpg', 'compressedsig-bzip2.gpg');
  }

  public function testSigningMessages() {
    $wkey = OpenPGP_Message::parse(file_get_contents(dirname(__FILE__) . '/data/helloKey.gpg'));
    $data = new OpenPGP_LiteralDataPacket('This is text.', array('format' => 'u', 'filename' => 'stuff.txt'));
    $sign = new OpenPGP_Crypt_RSA($wkey);
    $m = $sign->sign($data)->to_bytes();
    $reparsedM = OpenPGP_Message::parse($m);
    $this->assertSame($sign->verify($reparsedM), $reparsedM->signatures());
  }

/*
  public function testUncompressedOpsDSA() {
    $this->oneMessageDSA('pubring.gpg', 'uncompressed-ops-dsa.gpg');
  }

  public function testUncompressedOpsDSAsha384() {
    $this->oneMessageDSA('pubring.gpg', 'uncompressed-ops-dsa-sha384.gpg');
  }
*/
}


class KeyVerification extends PHPUnit_Framework_TestCase {
  public function oneKeyRSA($path) {
    $m = OpenPGP_Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $path));
    $verify = new OpenPGP_Crypt_RSA($m);
    $this->assertSame($verify->verify($m), $m->signatures());
  }

  public function testHelloKey() {
    $this->oneKeyRSA("helloKey.gpg");
  }
}


class Decryption extends PHPUnit_Framework_TestCase {
  public function oneSymmetric($pass, $cnt, $path) {
    $m = OpenPGP_Message::parse(file_get_contents(dirname(__FILE__) . '/data/' . $path));
    $m2 = OpenPGP_Crypt_AES_TripleDES::decryptSymmetric($pass, $m);
    while($m2[0] instanceof OpenPGP_CompressedDataPacket) $m2 = $m2[0]->data;
    foreach($m2 as $p) {
      if($p instanceof OpenPGP_LiteralDataPacket) {
        $this->assertEquals($p->data, $cnt);
      }
    }
  }

  public function testDecryptAES() {
    $this->oneSymmetric("hello", "PGP\n", "symmetric-aes.gpg");
  }

  public function testDecrypt3DES() {
    $this->oneSymmetric("hello", "PGP\n", "symmetric-3des.gpg");
  }

/* TODO
  public function testDecryptSessionKey() {
    $this->oneSymmetric("hello", "PGP\n", "symmetric-with-session-key.gpg");
  }

  public function testDecryptNoMDC() {
    $this->oneSymmetric("hello", "PGP\n", "symmetric-no-mdc.gpg");
  }
*/
}
