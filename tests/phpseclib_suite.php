<?php

/* The tests which require phpseclib */

require_once dirname(__FILE__).'/../lib/openpgp.php';
require_once dirname(__FILE__).'/../lib/openpgp_crypt_rsa.php';

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
