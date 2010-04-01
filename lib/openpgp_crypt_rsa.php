<?php
// This is free and unencumbered software released into the public domain.
/**
 * OpenPGP_Crypt_RSA.php is a wrapper for using the classes from OpenPGP.php with Crypt_RSA
 *
 * @package OpenPGP
 * @version 0.0.1
 * @author  Stephen Paul Weber <singpolyma@singpolyma.net>
 * @link    http://github.com/singpolyma/openpgp-php
 */

// From http://phpseclib.sourceforge.net/
require 'Crypt/RSA.php';

class OpenPGP_Crypt_RSA {
  protected $key, $message;

  // Construct a wrapper object from a key or a message packet
  function __construct($packet) {
    if(!is_object($packet)) $packet = OpenPGP_Message::parse($packet);
    if($packet[0] instanceof OpenPGP_PublicKeyPacket) $packet = $packet[0];
    if($packet instanceof OpenPGP_PublicKeyPacket) { // If it's a key (other keys are subclasses of this one)
      $this->key = $packet;
    } else {
      $this->message = $packet;
    }
  }

  // Get Crypt_RSA for the public key
  function public_key() {
    if(!$this->key) return NULL; // No key
    return self::convert_public_key($this->key);
  }

  // Get Crypt_RSA for the private key
  function private_key() {
    if(!$this->key) return NULL; // No key
    return self::convert_private_key($this->key);
  }

  // Pass a message to verify with this key, or a key (OpenPGP or Crypt_RSA) to check this message with
  // Second optional parameter to specify which signature to verify (if there is more than one)
  function verify($packet, $index=0) {
    if(!is_object($packet)) $packet = OpenPGP_Message::parse($packet);
    if($packet[0] instanceof OpenPGP_PublicKeyPacket) $packet = $packet[0];
    if($packet instanceof OpenPGP_Message) {
      $key = $this->public_key();
      list($signature_packet, $data_packet) = $packet->signature_and_data($index);
      if(!$key || $signature_packet->key_algorithm_name() != 'RSA') return NULL;
      $key->setHash(strtolower($signature_packet->hash_algorithm_name()));
      return $packet->verify(array('RSA' => array($signature_packet->hash_algorithm_name() => array($key, 'verify'))));
    } else {
      list($signature_packet, $data_packet) = $this->message->signature_and_data($index);
      if(!$this->message || $signature_packet->key_algorithm_name() != 'RSA') return NULL;
      if(!($packet instanceof Crypt_RSA)) $packet = self::convert_public_key($packet);
      $packet->setHash(strtolower($signature_packet->hash_algorithm_name()));
      return $this->message->verify(array('RSA' => array($signature_packet->hash_algorithm_name() => array($packet, 'verify'))));
    }
  }

  // Pass a message to sign with this key, or a secret key to sign this message with
  // Second parameter is hash algorithm to use (default SHA256)
  // Third parameter is the 16-digit key ID to use... defaults to the key id in the key packet
  function sign($packet, $hash='SHA256', $key_id=NULL) {
    if(!is_object($packet)) {
      if($this->key) {
        $packet = new OpenPGP_LiteralDataPacket($packet);
      } else {
        $packet = OpenPGP_Message::parse($packet);
        $packet = $packet[0];
      }
    }

    if($packet instanceof OpenPGP_SecretKeyPacket || $packet instanceof Crypt_RSA) {
      $key = $packet;
      $message = $this->message;
    } else {
      $key = $this->private_key();
      $message = $packet;
    }

    if(!$key || !$message) return NULL; // Missing some data

    if($message instanceof OpenPGP_Message) {
      list($dummy, $message) = $message->signature_and_data();
    }

    if(!$key_id) $key_id = substr($key->fingerprint, -16, 16);
    if($key instanceof OpenPGP_SecretKeyPacket) $key = self::convert_private_key($key);
    $key->setHash(strtolower($hash));

    $sig = new OpenPGP_SignaturePacket($message, 'RSA', strtoupper($hash));
    $sig->hashed_subpackets[] = new OpenPGP_SignaturePacket_IssuerPacket($key_id);
    $sig->sign_data(array('RSA' => array($hash => array($key, 'sign'))));

    return new OpenPGP_Message(array($sig, $message));
  }

  static function crypt_rsa_key($mod, $exp, $hash='SHA256') {
    $rsa = new Crypt_RSA();
    $rsa->signatureMode = CRYPT_RSA_SIGNATURE_PKCS1;
    $rsa->setHash(strtolower($hash));
    $rsa->modulus = new Math_BigInteger($mod, 256);
    $rsa->k = strlen($rsa->modulus->toBytes());
    $rsa->exponent = new Math_BigInteger($exp, 256);
    return $rsa;
  }

  static function convert_key($packet, $private=false) {
    if(!is_object($packet)) $packet = OpenPGP_Message::parse($packet);
    if($packet instanceof OpenPGP_Message) $packet = $packet[0];

    $mod = $packet->key['n'];
    $exp = $packet->key['e'];
    if($private) $exp = $packet->key['d'];
    if(!$exp) return NULL; // Packet doesn't have needed data

    $rsa = self::crypt_rsa_key($mod, $exp);

    if($private) {
      if($packet->key['p'] && $packet->key['q']) $rsa->primes = array($packet->key['p'], $packet->key['q']);
      if($packet->key['u']) $rsa->coefficients = array($packet->key['u']);
    }

    return $rsa;
  }

  static function convert_public_key($packet) {
    return self::convert_key($packet, false);
  }

  static function convert_private_key($packet) {
    return self::convert_key($packet, true);
  }

}

?>
