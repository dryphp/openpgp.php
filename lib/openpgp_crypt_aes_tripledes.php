<?php

require_once dirname(__FILE__).'/openpgp.php';
require_once 'Crypt/AES.php';
require_once 'Crypt/TripleDES.php';

class OpenPGP_Crypt_AES_TripleDES {
  public static function decryptSymmetric($pass, $m) {
    foreach($m as $p) {
      if($p instanceof OpenPGP_SymmetricSessionKeyPacket) {
        list($cipher, $key_bytes, $key_block_bytes) = self::getCipher($p->symmetric_algorithm);
        if(!$cipher) continue;
        $cipher->setKey($p->s2k->make_key($pass, $key_bytes));

        if(strlen($p->encrypted_data) > 0) {
          $padAmount = $key_block_bytes - (strlen($p->encrypted_data) % $key_block_bytes);
          $data = substr($cipher->decrypt($p->encrypted_data . str_repeat("\0", $padAmount)), 0, strlen($p->encrypted_data));
          list($cipher, $key_bytes, $key_block_bytes) = self::getCipher(ord($data{0}));
          if(!$cipher) continue;
          $cipher->setKey(substr($data, 1));
        }

        $epacket = self::getEncryptedData($m);
        $padAmount = $key_block_bytes - (strlen($epacket->data) % $key_block_bytes);

        if($epacket instanceof OpenPGP_IntegrityProtectedDataPacket) {
           $data = substr($cipher->decrypt($epacket->data . str_repeat("\0", $padAmount)), 0, strlen($epacket->data));
           $prefix = substr($data, 0, $key_block_bytes + 2);
           $mdc = substr(substr($data, -22, 22), 2);
           $data = substr($data, $key_block_bytes + 2, -22);

           $mkMDC = hash("sha1", $prefix . $data . "\xD3\x14", true);
           if($mkMDC !== $mdc) return false;

           try {
             $msg = OpenPGP_Message::parse($data);
           } catch (Exception $ex) { $msg = NULL; }
           if($msg) return $msg; /* Otherwise keep trying */
        } else {
           // No MDC mean decrypt with resync
           $iv = substr($epacket->data, 2, $key_block_bytes);
           $edata = substr($epacket->data, $key_block_bytes + 2);

           $cipher->setIV($iv);
           $data = substr($cipher->decrypt($edata . str_repeat("\0", $padAmount)), 0, strlen($edata));

           try {
             $msg = OpenPGP_Message::parse($data);
           } catch (Exception $ex) { $msg = NULL; }
           if($msg) return $msg; /* Otherwise keep trying */
        }
      }
    }

    return NULL; /* If we get here, we failed */
  }

  public static function getCipher($algo) {
    switch($algo) {
      case 2:
        $cipher = new Crypt_TripleDES(CRYPT_DES_MODE_CFB);
        $key_bytes = 24;
        $key_block_bytes = 8;
        break;
      case 7:
        $cipher = new Crypt_AES(CRYPT_AES_MODE_CFB);
        $cipher->setKeyLength(128);
        break;
      case 8:
        $cipher = new Crypt_AES(CRYPT_AES_MODE_CFB);
        $cipher->setKeyLength(192);
        break;
      case 9:
        $cipher = new Crypt_AES(CRYPT_AES_MODE_CFB);
        $cipher->setKeyLength(256);
        break;
      default:
        $cipher = NULL;
    }
    if(!$cipher) return array(NULL, NULL, NULL); // Unsupported cipher
    if(!isset($key_bytes)) $key_bytes = $cipher->key_size;
    if(!isset($key_block_bytes)) $key_block_bytes = $cipher->block_size;
    return array($cipher, $key_bytes, $key_block_bytes);
  }

  public static function getEncryptedData($m) {
    foreach($m as $p) {
      if($p instanceof OpenPGP_EncryptedDataPacket) return $p;
    }
    throw new Exception("Can only decrypt EncryptedDataPacket");
  }
}
