<?php

require_once dirname(__FILE__).'/openpgp.php';
require_once 'Crypt/AES.php';

class OpenPGP_phpseclib_Crypt {
  public static function decryptSymmetric($pass, $m) {
    foreach($m as $p) {
      if($p instanceof OpenPGP_SymmetricSessionKeyPacket) {
        switch($p->symmetric_algorithm) {
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
        }
        if(!$cipher) continue; // Unsupported cipher

        $cipher->setKey($p->s2k->make_key($pass, $cipher->key_size));
        $epacket = self::getEncryptedData($m);
        $padAmount = $cipher->block_size - (strlen($epacket->data) % $cipher->block_size);

        if(strlen($p->encrypted_data) < 1) {
          if($epacket instanceof OpenPGP_IntegrityProtectedDataPacket) {
				 $data = substr($cipher->decrypt($epacket->data . str_repeat("\0", $padAmount)), 0, strlen($epacket->data));
				 $prefix = substr($data, 0, $cipher->block_size + 2);
				 $mdc = substr(substr($data, -22, 22), 2);
				 $data = substr($data, $cipher->block_size + 2, -22);

             $mkMDC = hash("sha1", $prefix . $data . "\xD3\x14", true);
             if($mkMDC !== $mdc) return false;

             return OpenPGP_Message::parse($data);
          } else {
            // TODO (resync)
          }
        } else {
          // TODO
        }
      }
    }
  }

  public static function getEncryptedData($m) {
    foreach($m as $p) {
      if($p instanceof OpenPGP_EncryptedDataPacket) return $p;
    }
    throw new Exception("Can only decrypt EncryptedDataPacket");
  }
}
