<?php

require_once dirname(__FILE__).'/openpgp.php';
require_once 'Crypt/AES.php';
require_once 'Crypt/TripleDES.php';

class OpenPGP_Crypt_AES_TripleDES {
  public static function decryptSymmetric($pass, $m) {
    foreach($m as $p) {
      if($p instanceof OpenPGP_SymmetricSessionKeyPacket) {
        switch($p->symmetric_algorithm) {
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
        }
        if(!$cipher) continue; // Unsupported cipher
        if(!isset($key_bytes)) $key_bytes = $cipher->key_size;
        if(!isset($key_block_bytes)) $key_block_bytes = $cipher->block_size;

        $cipher->setKey($p->s2k->make_key($pass, $key_bytes));
        $epacket = self::getEncryptedData($m);
        $padAmount = $key_block_bytes - (strlen($epacket->data) % $key_block_bytes);

        if(strlen($p->encrypted_data) < 1) {
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
            // TODO (resync)
          }
        } else {
          // TODO
        }
      }
    }

    return NULL; /* If we get here, we failed */
  }

  public static function getEncryptedData($m) {
    foreach($m as $p) {
      if($p instanceof OpenPGP_EncryptedDataPacket) return $p;
    }
    throw new Exception("Can only decrypt EncryptedDataPacket");
  }
}
