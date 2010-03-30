<?php
// This is free and unencumbered software released into the public domain.
/**
 * OpenPGP.php is a pure-PHP implementation of the OpenPGP Message Format
 * (RFC 4880).
 *
 * @package OpenPGP
 * @version 0.0.1
 * @author  Arto Bendiken <arto.bendiken@gmail.com>
 * @link    http://github.com/bendiken/openpgp-php
 */

//////////////////////////////////////////////////////////////////////////////
// OpenPGP utilities

/**
 * @see http://tools.ietf.org/html/rfc4880
 */
class OpenPGP {
  /**
   * @see http://tools.ietf.org/html/rfc4880#section-6
   * @see http://tools.ietf.org/html/rfc4880#section-6.2
   * @see http://tools.ietf.org/html/rfc2045
   */
  static function enarmor($data, $marker = 'MESSAGE', array $headers = array()) {
    $text = self::header($marker) . "\n";
    foreach ($headers as $key => $value) {
      $text .= $key . ': ' . (string)$value . "\n";
    }
    $text .= "\n" . base64_encode($data);
    $text .= '=' . substr(pack('N', self::crc24($data)), 1) . "\n";
    $text .= self::footer($marker) . "\n";
    return $text;
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-6
   * @see http://tools.ietf.org/html/rfc2045
   */
  static function unarmor($text, $header = 'PGP PUBLIC KEY BLOCK') {
    $header = self::header($header);
    $text = str_replace(array("\r\n", "\r"), array("\n", ''), $text);
    if (($pos1 = strpos($text, $header)) !== FALSE &&
        ($pos1 = strpos($text, "\n\n", $pos1 += strlen($header))) !== FALSE &&
        ($pos2 = strpos($text, "\n=", $pos1 += 2)) !== FALSE) {
      return base64_decode($text = substr($text, $pos1, $pos2 - $pos1));
    }
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-6.2
   */
  static function header($marker) {
    return '-----BEGIN ' . strtoupper((string)$marker) . '-----';
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-6.2
   */
  static function footer($marker) {
    return '-----END ' . strtoupper((string)$marker) . '-----';
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-6
   * @see http://tools.ietf.org/html/rfc4880#section-6.1
   */
  static function crc24($data) {
    $crc = 0x00b704ce;
    for ($i = 0; $i < strlen($data); $i++) {
      $crc ^= (ord($data[$i]) & 255) << 16;
      for ($j = 0; $j < 8; $j++) {
        $crc <<= 1;
        if ($crc & 0x01000000) {
          $crc ^= 0x01864cfb;
        }
      }
    }
    return $crc & 0x00ffffff;
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-12.2
   */
  static function bitlength($data) {
    return (strlen($data) - 1) * 8 + (int)floor(log(ord($data[0]), 2)) + 1;
  }
}

//////////////////////////////////////////////////////////////////////////////
// OpenPGP messages

/**
 * @see http://tools.ietf.org/html/rfc4880#section-4.1
 * @see http://tools.ietf.org/html/rfc4880#section-11
 * @see http://tools.ietf.org/html/rfc4880#section-11.3
 */
class OpenPGP_Message implements IteratorAggregate, ArrayAccess {
  public $uri = NULL;
  public $packets = array();

  static function parse_file($path) {
    if (($msg = self::parse(file_get_contents($path)))) {
      $msg->uri = preg_match('!^[\w\d]+://!', $path) ? $path : 'file://' . realpath($path);
      return $msg;
    }
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-4.1
   * @see http://tools.ietf.org/html/rfc4880#section-4.2
   */
  static function parse($input) {
    if (is_resource($input)) {
      return self::parse_stream($input);
    }
    if (is_string($input)) {
      return self::parse_string($input);
    }
  }

  static function parse_stream($input) {
    return self::parse_string(stream_get_contents($input));
  }

  static function parse_string($input) {
    $msg = new self;
    while (($length = strlen($input)) > 0) {
      if (($packet = OpenPGP_Packet::parse($input))) {
        $msg[] = $packet;
      }
      if ($length == strlen($input)) { // is parsing stuck?
        break;
      }
    }
    return $msg;
  }

  function __construct(array $packets = array()) {
    $this->packets = $packets;
  }

  // IteratorAggregate interface

  function getIterator() {
    return new ArrayIterator($this->packets);
  }

  // ArrayAccess interface

  function offsetExists($offset) {
    return isset($this->packets[$offset]);
  }

  function offsetGet($offset) {
    return $this->packets[$offset];
  }

  function offsetSet($offset, $value) {
    return is_null($offset) ? $this->packets[] = $value : $this->packets[$offset] = $value;
  }

  function offsetUnset($offset) {
    unset($this->packets[$offset]);
  }
}

//////////////////////////////////////////////////////////////////////////////
// OpenPGP packets

/**
 * OpenPGP packet.
 *
 * @see http://tools.ietf.org/html/rfc4880#section-4.1
 * @see http://tools.ietf.org/html/rfc4880#section-4.3
 */
class OpenPGP_Packet {
  public $tag, $size, $data;

  static function class_for($tag) {
    return isset(self::$tags[$tag]) && class_exists(
      $class = 'OpenPGP_' . self::$tags[$tag] . 'Packet') ? $class : __CLASS__;
  }

  /**
   * Parses an OpenPGP packet.
   *
   * @see http://tools.ietf.org/html/rfc4880#section-4.2
   */
  static function parse(&$input) {
    $packet = NULL;
    if (strlen($input) > 0) {
      $parser = ord($input[0]) & 64 ? 'parse_new_format' : 'parse_old_format';
      list($tag, $head_length, $data_length) = self::$parser($input);
      $input = substr($input, $head_length);
      if ($tag && ($class = self::class_for($tag))) {
        $packet = new $class();
        $packet->tag    = $tag;
        $packet->input  = substr($input, 0, $data_length);
        $packet->length = $data_length;
        $packet->read();
        unset($packet->input);
      }
      $input = substr($input, $data_length);
    }
    return $packet;
  }

  /**
   * Parses a new-format (RFC 4880) OpenPGP packet.
   *
   * @see http://tools.ietf.org/html/rfc4880#section-4.2.2
   */
  static function parse_new_format($input) {
    $tag = ord($input[0]) & 63;
    // TODO
  }

  /**
   * Parses an old-format (PGP 2.6.x) OpenPGP packet.
   *
   * @see http://tools.ietf.org/html/rfc4880#section-4.2.1
   */
  static function parse_old_format($input) {
    $len = ($tag = ord($input[0])) & 3;
    $tag = ($tag >> 2) & 15;
    switch ($len) {
      case 0: // The packet has a one-octet length. The header is 2 octets long.
        $head_length = 2;
        $data_length = ord($input[1]);
        break;
      case 1: // The packet has a two-octet length. The header is 3 octets long.
        $head_length = 3;
        $data_length = unpack('n', substr($input, 1, 2));
        $data_length = $data_length[1];
        break;
      case 2: // The packet has a four-octet length. The header is 5 octets long.
        $head_length = 5;
        $data_length = unpack('N', substr($input, 1, 4));
        $data_length = $data_length[1];
        break;
      case 3: // The packet is of indeterminate length. The header is 1 octet long.
        $head_length = 1;
        $data_length = strlen($input) - $head_length;
        break;
    }
    return array($tag, $head_length, $data_length);
  }

  function __construct() {}

  function read() {
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-3.5
   */
  function read_timestamp() {
    return $this->read_unpacked(4, 'N');
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-3.2
   */
  function read_mpi() {
    $length = $this->read_unpacked(2, 'n');  // length in bits
    $length = (int)floor(($length + 7) / 8); // length in bytes
    return $this->read_bytes($length);
  }

  /**
   * @see http://php.net/manual/en/function.unpack.php
   */
  function read_unpacked($count, $format) {
    $unpacked = unpack($format, $this->read_bytes($count));
    return $unpacked[1];
  }

  function read_byte() {
    return ($bytes = $this->read_bytes()) ? $bytes[0] : NULL;
  }

  function read_bytes($count = 1) {
    $bytes = substr($this->input, 0, $count);
    $this->input = substr($this->input, $count);
    return $bytes;
  }

  static $tags = array(
     1 => 'AsymmetricSessionKey',      // Public-Key Encrypted Session Key
     2 => 'Signature',                 // Signature Packet
     3 => 'SymmetricSessionKey',       // Symmetric-Key Encrypted Session Key Packet
     4 => 'OnePassSignature',          // One-Pass Signature Packet
     5 => 'SecretKey',                 // Secret-Key Packet
     6 => 'PublicKey',                 // Public-Key Packet
     7 => 'SecretSubkey',              // Secret-Subkey Packet
     8 => 'CompressedData',            // Compressed Data Packet
     9 => 'EncryptedData',             // Symmetrically Encrypted Data Packet
    10 => 'Marker',                    // Marker Packet
    11 => 'LiteralData',               // Literal Data Packet
    12 => 'Trust',                     // Trust Packet
    13 => 'UserID',                    // User ID Packet
    14 => 'PublicSubkey',              // Public-Subkey Packet
    17 => 'UserAttribute',             // User Attribute Packet
    18 => 'IntegrityProtectedData',    // Sym. Encrypted and Integrity Protected Data Packet
    19 => 'ModificationDetectionCode', // Modification Detection Code Packet
    60 => 'Experimental',              // Private or Experimental Values
    61 => 'Experimental',              // Private or Experimental Values
    62 => 'Experimental',              // Private or Experimental Values
    63 => 'Experimental',              // Private or Experimental Values
  );
}

/**
 * OpenPGP Public-Key Encrypted Session Key packet (tag 1).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.1
 */
class OpenPGP_AsymmetricSessionKeyPacket extends OpenPGP_Packet {
  // TODO
}

/**
 * OpenPGP Signature packet (tag 2).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.2
 */
class OpenPGP_SignaturePacket extends OpenPGP_Packet {
  // TODO
}

/**
 * OpenPGP Symmetric-Key Encrypted Session Key packet (tag 3).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.3
 */
class OpenPGP_SymmetricSessionKeyPacket extends OpenPGP_Packet {
  // TODO
}

/**
 * OpenPGP One-Pass Signature packet (tag 4).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.4
 */
class OpenPGP_OnePassSignaturePacket extends OpenPGP_Packet {
  // TODO
}

/**
 * OpenPGP Public-Key packet (tag 6).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.1.1
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.2
 * @see http://tools.ietf.org/html/rfc4880#section-11.1
 * @see http://tools.ietf.org/html/rfc4880#section-12
 */
class OpenPGP_PublicKeyPacket extends OpenPGP_Packet {
  public $version, $timestamp, $algorithm;
  public $key, $key_id, $fingerprint;

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-5.5.2
   */
  function read() {
    switch ($this->version = ord($this->read_byte())) {
      case 2:
      case 3:
        return FALSE; // TODO
      case 4:
        $this->timestamp = $this->read_timestamp();
        $this->algorithm = ord($this->read_byte());
        $this->read_key_material();
        return TRUE;
    }
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-5.5.2
   */
  function read_key_material() {
    static $key_fields = array(
       1 => array('n', 'e'),           // RSA
      16 => array('p', 'g', 'y'),      // ELG-E
      17 => array('p', 'q', 'g', 'y'), // DSA
    );
    foreach ($key_fields[$this->algorithm] as $field) {
      $this->key[$field] = $this->read_mpi();
    }
    $this->key_id = substr($this->fingerprint(), -8);
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-12.2
   * @see http://tools.ietf.org/html/rfc4880#section-3.3
   */
  function fingerprint() {
    switch ($this->version) {
      case 2:
      case 3:
        return $this->fingerprint = md5($this->key['n'] . $this->key['e']);
      case 4:
        $material = array(
          chr(0x99), pack('n', $this->length),
          chr($this->version), pack('N', $this->timestamp),
          chr($this->algorithm),
        );
        foreach ($this->key as $data) {
          $material[] = pack('n', OpenPGP::bitlength($data));
          $material[] = $data;
        }
        return $this->fingerprint = sha1(implode('', $material));
    }
  }
}

/**
 * OpenPGP Public-Subkey packet (tag 14).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.1.2
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.2
 * @see http://tools.ietf.org/html/rfc4880#section-11.1
 * @see http://tools.ietf.org/html/rfc4880#section-12
 */
class OpenPGP_PublicSubkeyPacket extends OpenPGP_PublicKeyPacket {
  // TODO
}

/**
 * OpenPGP Secret-Key packet (tag 5).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.1.3
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.3
 * @see http://tools.ietf.org/html/rfc4880#section-11.2
 * @see http://tools.ietf.org/html/rfc4880#section-12
 */
class OpenPGP_SecretKeyPacket extends OpenPGP_PublicKeyPacket {
  // TODO
}

/**
 * OpenPGP Secret-Subkey packet (tag 7).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.1.4
 * @see http://tools.ietf.org/html/rfc4880#section-5.5.3
 * @see http://tools.ietf.org/html/rfc4880#section-11.2
 * @see http://tools.ietf.org/html/rfc4880#section-12
 */
class OpenPGP_SecretSubkeyPacket extends OpenPGP_SecretKeyPacket {
  // TODO
}

/**
 * OpenPGP Compressed Data packet (tag 8).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.6
 */
class OpenPGP_CompressedDataPacket extends OpenPGP_Packet {
  public $algorithm;
  /* see http://tools.ietf.org/html/rfc4880#section-9.3 */
  static $algorithms = array(0 => 'Uncompressed', 1 => 'ZIP', 2 => 'ZLIB', 3 => 'BZip2');
  function read() {
    $this->algorithm = ord($this->read_byte());
    $this->data = $this->read_bytes($this->length);
    switch($this->algorithm) {
      case 0:
        $this->data = OpenPGP_Message::parse($this->data);
        break;
      case 1:
        $this->data = OpenPGP_Message::parse(gzinflate($this->data));
        break;
      case 2:
        $this->data = OpenPGP_Message::parse(gzuncompress($this->data));
        break;
      case 3:
        $this->data = OpenPGP_Message::parse(bzdecompress($this->data));
        break;
      default:
        /* TODO error? */
    }
    if($this->data) {
      $this->data = $this->data->packets;
    }
  }
}

/**
 * OpenPGP Symmetrically Encrypted Data packet (tag 9).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.7
 */
class OpenPGP_EncryptedDataPacket extends OpenPGP_Packet {
  // TODO
}

/**
 * OpenPGP Marker packet (tag 10).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.8
 */
class OpenPGP_MarkerPacket extends OpenPGP_Packet {
  // TODO
}

/**
 * OpenPGP Literal Data packet (tag 11).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.9
 */
class OpenPGP_LiteralDataPacket extends OpenPGP_Packet {
  public $format, $filename, $timestamp;
  function read() {
    $this->size = $this->length - 1 - 4;
    $this->format = $this->read_byte();
    $filename_length = ord($this->read_byte());
    $this->size -= $filename_length;
    $this->filename = $this->read_bytes($filename_length);
    $this->timestamp = $this->read_unpacked(4, 'N');
    $this->data = $this->read_bytes($this->size);
  }
}

/**
 * OpenPGP Trust packet (tag 12).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.10
 */
class OpenPGP_TrustPacket extends OpenPGP_Packet {
  // TODO
}

/**
 * OpenPGP User ID packet (tag 13).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.11
 * @see http://tools.ietf.org/html/rfc2822
 */
class OpenPGP_UserIDPacket extends OpenPGP_Packet {
  public $name, $comment, $email;

  function read() {
    $this->text = $this->input;
    // User IDs of the form: "name (comment) <email>"
    if (preg_match('/^([^\(]+)\(([^\)]+)\)\s+<([^>]+)>$/', $this->text, $matches)) {
      $this->name    = trim($matches[1]);
      $this->comment = trim($matches[2]);
      $this->email   = trim($matches[3]);
    }
    // User IDs of the form: "name <email>"
    else if (preg_match('/^([^<]+)\s+<([^>]+)>$/', $this->text, $matches)) {
      $this->name    = trim($matches[1]);
      $this->comment = NULL;
      $this->email   = trim($matches[2]);
    }
    // User IDs of the form: "name"
    else if (preg_match('/^([^<]+)$/', $this->text, $matches)) {
      $this->name    = trim($matches[1]);
      $this->comment = NULL;
      $this->email   = NULL;
    }
    // User IDs of the form: "<email>"
    else if (preg_match('/^<([^>]+)>$/', $this->text, $matches)) {
      $this->name    = NULL;
      $this->comment = NULL;
      $this->email   = trim($matches[2]);
    }
  }

  function __toString() {
    $text = array();
    if ($this->name)    { $text[] = $this->name; }
    if ($this->comment) { $text[] = "({$this->comment})"; }
    if ($this->email)   { $text[] = "<{$this->email}>"; }
    return implode(' ', $text);
  }
}

/**
 * OpenPGP User Attribute packet (tag 17).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.12
 * @see http://tools.ietf.org/html/rfc4880#section-11.1
 */
class OpenPGP_UserAttributePacket extends OpenPGP_Packet {
  public $packets;

  // TODO
}

/**
 * OpenPGP Sym. Encrypted Integrity Protected Data packet (tag 18).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.13
 */
class OpenPGP_IntegrityProtectedDataPacket extends OpenPGP_Packet {
  // TODO
}

/**
 * OpenPGP Modification Detection Code packet (tag 19).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-5.14
 */
class OpenPGP_ModificationDetectionCodePacket extends OpenPGP_Packet {
  // TODO
}

/**
 * OpenPGP Private or Experimental packet (tags 60..63).
 *
 * @see http://tools.ietf.org/html/rfc4880#section-4.3
 */
class OpenPGP_ExperimentalPacket extends OpenPGP_Packet {}
