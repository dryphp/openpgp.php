<?php
// This is free and unencumbered software released into the public domain.
/**
 * OpenPGP.php is a pure-PHP implementation of the OpenPGP Message Format
 * (RFC 4880).
 *
 * @package OpenPGP
 * @version 0.0.1
 * @author  Arto Bendiken <arto.bendiken@gmail.com>
 * @author  Stephen Paul Weber <singpolyma@singpolyma.net>
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

  function to_bytes() {
    $bytes = '';
    foreach($this as $p) {
      $bytes .= $p->to_bytes();
    }
    return $bytes;
  }

  function signature_and_data($index=0) {
    $msg = $this;
    while($msg[0] instanceof OpenPGP_CompressedDataPacket) $msg = $msg[0];

    $i = 0;
    foreach($msg as $p) {
      if($p instanceof OpenPGP_SignaturePacket) {
        if($i == $index) $signature_packet = $p;
        $i++;
      }
      if($p instanceof OpenPGP_LiteralDataPacket) $data_packet = $p;
      if($signature_packet && $data_packet) break;
    }

    return array($signature_packet, $data_packet);
  }

  /**
   * Function to verify signature number $index
   * $verifiers is an array of callbacks formatted like array('RSA' => array('SHA256' => CALLBACK)) that take two parameters: message and signature
   */
  function verify($verifiers, $index=0) {
    list($signature_packet, $data_packet) = $this->signature_and_data($index);
    if(!$signature_packet || !$data_packet) return NULL; // No signature or no data

    $verifier = $verifiers[$signature_packet->key_algorithm_name()][$signature_packet->hash_algorithm_name()];
    if(!$verifier) return NULL; // No verifier

    $data_packet->normalize();
    return call_user_func($verifier, $data_packet->data.$signature_packet->trailer, $signature_packet->data);
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
    $len = ord($input[1]);
    if($len < 192) { // One octet length
      return array($tag, 2, $len);
    }
    if($len > 191 && $len < 224) { // Two octet length
      return array($tag, 3, (($len - 192) << 8) + ord($input[2]) + 192);
    }
    if($len == 255) { // Five octet length
      return array($tag, 6, array_pop(unpack('N', substr($input, 2, 4))));
    }
    // TODO: Partial body lengths. 1 << ($len & 0x1F)
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

  function __construct($data=NULL) {
    $this->tag = array_search(substr(substr(get_class($this), 8), 0, -6), self::$tags);
    $this->data = $data;
  }

  function read() {
  }

  function body() {
    return $this->data; // Will normally be overridden by subclasses
  }

  function header_and_body() {
    $body = $this->body(); // Get body first, we will need it's length
    $tag = chr($this->tag | 0xC0); // First two bits are 1 for new packet format
    $size = chr(255).pack('N', strlen($body)); // Use 5-octet lengths
    return array('header' => $tag.$size, 'body' => $body);
  }

  function to_bytes() {
    $data = $this->header_and_body();
    return $data['header'].$data['body'];
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
  public $version, $signature_type, $hash_algorithm, $key_algorithm, $hashed_subpackets, $unhashed_subpackets, $hash_head;
  public $trailer; // This is the literal bytes that get tacked on the end of the message when verifying the signature

  function __construct($data=NULL, $key_algorithm=NULL, $hash_algorithm=NULL) {
    parent::__construct();
    $this->version = 4; // Default to version 4 sigs
    if(is_string($this->hash_algorithm = $hash_algorithm)) {
      $this->hash_algorithm = array_search($this->hash_algorithm, self::$hash_algorithms);
    }
    if(is_string($this->key_algorithm = $key_algorithm)) {
      $this->key_algorithm = array_search($this->key_algorithm, OpenPGP_PublicKeyPacket::$algorithms);
    }
    if($data) { // If we have any data, set up the creation time
      $this->hashed_subpackets = array(new OpenPGP_SignaturePacket_SignatureCreationTimePacket(time()));
    }
    if($data instanceof OpenPGP_LiteralDataPacket) {
      $this->signature_type = ($data->format == 'b') ? 0x00 : 0x01;
      $data->normalize();
      $data = $data->data;
    }
    $this->data = $data; // Store to-be-signed data in here until the signing happens
  }

  /**
   * $this->data must be set to the data to sign (done by constructor)
   * $signers in the same format as $verifiers for OpenPGP_Message.
   */
  function sign_data($signers) {
    $this->trailer = $this->body(true);
    $signer = $signers[$this->key_algorithm_name()][$this->hash_algorithm_name()];
    $this->data = call_user_func($signer, $this->data.$this->trailer);
    $this->hash_head = array_pop(unpack('n', substr($this->data, 0, 2)));
  }

  function read() {
    switch($this->version = ord($this->read_byte())) {
      case 3:
        // TODO: V3 sigs
        break;
      case 4:
        $this->signature_type = ord($this->read_byte());
        $this->key_algorithm = ord($this->read_byte());
        $this->hash_algorithm = ord($this->read_byte());
        $this->trailer = chr(4).chr($this->signature_type).chr($this->key_algorithm).chr($this->hash_algorithm);

        $hashed_size = $this->read_unpacked(2, 'n');
        $hashed_subpackets = $this->read_bytes($hashed_size);
        $this->trailer .= pack('n', $hashed_size).$hashed_subpackets;
        $this->hashed_subpackets = self::get_subpackets($hashed_subpackets);

        $this->trailer .= chr(4).chr(0xff).pack('N', 6 + $hashed_size);

        $unhashed_size = $this->read_unpacked(2, 'n');
        $this->unhashed_subpackets = self::get_subpackets($this->read_bytes($unhashed_size));

        $this->hash_head = $this->read_unpacked(2, 'n');
        $this->data = $this->read_mpi();
        break;
    }
  }

  function body($trailer=false) {
    $body = chr(4).chr($this->signature_type).chr($this->key_algorithm).chr($this->hash_algorithm);

    $hashed_subpackets = '';
    foreach((array)$this->hashed_subpackets as $p) {
      $hashed_subpackets .= $p->to_bytes();
    }
    $body .= pack('n', strlen($hashed_subpackets)).$hashed_subpackets;

    // The trailer is just the top of the body plus some crap
    if($trailer) return $body.chr(4).chr(0xff).pack('N', strlen($body));

    $unhashed_subpackets = '';
    foreach((array)$this->unhashed_subpackets as $p) {
      $unhashed_subpackets .= $p->to_bytes();
    }
    $body .= pack('n', strlen($unhashed_subpackets)).$unhashed_subpackets;

    $body .= pack('n', $this->hash_head);
    $body .= pack('n', strlen($this->data)*8).$this->data;

    return $body;
  }

  function key_algorithm_name() {
    return OpenPGP_PublicKeyPacket::$algorithms[$this->key_algorithm];
  }

  function hash_algorithm_name() {
    return self::$hash_algorithms[$this->hash_algorithm];
  }

  function issuer() {
    foreach($this->hashed_subpackets as $p) {
      if($p instanceof OpenPGP_SignaturePacket_IssuerPacket) return $p->data;
    }
    foreach($this->unhashed_subpackets as $p) {
      if($p instanceof OpenPGP_SignaturePacket_IssuerPacket) return $p->data;
    }
    return NULL;
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.1
   */
  static function get_subpackets($input) {
    $subpackets = array();
    while(($length = strlen($input)) > 0) {
      $subpackets[] = self::get_subpacket($input);
      if($length == strlen($input)) { // Parsing stuck?
        break;
      }
    }
    return $subpackets;
  }

  static function get_subpacket(&$input) {
    $len = ord($input[0]);
    $length_of_length = 1;
    // if($len < 192) One octet length, no furthur processing
    if($len > 190 && $len < 255) { // Two octet length
      $length_of_length = 2;
      $len = (($len - 192) << 8) + ord($input[1]) + 192;
    }
    if($len == 255) { // Five octet length
      $length_of_length = 5;
      $len = array_pop(unpack('N', substr($input, 1, 4)));
    }
    $input = substr($input, $length_of_length); // Chop off length header
    $tag = ord($input[0]);
    $class = self::class_for($tag);
    if($class) {
      $packet = new $class();
      $packet->tag = $tag;
      $packet->input = substr($input, 1, $len-1);
      $packet->length = $len-1;
      $packet->read();
      unset($packet->input);
    }
    $input = substr($input, $len); // Chop off the data from this packet
    return $packet;
  }

  static $hash_algorithms = array(
       1 => 'MD5',
       2 => 'SHA1',
       3 => 'RIPEMD160',
       8 => 'SHA256',
       9 => 'SHA384',
      10 => 'SHA512',
      11 => 'SHA224'
    );

  static $subpacket_types = array(
      //0 => 'Reserved',
      //1 => 'Reserved',
      2 => 'SignatureCreationTime',
      3 => 'SignatureExpirationTime',
      4 => 'ExportableCertification',
      5 => 'TrustSignature',
      6 => 'RegularExpression',
      7 => 'Revocable',
      //8 => 'Reserved',
      9 => 'KeyExpirationTime',
      //10 => 'Placeholder for backward compatibility',
      11 => 'PreferredSymmetricAlgorithms',
      12 => 'RevocationKey',
      //13 => 'Reserved',
      //14 => 'Reserved',
      //15 => 'Reserved',
      16 => 'Issuer',
      //17 => 'Reserved',
      //18 => 'Reserved',
      //19 => 'Reserved',
      20 => 'NotationData',
      21 => 'PreferredHashAlgorithms',
      22 => 'PreferredCompressionAlgorithms',
      23 => 'KeyServerPreferences',
      24 => 'PreferredKeyServer',
      25 => 'PrimaryUserID',
      26 => 'PolicyURI',
      27 => 'KeyFlags',
      28 => 'SignersUserID',
      29 => 'ReasonforRevocation',
      30 => 'Features',
      31 => 'SignatureTarget',
      32 => 'EmbeddedSignature',
    );

  static function class_for($tag) {
    if(!self::$subpacket_types[$tag]) return NULL;
    return 'OpenPGP_SignaturePacket_'.self::$subpacket_types[$tag].'Packet';
  }

}

class OpenPGP_SignaturePacket_Subpacket extends OpenPGP_Packet {
  function __construct($data=NULL) {
    parent::__construct($data);
    $this->tag = array_search(substr(substr(get_class($this), 8+16), 0, -6), OpenPGP_SignaturePacket::$subpacket_types);
  }

  function header_and_body() {
    $body = $this->body(); // Get body first, we will need it's length
    $size = chr(255).pack('N', strlen($body)+1); // Use 5-octet lengths + 1 for tag as first packet body octet
    $tag = chr($this->tag);
    return array('header' => $size.$tag, 'body' => $body);
  }
}

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.4
 */
class OpenPGP_SignaturePacket_SignatureCreationTimePacket extends OpenPGP_SignaturePacket_Subpacket {
  function read() {
    $this->data = $this->read_timestamp();
  }

  function body() {
    return pack('N', $this->data);
  }
}

class OpenPGP_SignaturePacket_SignatureExpirationTimePacket extends OpenPGP_SignaturePacket_Subpacket {
  function read() {
    $this->data = $this->read_timestamp();
  }

  function body() {
    return pack('N', $this->data);
  }
}

class OpenPGP_SignaturePacket_ExportableCertificationPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_TrustSignaturePacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_RegularExpressionPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_RevocablePacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_KeyExpirationTimePacket extends OpenPGP_SignaturePacket_Subpacket {
  function read() {
    $this->data = $this->read_timestamp();
  }

  function body() {
    return pack('N', $this->data);
  }
}

class OpenPGP_SignaturePacket_PreferredSymmetricAlgorithmsPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_RevocationKeyPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

/**
 * @see http://tools.ietf.org/html/rfc4880#section-5.2.3.5
 */
class OpenPGP_SignaturePacket_IssuerPacket extends OpenPGP_SignaturePacket_Subpacket {
  function read() {
    for($i = 0; $i < 8; $i++) { // Store KeyID in Hex
      $this->data .= sprintf('%02X',ord($this->read_byte()));
    }
  }

  function body() {
    $bytes = '';
    for($i = 0; $i < strlen($this->data); $i += 2) {
      $bytes .= chr(hexdec($this->data{$i}.$this->data{$i+1}));
    }
    return $bytes;
  }
}

class OpenPGP_SignaturePacket_NotationDataPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_PreferredHashAlgorithmsPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_PreferredCompressionAlgorithmsPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_KeyServerPreferencesPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_PreferredKeyServerPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_PrimaryUserIDPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_PolicyURIPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_KeyFlagsPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_SignersUserIDPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_ReasonforRevocationPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_FeaturesPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_SignatureTargetPacket extends OpenPGP_SignaturePacket_Subpacket {
  // TODO
}

class OpenPGP_SignaturePacket_EmbeddedSignaturePacket extends OpenPGP_SignaturePacket {
  // TODO: This is duplicated from subpacket... improve?
  function __construct($data=NULL) {
    parent::__construct($data);
    $this->tag = array_search(substr(substr(get_class($this), 8+16), 0, -6), OpenPGP_SignaturePacket::$subpacket_types);
  }

  function header_and_body() {
    $body = $this->body(); // Get body first, we will need it's length
    $size = chr(255).pack('N', strlen($body)+1); // Use 5-octet lengths + 1 for tag as first packet body octet
    $tag = chr($this->tag);
    return array('header' => $size.$tag, 'body' => $body);
  }
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
  public $version, $signature_type, $hash_algorithm, $key_algorithm, $key_id, $nested;
  function read() {
    $this->version = ord($this->read_byte());
    $this->signature_type = ord($this->read_byte());
    $this->hash_algorithm = ord($this->read_byte());
    $this->key_algorithm = ord($this->read_byte());
    for($i = 0; $i < 8; $i++) { // Store KeyID in Hex
      $this->key_id .= sprintf('%02X',ord($this->read_byte()));
    }
    $this->nested = ord($this->read_byte());
  }

  function body() {
    $body = chr($this->version).chr($this->signature_type).chr($this->hash_algorithm).chr($this->key_algorithm);
    for($i = 0; $i < strlen($this->key_id); $i += 2) {
      $body .= chr(hexdec($this->key_id{$i}.$this->key_id{$i+1}));
    }
    $body .= chr((int)$this->nested);
    return $body;
  }
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

  // Find self signatures in a message, these often contain metadata about the key
  function self_signatures($message) {
    $sigs = array();
    $keyid16 = strtoupper(substr($this->fingerprint, -16));
    foreach($message as $p) {
      if($p instanceof OpenPGP_SignaturePacket) {
        if(strtoupper($p->issuer()) == $keyid16) {
          $sigs[] = $p;
        } else {
          foreach(array_merge($p->hashed_subpackets, $p->unhashed_subpackets) as $s) {
            if($s instanceof OpenPGP_SignaturePacket_EmbeddedSignaturePacket && strtoupper($s->issuer()) == $keyid16) {
              $sigs[] = $p;
              break;
            }
          }
        }
      } else if(count($sigs)) break; // After we've seen a self sig, the next non-sig stop all self-sigs
    }
    return $sigs;
  }

  // Find expiry time of this key based on the self signatures in a message
  function expires($message) {
    foreach($this->self_signatures($message) as $p) {
      foreach(array_merge($p->hashed_subpackets, $p->unhashed_subpackets) as $s) {
        if($s instanceof OpenPGP_SignaturePacket_KeyExpirationTimePacket) {
          return $this->timestamp + $s->data;
        }
      }
    }
    return NULL; // Never expires
  }

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
    foreach (self::$key_fields[$this->algorithm] as $field) {
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
        $head = array(
          chr(0x99), NULL,
          chr($this->version), pack('N', $this->timestamp),
          chr($this->algorithm),
        );
        $material = array();
        foreach (self::$key_fields[$this->algorithm] as $i) {
          $material[] = pack('n', OpenPGP::bitlength($this->key[$i]));
          $material[] = $this->key[$i];
        }
        $material = implode('', $material);
        $head[1] = pack('n', 6 + strlen($material));
        return $this->fingerprint = sha1(implode('',$head).$material);
    }
  }

  static $key_fields = array(
     1 => array('n', 'e'),           // RSA
    16 => array('p', 'g', 'y'),      // ELG-E
    17 => array('p', 'q', 'g', 'y'), // DSA
  );

  static $algorithms = array(
       1 => 'RSA',
       2 => 'RSA',
       3 => 'RSA',
      16 => 'ELGAMAL',
      17 => 'DSA',
      18 => 'ECC',
      19 => 'ECDSA',
      21 => 'DH'
    );

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
  public $s2k_useage, $s2k_type, $s2k_hash_algorithm, $s2k_salt, $s2k_count, $symmetric_type, $private_hash, $encrypted_data;
  function read() {
    parent::read(); // All the fields from PublicKey
    $this->s2k_useage = ord($this->read_byte());
    if($this->s2k_useage == 255 || $this->s2k_useage == 254) {
      $this->symmetric_type = ord($this->read_byte());
      $this->s2k_type = ord($this->read_byte());
      $this->s2k_hash_algorithm = ord($this->read_byte());
      if($this->s2k_type == 1 || $this->s2k_type == 3) $this->s2k_salt = $this->read_bytes(8);
      if($this->s2k_type == 3) {
        $c = ord($this->read_byte());
        $this->s2k_count = ((int)16 + ($c & 15)) << (($c >> 4) + 6);
      }
    } else if($this->s2k_useage > 0) {
      $this->symmetric_type = $this->s2k_useage;
    }
    if($this->s2k_useage > 0) {
      // TODO: IV of the same length as cipher's block size
      $this->encrypted_data = $this->input; // Rest of input is MPIs and checksum (encrypted)
    } else {
      $this->data = $this->input; // Rest of input is MPIs and checksum
      $this->key_from_data();
    }
  }

  function key_from_data() {
    if(!$this->data) return NULL; // Not decrypted yet
    $this->input = $this->data;

    static $key_fields = array(
       1 => array('d', 'p', 'q', 'u'), // RSA
      16 => array('x'),                // ELG-E
      17 => array('x'),                // DSA
    );
    foreach($key_fields[$this->algorithm] as $field) {
      $this->key[$field] = $this->read_mpi();
    }

    // TODO: Validate checksum?
    if($this->s2k_useage == 254) { // 20 octet sha1 hash
      $this->private_hash = $this->read_bytes(20);
    } else { // two-octet checksum
      $this->private_hash = $this->read_bytes(2);
    }

    unset($this->input);
  }
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
class OpenPGP_CompressedDataPacket extends OpenPGP_Packet implements IteratorAggregate, ArrayAccess {
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
  }

  function body() {
    $body = chr($this->algorithm);
    switch($this->algorithm) {
      case 0:
        $body .= $this->data->to_bytes();
        break;
      case 1:
        $body .= gzdeflate($this->data->to_bytes());
        break;
      case 2:
        $body .= gzcompress($this->data->to_bytes());
        break;
      case 3:
        $body .= bzcompress($this->data->to_bytes());
        break;
      default:
        /* TODO error? */
    }
    return $body;
  }

  // IteratorAggregate interface

  function getIterator() {
    return new ArrayIterator($this->data->packets);
  }

  // ArrayAccess interface

  function offsetExists($offset) {
    return isset($this->data[$offset]);
  }

  function offsetGet($offset) {
    return $this->data[$offset];
  }

  function offsetSet($offset, $value) {
    return is_null($offset) ? $this->data[] = $value : $this->data[$offset] = $value;
  }

  function offsetUnset($offset) {
    unset($this->data[$offset]);
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

  function __construct($data=NULL, $opt=array()) {
    parent::__construct();
    $this->data = $data;
    $this->format = $opt['format'] ? $opt['format'] : 'b';
    $this->filename = $opt['filename'] ? $opt['filename'] : 'data';
    $this->timestamp = $opt['timestamp'] ? $opt['timestamp'] : time();
  }

  function normalize() {
    if($this->format == 'u' || $this->format == 't') { // Normalize line endings
      $this->data = str_replace("\n", "\r\n", str_replace("\r", "\n", str_replace("\r\n", "\n", $this->data)));
    }
  }

  function read() {
    $this->size = $this->length - 1 - 4;
    $this->format = $this->read_byte();
    $filename_length = ord($this->read_byte());
    $this->size -= $filename_length;
    $this->filename = $this->read_bytes($filename_length);
    $this->timestamp = $this->read_timestamp();
    $this->data = $this->read_bytes($this->size);
  }

  function body() {
    return $this->format.chr(strlen($this->filename)).$this->filename.pack('N', $this->timestamp).$this->data;
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
