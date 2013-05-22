component displayname="XMPPPrebind" accessors="true" {
  property string XMLNS_BODY;
  property string XMLNS_BOSH;
  property string XMLNS_CLIENT;
  property string XMLNS_SESSION;
  property string XMLNS_BIND;
  property string XMLNS_SASL;
  property string XMLNS_VCARD;

  property string XML_LANG;
  property string CONTENT_TYPE;

  property string ENCRYPTION_PLAIN;
  property string ENCRYPTION_DIGEST_MD5;
  property string ENCRYPTION_CRAM_MD5;

  property string SERVICE_NAME;
  this.setXMLNS_BODY('http://jabber.org/protocol/httpbind');
  this.setXMLNS_BOSH('urn:xmpp:xbosh');
  this.setXMLNS_CLIENT('jabber:client');
  this.setXMLNS_SESSION('urn:ietf:params:xml:ns:xmpp-session');
  this.setXMLNS_BIND('urn:ietf:params:xml:ns:xmpp-bind');
  this.setXMLNS_SASL('urn:ietf:params:xml:ns:xmpp-sasl');
  this.setXMLNS_VCARD('vcard-temp');
  this.setXML_LANG('en');
  this.setCONTENT_TYPE('text/xml charset=utf-8');
  this.setENCRYPTION_PLAIN('PLAIN');
  this.setENCRYPTION_DIGEST_MD5('DIGEST-MD5');
  this.setENCRYPTION_CRAM_MD5('CRAM-MD5');
  this.setSERVICE_NAME('xmpp');
  /**
   * Create a new XmppPrebind Object with the required params
   *
   * @param string $jabberHost Jabber Server Host
   * @param string $boshUri    Full URI to the http-bind
   * @param string $resource   Resource identifier
   * @param bool   $useSsl     Use SSL (not working yet, TODO)
   * @param bool   $debugEnable debug
  **/
  public XMPPPrebind function init($jabberHost, $boshUri, $resource, $useSsl = false) {
    $this = this;
    $this.jabberHost = arguments.$jabberHost;
    $this.boshUri    = arguments.$boshUri;
    $this.resource   = arguments.$resource;
    $this.useSsl = arguments.$useSsl;
    $this.mechanisms = [];
    /*
     * The client MUST generate a large, random, positive integer for the initial 'rid' (see Security Considerations)
     * and then increment that value by one for each subsequent request. The client MUST take care to choose an
     * initial 'rid' that will never be incremented above 9007199254740991 [21] within the session.
     * In practice, a session would have to be extraordinarily long (or involve the exchange of an extraordinary
     * number of packets) to exceed the defined limit.
     *
     * @link http://xmpp.org/extensions/xep-0124.html#rids
     */

     $this.rid = RandRange(1000000000, 10000000000);
    return $this;
  }
  private function debug($obj,$label) {
    writeDump(var=$obj,label=$label);
  }
  /**
   * connect to the jabber server with the supplied username & password
   *
   * @param string $username Username without jabber host
   * @param string $password Password
   */
  public function connect($username, $password) {
    this.jid      = $username & '@' & this.jabberHost & '/' & this.resource;
    this.password = $password;

    $response = this.sendInitialConnection();
    
    $documentObj = XmlParse($response);
    this.sid = $documentObj.XmlRoot.XmlAttributes['sid'];
    this.debug(this.sid, 'sid');
    //writeDump(var=$documentObj,abort=true);
    // $mechanisms = $documentObj.XmlChildren[1].XmlChildren[1].XmlChildren[1];
    // for ($value in $mechanisms.XmlChildren) {
    //   this.mechanisms.add($value.XmlText);
    // }
    // if (arrayFindNoCase(this.mechanisms,this.getENCRYPTION_DIGEST_MD5())) {
    //   this.encryption = "ENCRYPTION_DIGEST_MD5";
    // } elseif (arrayFindNoCase(this.mechanisms,this.getENCRYPTION_CRAM_MD5())) {
    //   this.encryption = "ENCRYPTION_CRAM_MD5";
    // } elseif (arrayFindNoCase(this.mechanisms,this.getENCRYPTION_PLAIN())) {
    //   this.encryption = "ENCRYPTION_PLAIN";
    // } else {
    //   throw "No encryption supported by the server is supported by this library.";
    // }
    this.encryption = "ENCRYPTION_PLAIN";
    //this.debug(this.encryption, 'encryption used');
  }

  /**
   * Try to authenticate
   *
   * @throws XmppPrebindException if invalid login
   * @return bool
   */
  public function auth() {
    //TODO: NEEDS SASL IMPLEMENTATION (most likely JAVA based);
    $auth = createObject("component","lib.auth_sasl.plain");
    $authXml = this.buildPlainAuth($auth);
    
    // switch (this.encryption) {
    //   case ENCRYPTION_PLAIN:
        
    //     break;
    //   case ENCRYPTION_DIGEST_MD5:
    //     $authXml = this.sendChallengeAndBuildDigestMd5Auth($auth);
    //     break;
    //   case ENCRYPTION_CRAM_MD5:
    //     $authXml = this.sendChallengeAndBuildCramMd5Auth($auth);
    //     break;
    // }
    $response = this.send($authXml);
    writeDump(var=$response,abort=true);
    flush();
    $body = getBodyFromXml($response);

    if (!$body.hasChildNodes() || $body.firstChild.nodeName NEQ 'success') {
      throw new XmppPrebindException("Invalid login");
    }

    this.sendRestart();
    this.sendBindIfRequired();
    this.sendSessionIfRequired();

    return true;
  }

  /**
   * Get jid, sid and rid for attaching
   *
   * @return array
   */
  public struct function getSessionInfo() {
    return {'jid': this.jid, 'sid': this.sid, 'rid': this.rid };
  }

  /**
   * Send xmpp restart message after successful auth
   *
   * @return string Response
   */
  private function sendRestart() {
    $domDocument = this.buildBody();
    $body = $domDocument.body;
    $body['xmlns'] = XmlElemNew($xml,"xmlns")
    $body['to'] = XmlElemNew($domDocument, 'to', this.jabberHost);
    $body['xmlns:xmpp'] = XmlElemNew($domDocument,'xmlns:xmpp', this.getXMLNS_BOSH());
    $body['xmpp:restart'] = XmlElemNew($domDocument,'xmpp:restart', 'true');

    $restartResponse = this.send($domDocument.saveXML());

    $restartBody = getBodyFromXml($restartResponse);
    for ($bodyChildNodes in $restartBody.childNodes) {
      if ($bodyChildNodes.nodeName === 'stream:features') {
        for ($streamFeatures in $bodyChildNodes.childNodes) {
          if ($streamFeatures.nodeName === 'bind') {
            this.doBind = true;
          } elseif ($streamFeatures.nodeName === 'session') {
            this.doSession = true;
          }
        }
      }
    }

    return $restartResponse;
  }

  /**
   * Send xmpp bind message after restart
   *
   * @return string Response
   */
  private function sendBindIfRequired() {
    if (this.doBind) {
      $domDocument = this.buildBody();
      $body = getBodyFromDomDocument($domDocument);

      $iq = $domDocument.createElement('iq');
      $iq.appendChild(getNewTextAttribute($domDocument, 'xmlns', XMLNS_CLIENT));
      $iq.appendChild(getNewTextAttribute($domDocument, 'type', 'set'));
      $iq.appendChild(getNewTextAttribute($domDocument, 'id', 'bind_' & rand()));

      $bind = $domDocument.createElement('bind');
      $bind.appendChild(getNewTextAttribute($domDocument, 'xmlns', XMLNS_BIND));

      $resource = $domDocument.createElement('resource');
      $resource.appendChild($domDocument.createTextNode(this.resource));

      $bind.appendChild($resource);
      $iq.appendChild($bind);
      $body.appendChild($iq);

      return this.send($domDocument.saveXML());
    }
    return false;
  }

  /**
   * Send session if there's a session node in the restart response (within stream:features)
   */
  private function sendSessionIfRequired() {
    if (this.doSession) {
      $domDocument = this.buildBody();
      $body = getBodyFromDomDocument($domDocument);

      $iq = $domDocument.createElement('iq');
      $iq.appendChild(getNewTextAttribute($domDocument, 'xmlns', XMLNS_CLIENT));
      $iq.appendChild(getNewTextAttribute($domDocument, 'type', 'set'));
      $iq.appendChild(getNewTextAttribute($domDocument, 'id', 'session_auth_' & rand()));

      $session = $domDocument.createElement('session');
      $session.appendChild(getNewTextAttribute($domDocument, 'xmlns', XMLNS_SESSION));

      $iq.appendChild($session);
      $body.appendChild($iq);

      return this.send($domDocument.saveXML());
    }
    return false;
  }

  /**
   * Send initial connection string
   *
   * @return string Response
   */
  private function sendInitialConnection() {
    $domDocument = this.buildBody();
    $body = $domDocument.body;

    $waitTime = 60;
    $domDocument.XmlRoot.XmlAttributes['hold'] = "1";
    $domDocument.XmlRoot.XmlAttributes['to'] = this.jabberHost;
    $domDocument.XmlRoot.XmlAttributes['xmlns:xmpp'] = this.getXMLNS_BOSH();
    //$domDocument.XmlRoot.XmlAttributes['xmpp:version'] = '1.0';
    $domDocument.XmlRoot.XmlAttributes['wait'] = $waitTime;

    return this.send(ToString($domDocument));
  }

  /**
   * Send challenge request
   *
   * @return string Challenge
   */
  private function sendChallenge() {
    $domDocument = this.buildBody();
    $body = $domDocument.XmlRoot;

    $auth = $body.XmlChildren['auth'] = XmlElemNew($domDocument,'auth');
    $auth.XmlAttributes['xmlns'] = this.getXMLNS_SASL();
    $auth.XmlAttributes['mechanism'] = this.encryption;
    
    $response = this.send(ToString($domDocument));

    $body = XmlParse($response).XmlRoot;
    $challenge = ToString(ToBinary($body.XmlChildren[1].XmlText));

    return $challenge;
  }

  /**
   * Build PLAIN auth string
   *
   * @param Auth_SASL_Common $auth
   * @return string Auth XML to send
   */
  private function buildPlainAuth(lib.auth_sasl.plain $auth) {
    $authString = $auth.getResponse(getNodeFromJid(this.jid), this.password, getBareJidFromJid(this.jid));
    $authString = toBase64($authString);
    this.debug($authString, 'PLAIN Auth String');

    $domDocument = this.buildBody();
    $body = $domDocument.XmlRoot;

    $auth = $body['auth'] = XmlElemNew($domDocument,'auth');
    $auth.XmlAttributes['xmlns'] = this.getXMLNS_SASL();
    $auth.XmlAttributes['mechanism'] = this.encryption;
    $auth.XmlText = $authString;
    
    return ToString($domDocument);
  }

  /**
   * Send challenge request and build DIGEST-MD5 auth string
   *
   * @param Auth_SASL_Common $auth
   * @return string Auth XML to send
   */
  private function sendChallengeAndBuildDigestMd5Auth(Auth_SASL_Common $auth) {
    $challenge = this.sendChallenge();

    $authString = $auth.getResponse(getNodeFromJid(this.jid), this.password, $challenge, this.jabberHost, SERVICE_NAME, this.jid);
    this.debug($authString, 'DIGEST-MD5 Auth String');

    $authString = toBase64($authString);

    $domDocument = this.buildBody();
    $body = getBodyFromDomDocument($domDocument);

    $response = $domDocument.createElement('response');
    $response.appendChild(getNewTextAttribute($domDocument, 'xmlns', XMLNS_SASL));
    $response.appendChild($domDocument.createTextNode($authString));

    $body.appendChild($response);


    $challengeResponse = this.send($domDocument.saveXML());

    return this.replyToChallengeResponse($challengeResponse);
  }

  /**
   * Send challenge request and build CRAM-MD5 auth string
   *
   * @param Auth_SASL_Common $auth
   * @return string Auth XML to send
   */
  private function sendChallengeAndBuildCramMd5Auth(Auth_SASL_Common $auth) {
    $challenge = this.sendChallenge();

    $authString = $auth.getResponse(getNodeFromJid(this.jid), this.password, $challenge);
    this.debug($authString, 'CRAM-MD5 Auth String');

    $authString = toBase64($authString);

    $domDocument = this.buildBody();
    $body = getBodyFromDomDocument($domDocument);

    $response = $domDocument.createElement('response');
    $response.appendChild(getNewTextAttribute($domDocument, 'xmlns', XMLNS_SASL));
    $response.appendChild($domDocument.createTextNode($authString));

    $body.appendChild($response);

    $challengeResponse = this.send($domDocument.saveXML());

    return this.replyToChallengeResponse($challengeResponse);
  }

  /**
   * CRAM-MD5 and DIGEST-MD5 reply with an additional challenge response which must be replied to.
   * After this additional reply, the server should reply with "success".
   */
  private function replyToChallengeResponse($challengeResponse) {
    $body = getBodyFromXml($challengeResponse);

    $challenge = ToString(BinaryDecode($body.firstChild.nodeValue , "base64"));
    if (!findNoCase($challenge, 'rspauth')) {
      throw new XmppPrebindConnectionException('Invalid challenge response received');
    }

    $domDocument = this.buildBody();
    $body = getBodyFromDomDocument($domDocument);
    $response = $domDocument.createElement('response');
    $response.appendChild(getNewTextAttribute($domDocument, 'xmlns', XMLNS_SASL));

    $body.appendChild($response);

    return $domDocument.saveXML();
  }

  /**
   * Send XML via CURL
   *
   * @param string $xml
   * @return string Response
   */
  private function send($xml) {
    $ch = new HTTP();
    $ch.setUrl(this.boshUri);
    $ch.setMethod("POST");
    $ch.setRedirect(true);

    $ch.addParam(type='body',value=$xml);
    $ch.addParam(type='header',name="content-type",value='text/xml');
    $response = $ch.send().getPrefix(); 
    
    writeDump(var=$xml,label='SENT:');
    writeDump(var=$response.filecontent, label='RECV:');

    return $response.filecontent;
  }

  /**
   * Fix gzdecompress/gzinflate data error warning.
   *
   * @link http://www.mydigitallife.info/2010/01/17/workaround-to-fix-php-warning-gzuncompress-or-gzinflate-data-error-in-wordpress-http-php/
   *
   * @param string $gzData
   * @return string|bool
   */
  // public static function compatibleGzInflate($gzData) {
  //   if ( substr($gzData, 0, 3) == "\x1f\x8b\x08" ) {
  //     $i = 10;
  //     $flg = ord( substr($gzData, 3, 1) );
  //     if ( $flg > 0 ) {
  //       if ( $flg & 4 ) {
  //         list($xlen) = unpack('v', substr($gzData, $i, 2) );
  //         $i = $i + 2 + $xlen;
  //       }
  //       if ( $flg & 8 )
  //       $i = strpos($gzData, "\0", $i) + 1;
  //       if ( $flg & 16 )
  //       $i = strpos($gzData, "\0", $i) + 1;
  //       if ( $flg & 2 )
  //       $i = $i + 2;
  //     }
  //     return gzinflate( substr($gzData, $i, -8) );
  //   } else {
  //     return false;
  //   }
  // }

  /**
   * Build DOMDocument with standard xmpp body child node.
   *
   * @return DOMDocument
   */
  private function buildBody() {
    $xml = XmlNew();

    $xml.xmlRoot = XmlElemNew($xml,"body")
    
    $xml.body.XmlAttributes['xmlns'] = this.getXMLNS_BODY();
    $xml.body.XmlAttributes['content'] = this.getCONTENT_TYPE()
    $xml.body.XmlAttributes['rid'] = getAndIncrementRid()
    $xml.body.XmlAttributes['xml:lang'] = this.getXML_LANG();

    if (structKeyExists(this,'sid') AND this.sid NEQ '') {
      $xml.body.XmlAttributes['sid'] = this.sid;
    }

    return $xml;
  }

  /**
   * Get jid in form of username@jabberHost
   *
   * @param string $jid Jid in form username@jabberHost/Resource
   * @return string JID
   */
  public function getBareJidFromJid($jid) {
    if ($jid == '') {
      return '';
    }
    $splittedJid = listFirst($jid,'/');
    return $splittedJid;
  }

  /**
   * Get node (username) from jid
   *
   * @param string $jid
   * @return string Node
   */
  public function getNodeFromJid($jid) {
    var $node = listFirst(arguments.$jid,'@');
    return $node;
  }

  /**
   * Append new attribute to existing DOMDocument.
   *
   * @param DOMDocument $domDocument
   * @param string $attributeName
   * @param string $value
   * @return DOMNode
   */
  private function getNewTextAttribute($domDocument, $attributeName, $value) {
    var $attribute = arguments.$domDocument.XmlRoot.XmlAttributes[arguments.$attributeName];

    return $attribute;
  }

  /**
   * Get body node from DOMDocument
   *
   * @param DOMDocument $domDocument
   * @return DOMNode
   */
  private function getBodyFromDomDocument($domDocument) {
    return arguments.$domDocument.body;
  }

  /**
   * Parse XML and return DOMNode of the body
   *
   * @uses XmppPrebind.getBodyFromDomDocument()
   * @param string $xml
   * @return DOMNode
   */
  private function getBodyFromXml($xml) {
    var $domDocument = xmlParse(arguments.$xml);

    return $domDocument.XmlRoot;
  }

  /**
   * Get the rid and increment it by one.
   * Required by RFC
   *
   * @return int
   */
  private function getAndIncrementRid() {
    return this.rid++;
  }
}