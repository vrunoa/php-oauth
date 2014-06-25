<?php
class Model_Oauth extends Zend_Db_Table_Abstract {

    const NONCE_DURATION = 86400;
    const TIMESTAMP_OFFSET = 3600;

    public function requestToken($client_id) {

        $output = array(
            'oauth_token' => $this->uniqid(16),
            'oauth_token_secret' => $this->uniqid(16)
        );
        $table = new Zend_Db_Table('oauth_token');
        $data  = array(
            'client'             => $client_id,
            'oauth_token'        => $output['oauth_token'],
            'oauth_token_secret' => $output['oauth_token_secret'],
            'token_type'         => 'request'
        );
	try {
            $table->insert($data);
        }catch(Zend_Db_Table_Exception $e) {
            return $e;
        }
        return $output;
    }

    public function getClient($oauth_consumer_key) {
        
        $oauth_consumer_key = $this->_db->quote($oauth_consumer_key);
       
        $table = new Zend_Db_Table('oauth_client');
        $sql   = $table->select()->where("client_key = $oauth_consumer_key AND status = 'Active'");
        
        $res   = $table->fetchAll($sql)->toArray();
        return sizeof($res) ? $res[0] : null;
    }


    public function getClientById($id_client) {

        $table = new Zend_Db_Table('oauth_client');
        $sql   = $table->select()->where("id = $id_client AND status = 'Active'");

        $res   = $table->fetchAll($sql)->toArray();
        return sizeof($res) ? $res[0] : null;        
    }

    public function authorize($oauth_token, $oauth_token_secret, $user_id) {
        /*
	 * UPDATE oauth_token
         * SET user = ".(int) $user_data['id'].",
         *     oauth_verifier = '".addslashes($output['oauth_verifier'])."',
         *     token_type = 'verified'
         * WHERE oauth_token = '".addslashes($_REQUEST['oauth_token'])."'
         * AND oauth_token_secret = '".addslashes($_REQUEST['oauth_token_secret'])."'";
         */

        $oauth_verifier     = $this->uniqid(16);
        $oauth_token        = $this->_db->quote($oauth_token);
        $oauth_token_secret = $this->_db->quote($oauth_token_secret);

        $table = new Zend_Db_Table('oauth_token');
        $data = array(
            'user'  => $user_id,
            'oauth_verifier' => $oauth_verifier,
            'token_type' => 'verified'
        );
       
        $where = "oauth_token = $oauth_token AND oauth_token_secret = $oauth_token_secret";

        $affected = $table->update($data, $where);
        return $oauth_verifier;
    }

    public function uniqid($length = 32) {
        return substr(sha1(microtime(true).rand(0, 9999)), rand(0, 40 - $length), $length);
    }

    public function genSignature($signature_method, $client_secret, $token) {
        switch ($signature_method) {
            case 'HMAC-SHA1':
                $key = $this->uencode($client_secret).'&'.(isset($token) ? $this->uencode($token['oauth_token_secret']) : '');
                $signature = base64_encode(hash_hmac('sha1', $this->getBaseString(), $key, true));
		break;
            default: throw new Exception('Only HMAC-SHA1 is supported');
        }
		return $signature;
    }

	public function getValidToken($oauth_token) {
	
		$table = new Zend_Db_Table('oauth_token');
		$where = " oauth_token = ".$this->_db->quote($oauth_token).
				 " AND token_type = 'access'";

		$sql   = $table->select()->from($table)->where($where);
		$r     = $table->fetchAll($sql)->toArray();	
		return sizeof($r) ? $r[0] : null;
	}

	public function getOauthUser($token) {
	
		$table = new Zend_Db_Table('oauth_token');
		$where = " oauth_token = ".$this->_db->quote($token['oauth_token']).
				 " AND oauth_token_secret = ".$this->_db->quote($token['oauth_token_secret']).
				 " AND oauth_verifier = ".$this->_db->quote($token['oauth_verifier']).
				 " AND token_type = 'access'";

		$sql   = $table->select()->from($table)->setIntegrityCheck(false)->where($where)->joinLeft(array("usuarios"), "usuarios.id = oauth_token.user");
		return $table->fetchAll($sql)->toArray();
	}

	public function deleteAuthorization($token) {
	    $where = " oauth_token = ".$this->_db->quote($token['oauth_token']).
				 " AND oauth_token_secret = ".$this->_db->quote($token['oauth_token_secret']).
				 " AND oauth_verifier = ".$this->_db->quote($token['oauth_verifier']);

        $table = new Zend_Db_Table('oauth_token');
		return $table->delete($where);

	}

	public function setValidateToken($token) {
        $where = " oauth_token = ".$this->_db->quote($token['oauth_token']).
				 " AND oauth_token_secret = ".$this->_db->quote($token['oauth_token_secret']).
				 " AND oauth_verifier = ".$this->_db->quote($token['oauth_verifier']);

        $table = new Zend_Db_Table('oauth_token');
	    $data = array('token_type' => 'access');
		return $table->update($data, $where);
	}

	public function deleteOldTokens($client_id, $user_id, $oauth_token) {
		
		$table = new Zend_Db_Table('oauth_token');
		return $table->delete("client = ".($client_id)." AND user = ".($user_id)." AND oauth_token <>". $this->_db->quote($oauth_token) );
	}

    public function getVerifiedToken($client_id, $oauth_token, $oauth_verifier) {
        /*
         * SELECT id, oauth_token, oauth_token_secret, user
         * FROM oauth_token
         * WHERE client = ".(int) $this->client['id']."
         * AND oauth_token = '".addslashes($_REQUEST['oauth_token'])."'
         * AND oauth_verifier = '".addslashes($_REQUEST['oauth_verifier'])."'
         * AND token_type = 'verified'";
         */
         $client_id      = (int) $client_id;
         $oauth_token    = $this->_db->quote($oauth_token);
         $oauth_verifier = $this->_db->quote($oauth_verifier);

         $table = new Zend_Db_Table('oauth_token');
         $sql   = $table->select()
                 ->where("client = $client_id AND
                         oauth_token = $oauth_token AND
                         oauth_verifier = $oauth_verifier AND
                         token_type = 'verified'");

         $res = $table->fetchAll($sql)->toArray();
         return sizeof($res) ? $res[0] : null;
    }

    public function uencode($str) {
        return str_replace('%7E', '~', rawurlencode($str));
    }

    public function getRequestToken($oauth_token) {
        // SELECT client, oauth_token, oauth_token_secret
        // FROM oauth_token WHERE oauth_token = '".addslashes($_REQUEST['oauth_token'])."'
        // AND token_type  = 'request'

        $oauth_token = $this->_db->quote($oauth_token);

        $table = new Zend_Db_Table('oauth_token');
        $sql   = $table->select()->where("oauth_token = $oauth_token AND token_type = 'request'");
        $res   = $table->fetchAll($sql)->toArray();
        
        if(!sizeof($res)) {
            throw new Exception('Oauth_token is not valid');
        }
        return $res[0];
    }

    private function getBaseString() {
        $http_scheme = $this->getHttpScheme();
	$base_string = $_SERVER['REQUEST_METHOD'].'&'.$this->uencode($http_scheme.'://'.$_SERVER['HTTP_HOST']);
	if (($http_scheme == 'http' && $_SERVER['SERVER_PORT'] != 80) || ($http_scheme == 'https' && $_SERVER['SERVER_PORT'] != 443)) {
            $base_string .= ':'.$_SERVER['SERVER_PORT'];
	}
	$path = $_SERVER['REQUEST_URI'];
	if (($pos = strpos($path, '?')) > 0) {
            $path = substr($path, 0, $pos);
	}
	if (empty($path)) {
            $path = '/';
	}
	$base_string .= $this->uencode($path);
	$params = array_merge($_GET, $_POST);
	if (isset($params['object'])) {
		unset($params['object']);
	}
	if (isset($params['method'])) {
		unset($params['method']);
	}
	if (isset($params['oauth_signature'])) unset($params['oauth_signature']);
        
        ksort($params);
        $base_string .= '&'.$this->uencode(http_build_query($params));
        return $base_string;
    }

    private function getHttpScheme() {
	if (isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] == 'on' || $_SERVER['HTTPS'] === true)) {
            $http_scheme = 'https';
	}
	else {
            $http_scheme = 'http';
	}
	return $http_scheme;
    }

    public function checkTimestamp($oath_signature_method, $oauth_timestamp) {
	if ($oath_signature_method != 'PLAINTEXT') {
            if ($oauth_timestamp < time() - Model_Oauth::TIMESTAMP_OFFSET && $oauth_timestamp > time() + Model_Oauth::TIMESTAMP_OFFSET && $oauth_timestamp < time() - OAuth::NONCE_DURATION) {
                return false;
            }
            else {
                return true;
            }
	}
        return false;
    }

    public function checkNonce($oauth_signature_method, $oauth_nonce, $client_id) {
        if ($oauth_signature_method != 'PLAINTEXT') {
            $table = new Zend_Db_Table('oauth_nonce');
            $data  = array(
                'nonce'  => $oauth_nonce,
                'client' => (int) $client_id
            );
            try {
                $id = $table->insert($data);
                return true;
            }
            catch(Zend_Db_Statement_Exception $e)  {
                return false;
            }
        }
        return false;
    }

    public function checkVersion($oauth_version) {
        if (isset($oauth_version) && $oauth_version != '1.0') {
            return false;
	}
        return true;
    }

	public function generatefblogin($id, $client, $fb_access_token) {

		$auth = array(
			"user"   => (int)$id,
			"client" => (int)$client,
			"oauth_token" => $this->uniqid(16),
			"oauth_token_secret" => $this->uniqid(16),	
			"oauth_verifier" => $this->uniqid(16),
			"fb_access_token" => $this->_db->quote($fb_access_token),
			"token_type" => "access"
		);
		$table = new Zend_Db_Table('oauth_token');

		$table->delete("user =".(int)$id." AND client=".(int)$client);
		$table->insert($auth);

		return $auth;
	}

    public function validUser($user, $pass) {
       
        $user = $this->_db->quote($user);
        $pass = $this->_db->quote(md5($pass));

		$table = new Zend_Db_Table('usuarios');

		if(preg_match("/@/",$user)) {
        	$sql = $table->select()->where("mail = $user AND pass=$pass");
		}else {
        	$sql = $table->select()->where("user = $user AND pass=$pass");
		}

        $res = $table->fetchAll($sql)->toArray();
        return sizeof($res) ? $res[0] : null;
    }

    public function newconsumerkeyAction() {
        $fp = fopen('/dev/urandom','rb');
        $entropy = fread($fp, 32);
        fclose($fp);
        // in case /dev/urandom is reusing entropy from its pool, let's add a bit more entropy
        $entropy .= uniqid(mt_rand(), true);
        $hash = sha1($entropy);  // sha1 gives us a 40-byte hash
        // The first 30 bytes should be plenty for the consumer_key
        // We use the last 10 for the shared secret
        echo 'CK-> '.substr($hash,0,30).'<br />';
        echo 'SECRET-> '.substr($hash,30,10);
        die ();
   }
}
?>
