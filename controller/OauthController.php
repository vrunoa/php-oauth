<?php

class OauthController extends Zend_Controller_Action
{

    private $model;

    public function init()
    {
        $this->model = new Model_Oauth();             
    }  

    public function requesttokenAction() {

        $params = array(
            'oauth_consumer_key'     => $this->_request->getParam('oauth_consumer_key'),
            'oauth_nonce'            => $this->_request->getParam('oauth_nonce'),
            'oauth_version'          => $this->_request->getParam('oauth_version'),
            'oauth_timestamp'        => $this->_request->getParam('oauth_timestamp'),
            'oauth_signature_method' => $this->_request->getParam('oauth_signature_method'),
            'oauth_signature'        => $this->_request->getParam('oauth_signature'),
            'oauth_verifier'         => $this->_request->getParam('oauth_verifier')
        );

        try {
            // checks oauth_client
            $client = $this->model->getClient(
                $params['oauth_consumer_key']
            );
            if($client === null) {
                throw new Exception('oauth_consumer_key is not valid');
            }
            // checks signature
            $signature = $this->model->genSignature(
                $params['oauth_signature_method'],
                $client['client_secret'],
                null
            );
            if($params['oauth_signature'] !== $signature) {
                throw new Exception('oauth_signature is not valid');
            }
            // checks timestamp
            if(!$this->model->checkTimestamp($params['oauth_signature_method'], $params['oauth_timestamp'])) {
                throw new Exception('oauth_timestamp is not valid');
            }
            // checks nonce
            if(!$this->model->checkNonce($params['oauth_signature_method'], $params['oauth_nonce'], $client['id'])) {
                throw new Exception('Used nonce');
            }
            // checks Version
            if(!$this->model->checkVersion($params['oauth_version'])) {
              throw new Exception('oauth_version is not supported');
            }
        }
        catch(Exception $e) {
            die(json_encode(array(
                'error' => 'unauthorized',
                'msg' => $e->getMessage()
            )));
        };        

        $response = $this->model->requestToken($client['id']);
        if($response instanceof Zend_Db_Table_Exception) {
            die(json_encode(array(
                'error' => 'unauthorized',
                'msg' => $response->getMessage()
            )));
        }
        die(json_encode($response));
    }

    public function loginAction()
    {
		try {
			
			$plt = $this->_request->getParam('plt');
			
			switch($plt){
				case 'iphone':
					$css = '/resources/css/jquery.mobile-1.0b3.min.iphone.css';
					break;
				default:
				    $css = '/resources/css/jquery.mobile-1.0b3.min.css';	
			}

			$this->_helper->getHelper('Layout')->disableLayout();
	        $this->view->oauth_token    = $oauth_token    = $this->_request->getParam('oauth_token');
	        $this->view->oauth_callback = $oauth_callback = $this->_request->getParam('oauth_callback');
			$this->view->css = $css;
			$this->view->plt = $plt;
		
    	    if($this->_request->getParam("confirm") == "") {
				return;
    	    }

    	    $user = trim($this->_request->getParam("usuario"));
    	    $pass = trim($this->_request->getParam("pass"));
	
	        if($user == "" || $pass == "") {
	            $this->view->error = "Los campos usuario/password son obligatorios";
	            return;
	        }
	        $user = $this->model->validUser($user, $pass);
	        if($user === null) {
	            $this->view->error = "El usuario/password son incorrectos";
	            return;
	        }

	        $session = new Zend_Session_Namespace("Zend_Auth");
	        $session->idUser = $user['id'];
	        
        	$tokens = $this->model->getRequestToken($oauth_token);
        	$client = $this->model->getClientById($tokens['client']);

        	$redirect_url = '/oauth/authorize?';
        	$redirect_url.= 'oauth_token='.$tokens['oauth_token'];
        	$redirect_url.= '&oauth_callback='.$oauth_callback;
        	$redirect_url.= '&key='.$client['key'];
        	$redirect_url.= '&plt='.$plt;
        	$redirect_url.= '&oauth_token_secret='.$tokens['oauth_token_secret'];
        	$redirect_url.= '&confirm=1';

        	$this->_redirect($redirect_url);

		}catch(Exception $e){
            $this->view->error = "El usuario/password son incorrectos";
            return;
				
		}

    }

    public function logoutAction() {

        $oauth_token        = $this->_request->getParam('oauth_token');
        $oauth_callback     = $this->_request->getParam('oauth_callback');

        $session = new Zend_Session_Namespace("Zend_Auth");
        $session->idUser = 0;

        $this->_redirect('/oauth/login?oauth_token='.$oauth_token.'&oauth_callback='.$oauth_callback);
    }

    public function authorizeAction() {

		print_r("authorize");
		$this->_helper->getHelper('Layout')->disableLayout();
        $oauth_token    = $this->_request->getParam('oauth_token');
        $oauth_callback = $this->_request->getParam('oauth_callback');
        $confirm        = $this->_request->getParam('confirm');
        $plat	        = $this->_request->getParam('plt');

        $session = new Zend_Session_Namespace("Zend_Auth");
		if(!(int)$session->idUser || !isset($confirm)) {
			var_dump($session);
			var_dump($session->idUser);
            $this->_redirect('/oauth/login?oauth_token='.$oauth_token.'&oauth_callback='.$oauth_callback.'&plt='.$plat);
        }

        $oauth_token_secret = $this->_request->getParam('oauth_token_secret');
        $client_key         = $this->_request->getParam('key');
        $user_id            = $session->idUser;

        $verifier = $this->model->authorize($oauth_token, $oauth_token_secret, $user_id);

        $redirect_url = $oauth_callback.'?';
        $redirect_url.= 'oauth_token='.$oauth_token;
        $redirect_url.= '&oauth_verifier='.$verifier;
        
        $this->_redirect($redirect_url);
    }

    public function accesstokenAction() {

        $params = array(
            'oauth_consumer_key'     => $this->_request->getParam('oauth_consumer_key'),
            'oauth_nonce'            => $this->_request->getParam('oauth_nonce'),
            'oauth_version'          => $this->_request->getParam('oauth_version'),
            'oauth_timestamp'        => $this->_request->getParam('oauth_timestamp'),
            'oauth_signature_method' => $this->_request->getParam('oauth_signature_method'),
            'oauth_signature'        => $this->_request->getParam('oauth_signature'),
            'oauth_verifier'         => $this->_request->getParam('oauth_verifier'),
            'oauth_token'            => $this->_request->getParam('oauth_token')
        );
        try {
            // checks oauth_client
            $client = $this->model->getClient(
                $params['oauth_consumer_key']
            );
            if($client === null) {
                throw new Exception('oauth_consumer_key is not valid');
            }

            $token = $this->model->getVerifiedToken(
                    $client['id'],
                    $params['oauth_token'],
                    $params['oauth_verifier']
            );
            if($token === null) {
                throw new Exception('oauth_verifier is not valid');
            }
            // checks signature
            $signature = $this->model->genSignature(
                $params['oauth_signature_method'],
                $client['client_secret'],
				$token
            );

            if($params['oauth_signature'] !== $signature) {
                throw new Exception('oauth_signature is not valid');
            }
            // checks timestamp
            if(!$this->model->checkTimestamp($params['oauth_signature_method'], $params['oauth_timestamp'])) {
                throw new Exception('oauth_timestamp is not valid');
            }
            // checks nonce
            if(!$this->model->checkNonce($params['oauth_signature_method'], $params['oauth_nonce'], $client['id'])) {
                throw new Exception('Used nonce');
            }
            // checks Version
            if(!$this->model->checkVersion($params['oauth_version'])) {
              throw new Exception('oauth_version is not supported');
            }

        } catch(Exception $e) {

            die(json_encode(array(
                'error' => 'unauthorized',
                'msg' => $e->getMessage()
            )));
        }
		$this->model->setValidateToken($token);
		$user = $this->model->getOauthUser($token);
		$user = $user[0];
		
		$this->model->deleteOldTokens($client['id'], $user['id'], $token['oauth_token']);

		unset($user['pass']);

        die(json_encode($user));
    }

    public function authcallbackAction() {
        die('Kuesty access verified! This is good!');
    }
}

