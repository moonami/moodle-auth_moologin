<?php

// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Authentication Plugin: MooLogin - Wordpress and Moodle authentication.
 *
 * @package moologin
 * @author Tõnis Tartes
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once($CFG->libdir.'/moodlelib.php');
require_once($CFG->libdir.'/authlib.php');

class XMLRPClientWordPress {
    
    var $xmlrpcurl = "";  
    var $username = "";  
    var $password = "";
    var $msharedsecret = "";
    
    // Constructor  
    public function __construct() {
        
        $this->config = get_config('auth/moologin');        
        $this->xmlrpcurl = $this->config->wpaddress.'xmlrpc.php';  
        $this->username = $this->config->wprpcuser;  
        $this->password = $this->config->wprpcpassword;  
        $this->msharedsecret = $this->config->sharedsecret;
    }  
    
    function send_request($requestname, $params) {
        $request = xmlrpc_encode_request($requestname, $params);  
        $ch = curl_init();  
        curl_setopt($ch, CURLOPT_POSTFIELDS, $request);  
        curl_setopt($ch, CURLOPT_URL, $this->xmlrpcurl);  
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);  
        curl_setopt($ch, CURLOPT_TIMEOUT, 1);  
        $results = curl_exec($ch);
        curl_close($ch);
        return $results;
    }  
    
    function validateUser($username, $password) {
        //Crypted query
        $details = http_build_query(array(
            "a", rand(1, 1500),                 // set first to randomise the encryption when this string is encoded
            "stamp" => time(),                  // unix timestamp so we can check that the link isn't expired
            "wpusername" => $this->username,    // WP username
            "wppassword" => $this->password,    // WP password
            "username" => $username,            // username to check
            "password" => $password,            // password to check
            "z" => rand(1, 1500),               // extra randomiser for when this string is encrypted (for variance)
        ));
        $params = array($this->encrypt_string($details, $this->msharedsecret));
        return $this->send_request('moologinClient.validateUser', $params);
    }
    
    function checkUser($username) {
        //Crypted query
        $details = http_build_query(array(
            "a", rand(1, 1500),                 // set first to randomise the encryption when this string is encoded
            "stamp" => time(),                  // unix timestamp so we can check that the link isn't expired
            "wpusername" => $this->username,    // WP username
            "wppassword" => $this->password,    // WP password
            "username" => $username,            // username to check
            "z" => rand(1, 1500),               // extra randomiser for when this string is encrypted (for variance)
        ));
        $params = array($this->encrypt_string($details, $this->msharedsecret));  
        return $this->send_request('moologinClient.checkUser', $params);
    }
    
    function getUserInfo($username) {
        //Crypted query
        $details = http_build_query(array(
            "a", rand(1, 1500),                 // set first to randomise the encryption when this string is encoded
            "stamp" => time(),                  // unix timestamp so we can check that the link isn't expired
            "wpusername" => $this->username,    // WP username
            "wppassword" => $this->password,    // WP password
            "username" => $username,            // username to check
            "z" => rand(1, 1500),               // extra randomiser for when this string is encrypted (for variance)
        ));
        $params = array($this->encrypt_string($details, $this->msharedsecret));
        return $this->send_request('moologinClient.userInfo', $params);
    }
    
    function parse_xml_string($string) {        
        $xml = simplexml_load_string($string);
        $value = $xml->params;        
        return $value;
    }

    /**
     * Given a string and key, return the encrypted version (hard coded to use rijndael because it's tough)
     */
    function encrypt_string($value, $key) { 
        if (!$value) {
            return "";        
        }
        $text = $value;
        $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        $crypttext = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($key.$key), $text, MCRYPT_MODE_ECB, $iv);

        // encode data so that $_GET won't urldecode it and mess up some characters
        $data = base64_encode($crypttext);
        $data = str_replace(array('+','/','='),array('-','_',''),$data);
        return trim($data);
    }
}

?>