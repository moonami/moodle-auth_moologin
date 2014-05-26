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
require_once($CFG->dirroot.'/user/lib.php');
require_once('wp-xmlrpc.php');

/**
 * Plugin for no authentication.
 */
class auth_plugin_moologin extends auth_plugin_base {

    /**
     * Constructor.
     */
    function auth_plugin_moologin() {
        $this->authtype = 'moologin';
        $this->config = get_config('auth/moologin');
    }

    /**
     * Returns true if the username and password work or don't exist and false
     * if the user exists and the password is wrong.
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    function user_login ($username, $password = null, $fromwp = null) {
        global $CFG, $DB;

        if (!extension_loaded('xmlrpc') && !function_exists('curl_version')) {
            print_error('auth_moologin_xmlrpc_disabled', 'auth_moologin');
            return false;
        }
        
        if ($fromwp === null && (!$username or !$password)) {    // Don't allow blank usernames or passwords
            return false;
        }

        if ($user = $DB->get_record('user', array('username'=>$username, 'mnethostid'=>$CFG->mnet_localhost_id, 'auth' => 'moologin', 'confirmed' => 1, 'deleted' => 0))) {
            if ($fromwp === 'moologin' && $password === null) {
                $objXMLRPClientWordPress = new XMLRPClientWordPress();
                $xml_result = $objXMLRPClientWordPress->checkUser($username);
                $result = $objXMLRPClientWordPress->parse_xml_string($xml_result);
                return ((string)$result->param->value->boolean === '1' ? true : false);
            } else if ($fromwp === null && isset($password)) {
                $objXMLRPClientWordPress = new XMLRPClientWordPress();
                $xml_result = $objXMLRPClientWordPress->validateUser($username, $password);
                $result = $objXMLRPClientWordPress->parse_xml_string($xml_result);
                return ((string)$result->param->value->boolean === '1' ? true : false);
            } else {
                print_error('auth_moologin_hacking', 'auth_moologin');
                return false;
            }
        } else {
            $objXMLRPClientWordPress = new XMLRPClientWordPress();
            $xml_result = $objXMLRPClientWordPress->validateUser($username, $password);
            $result = $objXMLRPClientWordPress->parse_xml_string($xml_result);
            return ((string)$result->param->value->boolean === '1' ? true : false);
        }
    }
    
    /*
     * After authentication hook
     */
    function user_authenticated_hook(&$user, $username, $password) {  
        global $DB;

        if ($user->auth === 'moologin') {
            if (!$user->firstname || !$user->lastname || !$user->email) {
                $objXMLRPClientWordPress = new XMLRPClientWordPress();
                $xml_result = $objXMLRPClientWordPress->getUserInfo($username);        
                $result = $objXMLRPClientWordPress->parse_xml_string($xml_result);
                $min_result = $result->param->value->array->data;

                //Update neccessary fields if needed
                $user->idnumber = (!$user->idnumber ? (int)$min_result->value[0]->int : $user->idnumber);
                $user->firstname = (!$user->firstname ? (string)$min_result->value[1]->string : $user->firstname);
                $user->lastname = (!$user->lastname ? (string)$min_result->value[2]->string : $user->lastname);
                $user->email = (!$user->email ? (string)$min_result->value[3]->string : $user->email);
                $user->timemodified = time();

                if (!$DB->update_record('user', $user)) {
                    print_error('auth_moologin_could_not_update', 'auth_moologin');
                }
            }
        } 

    }
    /**
     * Indicates if password hashes should be stored in local moodle database.
     *
     * @return bool true means flag 'not_cached' stored instead of password hash
     */
    function prevent_local_passwords() {
        return true;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return false;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return false;
    }

    /*
     * Logout hook
     */
    function logoutpage_hook() {
        //Redirect user to specified logout address
        if (isset($this->config->logoffurl)) {
            set_moodle_cookie('nobody');
            require_logout();
            redirect($this->config->logoffurl);
        }
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        include "config.html";
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {
        // set to defaults if undefined
        if (!isset($config->wpaddress)) {
            $config->wpaddress = '';
        }
        if (!isset($config->wprpcuser)) {
            $config->wprpcuser = '';
        }
        if (!isset($config->wprpcpassword)) {
            $config->wprpcpassword = '';
        }
        if (!isset($config->sharedsecret)) {
            $config->sharedsecret = 'this is not a secure key, change it';
        }
        if (!isset($config->timeout)) {
            $config->timeout = '5';
        }
        if (!isset($config->logoffurl)) {
            $config->logoffurl = '';
        }
        if (!isset($config->autoopen)) {
            $config->autoopen = 'no';
        }
        // append trailing slash automatically
        if (substr($config->wpaddress, -1) != '/') {
            $config->wpaddress = $config->wpaddress.'/';
        }
        // save settings
        set_config('wpaddress', $config->wpaddress, 'auth/moologin');
        set_config('wprpcuser', $config->wprpcuser, 'auth/moologin');
        set_config('wprpcpassword', $config->wprpcpassword, 'auth/moologin');
        set_config('sharedsecret', $config->sharedsecret, 'auth/moologin');
        set_config('logoffurl', $config->logoffurl, 'auth/moologin');
        set_config('timeout', $config->timeout, 'auth/moologin');
        set_config('autoopen', $config->autoopen, 'auth/moologin');

        return true;
    }

}

?>