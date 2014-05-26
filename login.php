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

//error_reporting(E_ALL);
//ini_set('display_errors', '1');
global $CFG, $USER, $SESSION, $DB;

require('../../config.php');
require_once($CFG->libdir.'/moodlelib.php');
require_once($CFG->libdir.'/password_compat/lib/password.php');
require_once($CFG->dirroot.'/cohort/lib.php');

if (!is_enabled_auth('moologin')) {
    redirect($CFG->wwwroot, get_string('auth_moologin_disabled', 'auth_moologin'));
}
// logon may somehow modify this
$SESSION->wantsurl = $CFG->wwwroot.'/';

// $PASSTHROUGH_KEY = "the quick brown fox humps the lazy dog"; // must match moologin wordpress plugin setting
$PASSTHROUGH_KEY = get_config('auth/moologin', 'sharedsecret');
if (!isset($PASSTHROUGH_KEY)) {
    echo "Sorry, this plugin has not yet been configured. Please contact the Moodle administrator for details.";
}

/**
 * Handler for decrypting incoming data (specially handled base-64) in which is encoded a string of key=value pairs
 */
function decrypt_string($base64, $key) {
    
    if (!$base64) { 
        return "";
    }
    
    $data = str_replace(array('-','_'),array('+','/'),$base64);
    $mod4 = strlen($data) % 4;
    
    if ($mod4) {
        $data .= substr('====', $mod4);
    }
    
    $crypttext = base64_decode($data);
    $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
    $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
    $decrypttext = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($key.$key), $crypttext, MCRYPT_MODE_ECB, $iv);
    
    return trim($decrypttext);
}

/**
 * Querystring helper, returns the value of a key in a string formatted in key=value&key=value&key=value pairs, e.g. saved querystrings
 */
function get_key_value($string, $key) {
    $list = explode( '&', $string);
    foreach ($list as $pair) {
    	$item = explode( '=', $pair);
            if (strtolower($key) == strtolower($item[0])) {
                return urldecode($item[1]); // Not for use in $_GET etc, which is already decoded, however our encoder uses http_build_query() before encrypting
            }
    }
    return "";
}

$rawdata = $_GET['data'];
$user_updated = false;

if (!empty($_GET)) {
    
    // get the data that was passed in
    $userdata = decrypt_string($rawdata, $PASSTHROUGH_KEY);

    // time (in minutes) before incoming link is considered invalid
    $timeout = (integer) get_config('auth/moologin', 'timeout');
    
    if ($timeout == 0) { 
        $timeout = 5;
    }

    // check the timestamp to make sure that the request is still within a few minutes of this servers time
    // if userdata didn't decrypt, then timestamp will = 0, so following code will be bypassed anyway (e.g. bad data)
    $timestamp = (integer) get_key_value($userdata, "stamp"); // remote site should have set this to new DateTime("now").getTimestamp(); which is a unix timestamp (utc)
    $theirs = new DateTime("@$timestamp"); // @ format here: http://www.gnu.org/software/tar/manual/html_node/Seconds-since-the-Epoch.html#SEC127
    $diff = floatval(date_diff(date_create("now"), $theirs)->format("%i")); // http://www.php.net/manual/en/dateinterval.format.php

    if ($timestamp > 0 && $diff <= $timeout) { // less than N minutes passed since this link was created, so it's still ok

        $username = trim(strtolower(get_key_value($userdata, "username")));
        $hashedpassword = get_key_value($userdata, "passwordhash");
        $firstname = get_key_value($userdata, "firstname");
        $lastname = get_key_value($userdata, "lastname");
        $email = get_key_value($userdata, "email");
        $idnumber = get_key_value($userdata, "idnumber"); // the users id in the wordpress database, stored here for possible user-matching
        $cohort = get_key_value($userdata, "cohort"); // the cohort to map the user user; these can be set as enrolment options on one or more courses, if it doesn't exist then skip this step
        $courseid = get_key_value($userdata, "courseid"); //Course id
        
        //Admin username is illegal
        if ($username === 'admin') {
            // redirect to the homepage
            redirect($SESSION->wantsurl);
        }
        if (empty($lastname)) {
            $lastname = '';
        }
        
        //Too few data
        if (!$username || !$email || !$idnumber) {
            redirect($CFG->wwwroot, get_string('auth_moologin_few_data', 'auth_moologin'));
        }
        
        if (!empty($email)) {
            if (email_is_not_allowed($email)) {
                redirect($CFG->wwwroot, get_string('auth_moologin_email_prohibited', 'auth_moologin'));
            }
        }
        
        $auth = 'moologin'; // so they log in with this plugin
        $authplugin = get_auth_plugin($auth);
        
        // does this user exist (wordpress id is stored as the student id in this db, but we log on with username)
        // TODO: make the key column configurable
        // TODO: if (get_field('user', 'id', 'username', $username, 'deleted', 1, '')) ----> error since the user is now deleted
        // if ($user = get_complete_user_data('username', $username)) {}
        // $auth = empty($user->auth) ? 'manual' : $user->auth;  // use manual if auth not set
        // if ($auth=='nologin' or !is_enabled_auth($auth)) {}
        // if the user/password is ok then ensure the record is synched ()
        // does this user exist (wordpress id is stored as the student id in this db, but we log on with username)
        // TODO: make the key column configurable
        // TODO: if (get_field('user', 'id', 'username', $username, 'deleted', 1, '')) ----> error since the user is now deleted
        // if ($user = get_complete_user_data('username', $username)) {}
        // $auth = empty($user->auth) ? 'manual' : $user->auth;  // use manual if auth not set
        // if ($auth=='nologin' or !is_enabled_auth($auth)) {}
        // if the user/password is ok then ensure the record is synched ()       
        if ($DB->record_exists('user', array('username'=>$username, 'auth'=>'moologin', 'confirmed' => 1, 'deleted' => 0))) {
            
            $updateuser = get_complete_user_data('username', $username);
            $updateuser->idnumber = $idnumber;
            $updateuser->email = $email;
            $updateuser->firstname = $firstname;
            $updateuser->lastname = $lastname;
            $updateuser->policyagreed = 1;
            $updateuser->timemodified = time();
            // make sure we haven't exceeded any field limits
            $updateuser = truncate_userinfo(get_object_vars($updateuser)); //this needs array
            $user = new stdClass(); //array back to object before writing to DB
            foreach ($updateuser as $key => $value){
                $user->$key = $value;
            }
            
            if (!$DB->update_record('user', $user)) {
                //If update fails return error
                print_error('auth_moologin_db_error', 'auth_moologin');
                die();
            }
            // trigger correct update event
            events_trigger('user_updated', $DB->get_record('user', array('idnumber'=>$idnumber)));
            // ensure we have the latest data
            $user = get_complete_user_data('idnumber', $idnumber);

        } else if ($DB->record_exists('user', array('email'=>$email, 'auth'=>'manual', 'confirmed' => 1, 'deleted' => 0))) {
            // update manually created user that has the same username but doesn't yet have the right idnumber
            $updateuser = get_complete_user_data('email', $email);
            $updateuser->auth = $auth;
            $updateuser->idnumber = $idnumber;            
            $updateuser->username = $username;
            $updateuser->password = AUTH_PASSWORD_NOT_CACHED; //dont store wp passwords in moodle
            //$updateuser->email = $email;
            $updateuser->policyagreed = 1;
            $updateuser->firstname = $firstname;
            $updateuser->lastname = $lastname;
            $updateuser->timemodified = time();
            // make sure we haven't exceeded any field limits
            $updateuser = truncate_userinfo(get_object_vars($updateuser)); //this needs array
            $user = new stdClass(); //array back to object before writing to DB
            foreach ($updateuser as $key => $value){
                $user->$key = $value;
            }
            
            if (!$DB->update_record('user', $user)) {
                //If update fails return error
                print_error('auth_moologin_db_error', 'auth_moologin');
                die();
            }            
            // trigger correct update event
            events_trigger('user_updated', $DB->get_record('user', array('idnumber'=>$idnumber)));
            // ensure we have the latest data
            $user = get_complete_user_data('idnumber', $idnumber);
            
            $user_updated = true;
            
        } else { 
            // create new user
            if (!$DB->record_exists('user', array('email'=>$email, 'confirmed' => 1, 'deleted' => 0)) &&
                !$DB->record_exists('user', array('username'=>$username, 'confirmed' => 1, 'deleted' => 0)) &&
                !$DB->record_exists('user', array('idnumber'=>$idnumber, 'confirmed' => 1, 'deleted' => 0))
                ) {

                $newuser = new stdClass();

                $newuser->auth = $auth;
                $newuser->policyagreed = 1;
                $newuser->idnumber = $idnumber;
                $newuser->username = $username;
                $newuser->password = AUTH_PASSWORD_NOT_CACHED; //dont store wp passwords in moodle
                $newuser->firstname = $firstname;
                $newuser->lastname = $lastname;
                $newuser->email = $email;
                if (empty($newuser->lang) || !get_string_manager()->translation_exists($newuser->lang)) {
                    $newuser->lang = $CFG->lang;
                }
                if (!isset($newuser->city)) {
                    $newuser->city = '';
                }
                $newuser->confirmed = 1;
                $newuser->lastip = getremoteaddr();
                $newuser->timecreated = time();
                $newuser->timemodified = $newuser->timecreated;
                $newuser->mnethostid = $CFG->mnet_localhost_id;
                //make sure we haven't exceeded any field limits
                $newuser = truncate_userinfo(get_object_vars($newuser));

                $create_user = new stdClass(); //array back to object before writing to DB
                foreach ($newuser as $key => $value){
                    $create_user->$key = $value;
                }

                if (!$DB->insert_record('user', $create_user)) {
                    //If update fails return error
                    print_error('auth_moologin_db_error', 'auth_moologin');
                    die();
                }

                $user = get_complete_user_data('email', $create_user->email);
                events_trigger('user_created', $DB->get_record('user', array('id'=>$user->id)));
            } else {
                print_error('auth_moologin_user_exists', 'auth_moologin');
                die();
            }
        }

        // if we can find a cohort named what we sent in, enrol this user in that cohort by adding a record to cohort_members
        if (!empty($courseid) && empty($cohort)) {
            if ($DB->record_exists('course', array('id'=>$courseid))) {
                $course = $DB->get_record('course', array('id'=>$courseid));
                $context = context_course::instance($course->id, MUST_EXIST);
                 // add enrol instances
                if (!enrol_is_enabled('self')) {
                    print_error('auth_moologin_self_enrol_disabled', 'auth_moologin');
                    die();
                }
                if ($DB->record_exists('enrol', array('courseid' => $course->id, 'enrol' => 'self', 'name' => 'moologin'))) {
                    $self_enrol = $DB->get_record('enrol', array('courseid' => $course->id, 'enrol' => 'self', 'name' => 'moologin'));
                    if ($self_enrol->status == 0) {
                        if (!is_enrolled($context, $user)) {                            
                            if (!$instances = $DB->get_records('enrol', array('enrol' => 'self', 'courseid' => $course->id, 'status' => ENROL_INSTANCE_ENABLED, 'name' => 'moologin'), 'sortorder,id ASC')) {
                                print_error('auth_moologin_self_enrol_missing', 'auth_moologin');
                                die();
                            }
                            $instance = reset($instances);
                            $self = enrol_get_plugin('self');
                            $self->enrol_user($instance, $user->id, 5);
                            $SESSION->wantsurl = new moodle_url('/course/view.php', array('id' => $course->id));
                        } else {
                            $SESSION->wantsurl = new moodle_url('/course/view.php', array('id' => $course->id));
                        }
                    } else {
                        print_error('auth_moologin_self_enrol_disabled', 'auth_moologin');
                        die();
                    }
                } else {
                    print_error('auth_moologin_self_enrol_disabled', 'auth_moologin');
                    die();
                }
            } 
        }
        
        // if we can find a cohort named what we sent in, enrol this user in that cohort by adding a record to cohort_members
        if ($DB->record_exists('cohort', array('idnumber'=>$cohort))) {
            $cohortrow = $DB->get_record('cohort', array('idnumber'=>$cohort));
            if (!$DB->record_exists('cohort_members', array('cohortid'=>$cohortrow->id, 'userid'=>$user->id))) {
                // internally triggers cohort_member_added event
                cohort_add_member($cohortrow->id, $user->id);
            }
            // if the plugin auto-opens the course, then find the course this cohort enrols for and set it as the opener link
            if (get_config('auth/moologin', 'autoopen') == 'yes')  {
                if ($enrolrow = $DB->get_record('enrol', array('enrol'=>'cohort','customint1'=>$cohortrow->id,'status'=>0))) {
                    $SESSION->wantsurl = new moodle_url('/course/view.php', array('id'=>$enrolrow->courseid));
                }
            }
        }		

        // all that's left to do is to authenticate this user and set up their active session
        if ($authplugin->user_login($user->username, null, 'moologin')) {
            $user->loggedin = true;
            $user->site     = $CFG->wwwroot;
            complete_user_login($user);
            add_to_log(SITEID, 'user', 'login', "view.php?id=$user->id&course=".SITEID,$user->id, 0, $user->id);
        }
    }
}

if ($user_updated === true) {
    add_to_log(SITEID, 'user', 'login', "view.php?id=$user->id&course=".SITEID, 'user with '.$user->id.' has been updated by moologin', 0, $user->id);
    //Notify user about account data changed 
    $msg_vars = new stdClass();
    $msg_vars->username = $user->username;            
    redirect($SESSION->wantsurl, get_string('auth_moologin_user_updated', 'auth_moologin', $msg_vars), 10);
}

// redirect to the homepage
redirect($SESSION->wantsurl);