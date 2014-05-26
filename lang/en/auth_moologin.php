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

$string['auth_moologin_wpaddress'] = 'Remote Wordpress address';
$string['auth_moologin_wpaddress_desc'] = 'Must match actual Wordpress installation path - example: http://localhost/wordpress/. Must end with a trailing /!';

$string['auth_moologin_wprpcuser'] = 'Remote Wordpress username';
$string['auth_moologin_wprpcuser_desc'] = 'Remote Wordpress admin user must be created in remote Wordpress to have access to xmlrpc information';

$string['auth_moologin_wprpcpassword'] = 'Remote Wordpress password';
$string['auth_moologin_wprpcpassword_desc'] = 'Remote Wordpress admin user password must be entered to have access to xmlrpc information.';
        
$string['auth_moologin_secretkey'] = 'Encryption key';
$string['auth_moologin_secretkey_desc'] = 'Must match Wordpress plugin setting';

$string['auth_moologindescription'] = 'Uses Wordpress user details to create user & log onto Moodle';
$string['pluginname'] = 'MooLogin';

$string['auth_moologin_timeout'] = 'Link timeout';
$string['auth_moologin_timeout_desc'] = 'Minutes before incoming link is considered invalid (allow for reading time on Wordpress page)';

$string['auth_moologin_logoffurl'] = 'Logoff Url';
$string['auth_moologin_logoffurl_desc'] = 'Url to redirect to if the user presses Logoff';

$string['auth_moologin_autoopen_desc'] = 'Automatically open the course after successful auth';
$string['auth_moologin_autoopen'] = 'Auto open course?';

$string['auth_moologin_disabled'] = 'Sorry Wordpress and Moodle integration is disabled';
$string['auth_moologin_email_prohibited'] = 'Sorry this email is prohibited';

$string['auth_moologin_db_error'] = 'Could not update existing user, please notify administrator!';
$string['auth_moologin_few_data'] = 'Need more user details, please notify administrator!';
$string['auth_moologin_user_exists'] = 'Could not create a new user because a user with identical username, email or idnumber is existing already! Avoiding data conflict..';
$string['auth_moologin_user_updated'] = 'Attention! Your Moodle account has been updated to match Wordpress credentials. Your new username is {$a->username} and your password will be the same you use to login to Wordpress. Your old data is not lost, only account login credentials have been updated.';
$string['auth_moologin_self_enrol_disabled'] = 'Self enrolment is disabled';
$string['auth_moologin_self_enrol_missing'] = 'Self enrolment from Wordpress is missing or disabled in course';

$string['auth_moologin_xmlrpc_disabled'] = 'XMLRPC or CURL not enabled';
$string['auth_moologin_hacking'] = 'Hacking, huh!?';
$string['auth_moologin_could_not_update'] = 'Could not update record... Please inform admin!';