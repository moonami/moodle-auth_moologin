This is the Moodle-end of a two-part plugin that allows WP users to login to Moodle.

Data is encrypted at the Wordpress end and handed over a standard http GET request. 
Only the minimum required information is sent in order to create a Moodle user record. 
The user is automatically created if not present at the Moodle end, and then authenticated, and (optionally) enrolled in a Cohort.
When WP user logs directly to Moodle then user is authenticated through XML-RPC request in WP, on success the user will be logged in to Moodle site.

How to install this plugin
---------------------
Note, this plugin must exist in a folder named "moologin" - rename the zip file or folder before you upload it.

1. Upload/extract this to your moodle/auth folder (should be called "/~/auth/moologin/", where ~ is your Moodle root)
2. Activate the plugin in the administration / authentication section
3. Click settings and enter the same shared secret that you enter for the moologin settings in Wordpress
4. You will have to create a Administrator user in WP to allow XML-RPC to fetch user details from Wordpress. Enter the WP admin username and password in Moodle.
4. The logoff url will perform a Moodle logout, then redirect to this url. Typically this is your wordpress homepage.
5. The link timeout is the number of minutes before the incoming link is thought to be invalid (to allow for variances in server times).

Usage:
------
This plugin uses XML-RPC to authenticate WP user in Moodle.
XML-RPC must be enabled!

Thanks:
-------
Big thanks go to Tim St.Clair for creating initial plugin - https://github.com/frumbert

Licence:
--------
GPL2, as per Moodle.
