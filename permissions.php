<?php

/*
    This program is a php script to manage access rights between 
    different accounts of a Baikal server below version 2.

    This program is Copyright 2015 by Martin Hecht mrbaseman@gmx.de

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see http://www.gnu.org/licenses/.
*/

/*
  to use this script, just put it into the admin folder of your Baikal
  installation and call it from your web browser. It will prompt for
  the admin password and present you a table where you can set up the
  access rights for each user to another users calendars. There are
  three settings: NONE (which is the default), readonly access, and
  read-write access
*/

# Set up environment so that the include of the Baikal configuration works.
# Most of this can be dropped, once the script is included into the Flake
# framework. For the moment we just put here what we need for running.

ini_set("session.cookie_httponly", 1);
ini_set("display_errors", 0);
ini_set("log_errors", 1);
error_reporting(E_ALL);

session_start();

define("BAIKAL_CONTEXT", TRUE);
define("BAIKAL_CONTEXT_ADMIN", TRUE);
define("PROJECT_CONTEXT_BASEURI", "/admin/");

if(file_exists(dirname(getcwd()). "/Core")) {
	# Flat FTP mode
	define("PROJECT_PATH_ROOT", dirname(getcwd()) . "/");	#../
} else {
	# Dedicated server mode
	define("PROJECT_PATH_ROOT", dirname(dirname(getcwd())) . "/");	#../../
}

define("PROJECT_PATH_CORE", PROJECT_PATH_ROOT . "Core/");
define("PROJECT_PATH_CORERESOURCES", PROJECT_PATH_CORE . "Resources/");
define("PROJECT_PATH_SPECIFIC", PROJECT_PATH_ROOT . "Specific/");
define("PROJECT_PATH_FRAMEWORKS", PROJECT_PATH_CORE . "Frameworks/");
define("PROJECT_PATH_WWWROOT", PROJECT_PATH_CORE . "WWWRoot/");

$sScript = substr($_SERVER["SCRIPT_FILENAME"], strlen($_SERVER["DOCUMENT_ROOT"]));
$sDirName = str_replace("\\", "/", dirname($sScript));  
if($sDirName !== ".") {
   if(substr($sDirName, -1) !== "/") {
      $sDirName .= "/";
   }
} else {
   $sDirName = "/";
}

$sBaseUrl=substr($sDirName, 0, -1 * strlen(PROJECT_CONTEXT_BASEURI));
if(substr($sBaseUrl, -1) !== "/") {
   $sBaseUrl .= "/";
}

if(substr($sBaseUrl, 0, 1) !== "/") {
   $sBaseUrl = "/" . $sBaseUrl;
}
define("PROJECT_BASEURI", $sBaseUrl);

# ok, now we have everything and can include the config

require(PROJECT_PATH_ROOT . 'Specific/config.php');
require(PROJECT_PATH_ROOT . 'Specific/config.system.php');

# make sure the user is authenticated as admin, if not authenticate

if(!(isset($_SESSION["baikaladminauth"]) && $_SESSION["baikaladminauth"] === md5(BAIKAL_ADMIN_PASSWORDHASH))) {
    # There is no authentication from baikal, so we have to try to do authentication,
    # see php.net/manual/features.http-auth.php
    if (defined("BAIKAL_DAV_AUTH_TYPE") && ( BAIKAL_DAV_AUTH_TYPE === "Basic")) {
       # Basic authentication
       if (!isset($_SERVER['PHP_AUTH_USER'])) {
	   header('WWW-Authenticate: Basic realm="' . BAIKAL_AUTH_REALM . '"');
	   header('HTTP/1.0 401 Unauthorized');
	   die ("You are not allowed to see this page. Please authenticate.");
       } 

       $sPassHash =  md5('admin:' . BAIKAL_AUTH_REALM . ':' . $_SERVER['PHP_AUTH_PW']);

       if( ! ( $_SERVER['PHP_AUTH_USER'] === "admin" 
               && $sPassHash === BAIKAL_ADMIN_PASSWORDHASH)) {
	   die ("You must be admin to view this page. Please authenticate properly.");
       }
    } else {
        # Digest authentication

	if (empty($_SERVER['PHP_AUTH_DIGEST'])) {
	    header('HTTP/1.1 401 Unauthorized');
	    header('WWW-Authenticate: Digest realm="'.BAIKAL_AUTH_REALM.
        	   '",qop="auth",nonce="'.uniqid().'",opaque="'.md5(BAIKAL_AUTH_REALM).'"');

	    die('You are not allowed to see this page. Please authenticate.');
	}

	// next we need this function to parse the http auth header
	function http_digest_parse($txt)
	{
	    // protect against missing data
	    $needed_parts = array('nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1);
	    $data = array();
	    $keys = implode('|', array_keys($needed_parts));

	    preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $txt, $matches, PREG_SET_ORDER);

	    foreach ($matches as $m) {
        	$data[$m[1]] = $m[3] ? $m[3] : $m[4];
        	unset($needed_parts[$m[1]]);
	    }

	    return $needed_parts ? false : $data;
	}	

	// now use it to analyze the PHP_AUTH_DIGEST variable
	if (!($data = http_digest_parse($_SERVER['PHP_AUTH_DIGEST'])) ||
	    !($data['username'] === "admin"))
	    die("You must be admin to view this page. Please authenticate properly.");

	// generate the valid response
	$A1 = BAIKAL_ADMIN_PASSWORDHASH;
	$A2 = md5($_SERVER['REQUEST_METHOD'].':'.$data['uri']);
	$valid_response = md5($A1.':'.$data['nonce'].':'.$data['nc'].':'.$data['cnonce'].':'.$data['qop'].':'.$A2);

	if ($data['response'] != $valid_response)
	   die ("You must be admin to view this page. Please authenticate properly.");
    }
    // ok, valid username & password - we can establish the session now
    $_SESSION["baikaladminauth"] = md5(BAIKAL_ADMIN_PASSWORDHASH);
}

// now the user is authenticated and we can go on: check if the user wants to log out

if (isset($_POST['logout'])) {
    if(isset($_SESSION["baikaladminauth"])) unset($_SESSION["baikaladminauth"]);
    if(isset($_SERVER['PHP_AUTH_USER'])) unset($_SERVER['PHP_AUTH_USER']);
    if(isset($_SERVER['PHP_AUTH_PW'])) unset($_SERVER['PHP_AUTH_PW']);
    if(isset($_SERVER['PHP_AUTH_DIGEST'])) unset($_SERVER['PHP_AUTH_DIGEST']);
    session_destroy();
    // the browser might still have cached the credentials for http-auth
    // we have to send the headers to flush these
    header('HTTP/1.1 401 Unauthorized');
    // however this does not always work. Therefore, give this hint to the users:
    echo "You are logged out now. To ensure that the browser has not cached your credentials, please close all open browser windows.\n";
    exit;
}

// if not logged out now, we can connect to the database


if(PROJECT_DB_MYSQL){
  $db = new mysqli ( 
     PROJECT_DB_MYSQL_HOST,
     PROJECT_DB_MYSQL_USERNAME,
     PROJECT_DB_MYSQL_PASSWORD,
     PROJECT_DB_MYSQL_DBNAME
  );
} else {
  $db = new SQLite3(PROJECT_SQLITE_FILE); 
}


# build list of known users

$query='SELECT `username` FROM `users`'; 
$users=array();
$group_ids=array();

$get_content = $db->query($query);
while( PROJECT_DB_MYSQL 
         ? ($fetch_content = $get_content->fetch_array()) 
         : ($fetch_content = $get_content->fetchArray() )
     ){
        $user = $fetch_content['username'];
        $users[]=$user;
}

$ok_message="";

# add principals for read/write access and collect group ids
    
foreach ($users as $idx => $user){
   # readable shares 
   $query='SELECT `id` '
        .'FROM `principals` '
         .'WHERE `uri` = "principals/'.$user.'/calendar-proxy-read"';
   $get_content = $db->query($query);
   PROJECT_DB_MYSQL 
       ? $fetch_content=$get_content->fetch_array() 
       : $fetch_content=$get_content->fetchArray();
   if(!$fetch_content){
      $query_insert='INSERT INTO '
                   .'`principals` (`uri`)'
                   .' VALUES ("principals/'.$user.'/calendar-proxy-read")';
      if( !($db->query($query_insert))){
          echo "error adding read-access for $user<br/>\n";
      } else {
         $get_content = $db->query($query);
         PROJECT_DB_MYSQL 
           ? $fetch_content=$get_content->fetch_array() 
           : $fetch_content=$get_content->fetchArray();
     }
   }
   $group_ids['principals/'.$user.'/calendar-proxy-read'] = $fetch_content["id"];

   # writable shares   
   $query='SELECT `id` '
         .'FROM `principals` '
         .'WHERE `uri` = "principals/'.$user.'/calendar-proxy-write"';
   $get_content = $db->query($query);
   PROJECT_DB_MYSQL 
     ? $fetch_content=$get_content->fetch_array() 
     : $fetch_content=$get_content->fetchArray();
   if(!$fetch_content){
      $query_insert='INSERT INTO '
                   .'`principals` (`uri`) '
                   .'VALUES ("principals/'.$user.'/calendar-proxy-write")';
      if( !($db->query($query_insert))) {
          echo "error adding read-access for $user<br/>\n";
      } else {
         $get_content = $db->query($query);
         PROJECT_DB_MYSQL 
           ? $fetch_content=$get_content->fetch_array() 
           : $fetch_content=$get_content->fetchArray();
     }
   }
   $group_ids['principals/'.$user.'/calendar-proxy-write'] = $fetch_content["id"];

   # group ids of the users themselves
   $query='SELECT `id` '
         .'FROM `principals` '
         .'WHERE `uri` = "principals/'.$user.'"';
   $get_content = $db->query($query);
   PROJECT_DB_MYSQL 
     ? $fetch_content=$get_content->fetch_array() 
     : $fetch_content=$get_content->fetchArray();
   $group_ids['principals/'.$user] = $fetch_content["id"];
} # end of user loop


# now that we have the group ids, fetch assignments in groupmembers table
$group_members_read=array();
$group_members_write=array();

foreach ($users as $idx => $user){
   # get users who have read permission on other accounts
   $read_permission=$group_ids['principals/'.$user.'/calendar-proxy-read'];
   $owner_id=$group_ids['principals/'.$user];
   $query='SELECT `member_id` '
         .'FROM `groupmembers` '
         .'WHERE `principal_id` = "'.$read_permission.'"';
   $get_content = $db->query($query);
   $members=array();
   while( PROJECT_DB_MYSQL 
            ? $fetch_content=$get_content->fetch_array() 
            : $fetch_content=$get_content->fetchArray()) {
     $user_id = $fetch_content['member_id'];
     if($user_id==$owner_id){
        $query='DELETE FROM '
              .'`groupmembers` '
              .'WHERE `member_id` = "'.$owner_id.'" '
              .'AND `principal_id` = "'.$read_permission.'"';
        $db->query($query) or die("error when correcting database");
     } else {
        $members[]=$user_id;
     }
   }
   $group_members_read[$owner_id]=$members;

   # get users who have write permissions on other accounts 
   $write_permission=$group_ids['principals/'.$user.'/calendar-proxy-write'];
   $query='SELECT `member_id` '
         .'FROM `groupmembers` '
         .'WHERE `principal_id` = "'.$write_permission.'"';
   $get_content = $db->query($query);
   $members=array();
   while( PROJECT_DB_MYSQL 
            ? $fetch_content=$get_content->fetch_array() 
            : $fetch_content=$get_content->fetchArray()) {
      $user_id = $fetch_content['member_id'];
      if($user_id==$owner_id){
         $query='DELETE '
               .'FROM `groupmembers` '
               .'WHERE `member_id` = "'.$owner_id.'" '
               .'AND `principal_id` = "'.$write_permission.'"';
         $db->query($query) or die("error when correcting database");
      } else {
         $members[]=$user_id;
      }
   }
   $group_members_write[$owner_id]=$members;
}  # end of user loop

# out of the current values, the client ip and some 'salt' we create a token 
$hashval = $_SERVER['REMOTE_ADDR'];
$hashval.= var_export($group_members_read, true);
$hashval.= var_export($group_members_write, true);
$hashval.= BAIKAL_ENCRYPTION_KEY;
$hashval.=date("d.m.Y");
$hashval=md5($hashval);

# check if the database has been altered or the user has tried to tweak us... 
if(isset($_POST['submit']) AND $_POST['submit'] != ''){
   if(!isset($_POST['token']) OR ($_POST['token']) != $hashval){
      die("security violation");
   }
   # evaluate POST-entries we do not take everything that comes in but just things we expect 
   foreach ($users as $idx => $owner){
     $oid=$group_ids['principals/'.$owner];
     $read_permission=$group_ids['principals/'.$owner.'/calendar-proxy-read'];
     $write_permission=$group_ids['principals/'.$owner.'/calendar-proxy-write'];
     foreach ($users as $idx2 => $user){
       $uid=$group_ids['principals/'.$user];
       # now for each user and each owner check if permissions are ok
       # the user using the share must be different from the owner
       # and we encode the permissions as 0=none 1=read 2=write 
       if($uid!=$oid){
         $access=(int)$_POST["${oid}_$uid"];
         # no access
         if($access==0){
            if(in_array($uid,$group_members_read[$oid])){
               $query='DELETE '
                     .'FROM `groupmembers` '
                     .'WHERE `principal_id` = "'.$read_permission.'" '
                     .'AND `member_id` = "'.$uid.'"';
              $db->query($query) or die("error setting permissions");
            }
            if(in_array($uid,$group_members_write[$oid])){
               $query='DELETE '
                     .'FROM `groupmembers` '
                     .'WHERE `principal_id` = "'.$write_permission.'" '
                     .'AND `member_id` = "'.$uid.'"';
               $db->query($query) or die("error setting permissions");
            }
         }  # end of none
         # read access
         if($access==1){
            if(!in_array($uid,$group_members_read[$oid])){
               $query='INSERT '
                     .'INTO `groupmembers` '
                     .'(`principal_id`, `member_id`) '
                     .'VALUES ("'.$read_permission.'", "'.$uid.'")';
               $db->query($query) or die("error setting permissions");
            }
            if(in_array($uid,$group_members_write[$oid])){
               $query='DELETE '
                     .'FROM `groupmembers` '
                     .'WHERE `principal_id` = "'.$write_permission.'" '
                     .'AND `member_id` = "'.$uid.'"';
               $db->query($query) or die("error setting permissions");
            }
         }  # end of read access
         # write access
         if($access==2){
            if(in_array($uid,$group_members_read[$oid])){
               $query='DELETE '
                     .'FROM `groupmembers` '
                     .'WHERE `principal_id` = "'.$read_permission.'" '
                     .'AND `member_id` = "'.$uid.'"';
               $db->query($query) or die("error setting permissions");
            }
            if(!in_array($uid,$group_members_write[$oid])){
               $query='INSERT '
                     .'INTO `groupmembers` '
                     .'(`principal_id`, `member_id`) '
                     .'VALUES ("'.$write_permission.'", "'.$uid.'")';
               $db->query($query) or die("error setting permissions");
            }
         }  # end of write access
       }   # end of user != owner
     }   # end of user loop
   }  # end of owner loop

  # we have to update the arrays and the hash because the next call 
  # of the script will see the changes we have just sent to the db 
  $group_members_read=array();
  $group_members_write=array();

  foreach ($users as $idx => $user){
    # read permissions first
    $read_permission=$group_ids['principals/'.$user.'/calendar-proxy-read'];
    $owner_id=$group_ids['principals/'.$user];
    $query='SELECT `member_id` '
          .'FROM `groupmembers` '
          .'WHERE `principal_id` = "'.$read_permission.'"';
    $get_content = $db->query($query);
    $members=array();
    while( PROJECT_DB_MYSQL 
             ? $fetch_content=$get_content->fetch_array() 
             : $fetch_content=$get_content->fetchArray()) {
      $user_id = $fetch_content['member_id'];
      if($user_id!==$owner_id){
         $members[]=$user_id;
      }
    }
    $group_members_read[$owner_id]=$members;

    # now write permissions
    $write_permission=$group_ids['principals/'.$user.'/calendar-proxy-write'];
    $query='SELECT `member_id` '
          .'FROM `groupmembers` '
          .'WHERE `principal_id` = "'.$write_permission.'"';
    $get_content = $db->query($query);
    $members=array();
    while( PROJECT_DB_MYSQL 
             ? $fetch_content=$get_content->fetch_array() 
             : $fetch_content=$get_content->fetchArray()){
      $user_id = $fetch_content['member_id'];
      if($user_id!=$owner_id){
         $members[]=$user_id;
      }
    }
    $group_members_write[$owner_id]=$members;
  }  # end of user loop
  # update the hash token 
  $hashval = $_SERVER['REMOTE_ADDR'];
  $hashval.= var_export($group_members_read, true);
  $hashval.= var_export($group_members_write, true);
  $hashval.= BAIKAL_ENCRYPTION_KEY;
  $hashval.=date("d.m.Y");
  $hashval=md5($hashval);

  $ok_message="<h3>Your settings have been stored to the database</h3>";

} # end of the processing of the POST values

# print out the form now

echo "<html>
<head></head><body>
  <h1>Manage permissions</h1> $ok_message
  <p>Select the access rights in the following matrix.<br />
  For the calendars owned by each user (displayed in separate sections) 
  you can grant rights to the other users (each permission is a line of the table). <br />
  Note that you first have to create the users in Baikal, so that they appear here.<br />
  It is not supported to grant access rights based on individual calendars, only on the basis of users.</p>
<form method=\"post\" name=\"permissions\" action=\"#\">\n";

# loop over users again and print out tables 
# and radio-buttons for granting access to this owner's calendars
foreach ($users as $idx => $owner){
   echo "<h3>Calendars owned by $owner</h3>
   <table padding=\"1\" border=\"1\" >
   <tr><td>Grant access to</td>
       <td>write</td>
       <td>read</td>
       <td>NONE</td></tr>"; 
   $oid=$group_ids['principals/'.$owner];
   # loop over other users who have access (or not) to the calendars of this owner
   foreach ($users as $idx2 => $user){ 
     $uid=$group_ids['principals/'.$user];
     if($uid!=$oid){
        $access=0;
        if (in_array($uid,$group_members_read[$oid]))$access=1;
        if (in_array($uid,$group_members_write[$oid]))$access=2;

        echo "<tr><td>$user</td>\n";

        # 2=write access
        echo "<td><input type=\"radio\" name=\"${oid}_$uid\" value=\"2\"";
        if($access==2) echo " checked";
        echo " /></td>\n";

        # 1=read access
        echo "<td><input type=\"radio\" name=\"${oid}_$uid\" value=\"1\"";
        if($access==1) echo " checked";
        echo " /></td>\n";

        # 0=no access
        echo "<td><input type=\"radio\" name=\"${oid}_$uid\" value=\"0\"";
        if($access==0) echo " checked";
        echo " /></td></tr>\n\n";
     }  # end of if uid!=oid
   }  # end of loop over users for granting access
   echo "</table>\n\n";
}  # end of loop over owners of the calendars

# finally the hidden field and the submit button
echo "<p></p><input type=\"hidden\" name=\"token\" value=\"$hashval\" />\n";
echo "<input type=\"submit\" name=\"submit\" value=\"submit\" />\n";
echo "<input type=\"submit\" name=\"logout\" value=\"logout\" />\n";

echo "</form></body></html>\n"
# and that's it.
?>

