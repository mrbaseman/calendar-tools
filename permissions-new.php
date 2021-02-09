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

if (!file_exists(PROJECT_PATH_ROOT . 'vendor/')) {
    exit('<h1>Incomplete installation</h1><p>Ba&iuml;kal dependencies have not been installed. If you are a regular user, this means that you probably downloaded the wrong zip file.</p><p>To install the dependencies manually, execute "<strong>composer install</strong>" in the Ba&iuml;kal root folder.</p>');
}

require PROJECT_PATH_ROOT . 'vendor/autoload.php';

# Bootstraping Flake
\Flake\Framework::bootstrap();

# Bootstrap BaikalAdmin
\BaikalAdmin\Framework::bootstrap();


if (!\BaikalAdmin\Core\Auth::isAuthenticated()) {
    exit('<h1>Permission denied. Please log in to Ba&iuml;kal first.</p>');
} 

$db =  $GLOBALS["DB"];


# build list of known users

$query='SELECT `username` FROM `users`'; 
$users=array();
$group_ids=array();

$get_content = $db->query($query);
while( $fetch_content = $get_content->fetch() ){
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
   $fetch_content = $get_content->fetch();
   if(!$fetch_content){
      $query_insert='INSERT INTO '
                   .'`principals` (`uri`)'
                   .' VALUES ("principals/'.$user.'/calendar-proxy-read")';
      if( !($db->query($query_insert))){
          echo "error adding read-access for $user<br/>\n";
      } else {
         $get_content = $db->query($query);
         $fetch_content = $get_content->fetch();

     }
   }
   $group_ids['principals/'.$user.'/calendar-proxy-read'] = $fetch_content["id"];

   # writable shares   
   $query='SELECT `id` '
         .'FROM `principals` '
         .'WHERE `uri` = "principals/'.$user.'/calendar-proxy-write"';
   $get_content = $db->query($query);
   $fetch_content = $get_content->fetch();
   if(!$fetch_content){
      $query_insert='INSERT INTO '
                   .'`principals` (`uri`) '
                   .'VALUES ("principals/'.$user.'/calendar-proxy-write")';
      if( !($db->query($query_insert))) {
          echo "error adding read-access for $user<br/>\n";
      } else {
         $get_content = $db->query($query);
         $fetch_content = $get_content->fetch();
     }
   }
   $group_ids['principals/'.$user.'/calendar-proxy-write'] = $fetch_content["id"];

   # group ids of the users themselves
   $query='SELECT `id` '
         .'FROM `principals` '
         .'WHERE `uri` = "principals/'.$user.'"';
   $get_content = $db->query($query);
   $fetch_content = $get_content->fetch();
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
   while(    $fetch_content = $get_content->fetch() ) {
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
   while(    $fetch_content = $get_content->fetch() ) {
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
$hashval.= session_id();
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
    while(    $fetch_content = $get_content->fetch() ) {
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
    while(    $fetch_content = $get_content->fetch() ){
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
  $hashval.= session_id();
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

echo "</form></body></html>\n";
# and that's it.
?>

