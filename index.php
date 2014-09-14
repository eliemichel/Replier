<?php
session_start();

define('SCRIPTNAME', 'Replier');
define('BASE_URL', 'http://tools.exppad.com/Replier/'); // Must be absolute
define('TOKEN_TTL', 300);
define('SESSION_TTL', 3600);
define('DATA_DIR', 'data');
define('TMP_DIR', DATA_DIR.'/tmp');
define('DB_FILE', DATA_DIR.'/db.sqlite');


require_once('inc/install.php');
require_once('inc/csrf.php');
require_once('inc/rain.tpl.class.php');
RainTPL::$base_url = BASE_URL;
RainTPL::$cache_dir = TMP_DIR . '/';


function make_error($title, $content) {
	return array(
		'type' => 'error',
		'title' => $title,
		'content' => $content
	);
}
function make_warning($title, $content) {
	return array(
		'type' => 'warning',
		'title' => $title,
		'content' => $content
	);
}
function make_info($title, $content) {
	return array(
		'type' => 'info',
		'title' => $title,
		'content' => $content
	);
}



/**
 * Get all entries from database
 */
function get_all_entries() {
	global $dbh;

	$query = $dbh->query('SELECT * FROM Entry ORDER BY pubDate');
	$entries = $query->fetchall(PDO::FETCH_ASSOC);

	return $entries;
}

/**
 * Get one entry by id
 */
function get_entry($id) {
	global $dbh;

	$query = $dbh->prepare('SELECT * FROM Entry WHERE id=:id');
	$query->execute(array(':id' => $id));
	$entries = $query->fetchall(PDO::FETCH_ASSOC);

	if (count($entries) == 0) return false;

	return $entries[0];
}

/**
 * RFC 4648 base64url hash
 */
function smallHash($text)
{
	$t = rtrim(base64_encode(hash('crc32',$text,true)),'=');
	return strtr($t, '+/', '-_');
}

/**
 * Delete entry from db
 */
function delete_entry($id) {
	global $dbh;

	$query = $dbh->prepare('DELETE FROM Entry WHERE id=:id');
	$query->execute(array(':id' => $id));
}

/**
 * Save entry (insert or update)
 */
function save_entry($id, $reply_to, $content) {
	global $dbh;

	$last_update = time();

	if ($id != '') {
		$entry = get_entry($id);
		$pub_date = $entry['pubDate'];
	} else {
		$id = smallHash($pub_date);
		$pub_date = time();
	}
	$dbh->beginTransaction();
	if ($id != '') {
		delete_entry($id);
	}

	$query = $dbh->prepare('INSERT INTO Entry(id, replyTo, content, pubDate, lastUpdate) VALUES(:id, :reply_to, :content, :pub_date, :last_update)');
	$query->execute(array(
		':id' => $id,
		':reply_to' => $reply_to,
		':content' => $content,
		':pub_date' => $pub_date,
		':last_update' => $last_update
	));

	$dbh->commit();

	return $id;
}


/**
 * Try and send a webmention to the commented URL
 */
function webmention($source, $target) {
	$data = file_get_contents($target);
	$status = $http_response_header[0];
	if (strpos($status, '200') === false) return false;

	$endpoint=null;
	// Get webmention endpoint. Can be rel="webmention", rel="http://webmention.org/", rel="webmention http://webmention.org/", etc.
	preg_match('!<link .*rel *= *\"(?:(?:webmention|http://webmention.org/?) *)+\" .*href *= *\"(.+?)\"!', $data, $matches);
	if (!empty($matches[1])) $endpoint=$matches[1];
	preg_match('!<link .*href *= *\"(.+?)\" .*rel *= *\"(?:(?:webmention|http://webmention.org/?) *)+\"!',$data,$matches); // The order between rel and href can be different
	if (!empty($matches[1])) $endpoint=$matches[1];

	if (!$endpoint) return false;
	
	$postdata = http_build_query(array('source' => $source, 'target' => $target));
	$options = array('http' => array('method' => 'POST', 'timeout' => 4, 'header' => 'Content-type: application/x-www-form-urlencoded', 'content' => $postdata));
	$context = stream_context_create($options);
	
	$res = file_get_contents($endpoint, false, $context);
	$status = $http_response_header[0];
	return strpos($status, '200') !== false or strpos($status, '202') !== false;
}

/**
 * Format date to be human readable
 * @param timestamp
 */
function format_date($timestamp) {
	$today = time();
	return date('Y-m-d H:i:s', $timestamp);
}

/**
 * Format date to iso format
 * @param timestamp
 */
function format_date_iso($timestamp) {
	$today = time();
	return date('Y-m-d H:i:s', $timestamp);
}

/**
 * Format content
 * @param raw content
 */
function format_content($content) {
	//$content = htmlspecialchars($content);
	$content = str_replace("\n", "<br/>\n", $content);
	return $content;
}


/**
 * Get user info by login
 */
function get_user_by_login($login) {
	global $dbh;

	if (!isset($dbh)) return false;

	$query = $dbh->prepare('SELECT * FROM User WHERE login=:login');
	$query->execute(array(':login' => $login));
	$users = $query->fetchall(PDO::FETCH_ASSOC);

	if (count($users) == 0) return false;

	return $users[0];
}

/**
 * Get user info
 */
function get_user() {
	if (!isset($_SESSION['username'])) return false;

	return get_user_by_login($_SESSION['username']);
}

/**
 * Test login session
 */
function is_logged_in() {
	return
		isset($_SESSION['username']) and
		isset($_SESSION['usertime']) and
		get_user() !== false and
		time() - (int)$_SESSION['usertime'] <= SESSION_TTL;
}

/**
 * Test login session
 */
function login($user) {
	global $tpl;

	$_SESSION['username'] = $user;
	$_SESSION['usertime'] = time();

	$tpl->assign('logged_in', true);
	$tpl->assign('user', get_user());
}


function check_login() {
	$user = get_user_by_login($_POST['login']);
	if ($user === false) return false;

	$password = sha1($user['salt'] . $_POST['password']);
	if ($password != $user['password']) return false;

	login($_POST['login']);
	return true;
}


function domain_of_url($url) {
	preg_match("#^.*?://(.*?)(/|$)#", $url, $matches);
	return $matches[1];
}


/**
 * Main
 */

// Installation of RainTPL
if (!is_raintpl_installed()) {
	$error = install_raintpl();
	if ($error) {
		?>
		An error occured:<br/>
		<strong><?=$error['title']?></strong><br/>
		<?=$error['content']?>
		<?php
		exit();
	}
}

// Initialization of RainTPL
$tpl = new RainTPL;
$tpl->assign('logged_in', false);
$tpl->assign('user', null);
$tpl->assign('dialogs', array());
function append_dialog ($dialog) {
	global $tpl;
	$tpl->var['dialogs'][] = $dialog;
}


if (!is_installed()) {
	// Installation
	if (isset($_POST['login']) and isset($_POST['password']) and isset($_POST['confirm_password'])) {
		if (empty($_POST['login']) or empty($_POST['password']) or $_POST['password'] != $_POST['confirm_password']) {
			append_dialog(make_error('Login can not be emtpy'));
			$tpl->draw('install');
			exit();
		}
		$error = install_db();
		if ($error) {
			append_dialog($error);
			$tpl->draw('install');
			exit();
		}
		append_dialog(make_info('Installation complete', ''));
		login($_POST['login']);
		$tpl->draw('index');
		exit();
	}

	// Display installation form
	$tpl->draw('install');
	exit();
}

// Inisitalize database handler
$dbh = new PDO('sqlite:' . DB_FILE);
$dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$logged_in = is_logged_in();
$tpl->assign('logged_in', $logged_in);
$tpl->assign('user', get_user());

if ($logged_in) {
	// Save new/edited comment
	if (isset($_POST['reply-to']) and isset($_POST['content']) and isset($_POST['token']) and isset($_POST['id'])) {
		$failed = false;
		if (!check_token(TOKEN_TTL, 'edit')) {
			append_dialog(make_error('Invalid token', 'You may have take too long to write your comment. Note: Limit is set to ' . TOKEN_TTL . 's. Just submit it again.'));
			$failed = true;
		}

		if (empty($_POST['content'])) {
			append_dialog(make_error('Empty comment', 'You should not want to post empty comments!'));
			$failed = true;
		}

		if ($failed) {
			$tpl->assign('token', generate_token('edit'));
			$tpl->assign('id', $_POST['id']);
			$tpl->assign('reply_to', $_POST['reply-to']);
			$tpl->assign('content', $_POST['content']);
			$tpl->draw('edit');
			exit();
		}

		$id = save_entry($_POST['id'], $_POST['reply-to'], $_POST['content']);

		if (!webmention(BASE_URL.'?'.$id, $_POST['reply-to'])) {
			append_dialog(make_warning('Webmention not supported', 'The commented URL does not support webmention so is not aware of your comment.'));
		}

		$tpl->assign('entries', array(get_entry($id)));
		$tpl->draw('index');
		exit();
	}

	// New comment
	if (isset($_GET['new'])) {
		$tpl->assign('token', generate_token('edit'));
		$tpl->assign('id', '');
		$tpl->assign('reply_to', '');
		$tpl->assign('content', '');
		$tpl->draw('edit');
		exit();
	}

	// Edit comment
	if (isset($_GET['edit'])) {
		$id = $_GET['edit'];
		$entry = get_entry($id);

		if ($entry === false) {
			append_dialog(make_error('Bad entry id', 'No entry was found with id `' . htmlspecialchars($id) . '` !'));
			$tpl->assign('entries', get_all_entries());
			$tpl->draw('index');
			exit();
		}


		$tpl->assign('token', generate_token('edit'));
		$tpl->assign('id', $id);
		$tpl->assign('reply_to', $entry['replyTo']);
		$tpl->assign('content', $entry['content']);
		$tpl->draw('edit');
		exit();
	}

	// Delete comment
	if (isset($_GET['delete'])) {
		$id = $_GET['delete'];
		$entry = get_entry($id);

		if ($entry === false) {
			append_dialog(make_error('Bad entry id', 'No entry was found with id `' . htmlspecialchars($id) . '` !'));
			$tpl->assign('entries', get_all_entries());
			$tpl->draw('index');
			exit();
		}

		if (!check_token(TOKEN_TTL, 'delete')) {
			append_dialog(make_info('Are you sure you want to delete this entry?', '<a href="?delete='.$id.'&token='.generate_token('delete').'">Yes</a> <a href="'.BASE_URL.'">No</a>'));
			$tpl->assign('entries', array($entry));
		} else {
			delete_entry($id);
			append_dialog(make_info('Entry deleted', 'Entry with id `' . htmlspecialchars($id) . '` has been deleted.'));
			$tpl->assign('entries', get_all_entries());
		}
		$tpl->draw('index');
		exit();
	}


	// Log out
	if (isset($_GET['logout'])) {
		append_dialog(make_info('Goodbye ' . $_SESSION['username'], ''));
		session_destroy();
		$tpl->assign('logged_in', false);
		$tpl->assign('entries', get_all_entries());
		$tpl->draw('index');
	}
}

// Log in check
if (isset($_POST['login']) and isset($_POST['password'])) {
	if (!check_login($_POST['login'], $_POST['password'])) {
		append_dialog(make_error('Login error', 'Incorrect login or password.'));
		
		$tpl->assign('login', $_POST['login']);
		$tpl->draw('login');
		exit();
	}

	append_dialog(make_info('Login successful', ''));
	$tpl->assign('entries', get_all_entries());
	$tpl->draw('index');
	exit();
}

// Log in form
if (isset($_GET['login'])) {
	$tpl->assign('login', '');
	$tpl->draw('login');
	exit();
}


// Log in form
if (isset($_GET['user'])) {
	$login = $_GET['user'];
	$user = get_user_by_login($login);

	if ($entry === false) {
		append_dialog(make_error('Bad user name', 'No user was found with name `' . htmlspecialchars($login) . '` !'));
		$tpl->assign('entries', get_all_entries());
		$tpl->draw('index');
		exit();
	}

	$tpl->assign('hcard', $user);
	$tpl->draw('hcard');
	exit();
}

// Show single entry
if (strlen($_SERVER['QUERY_STRING']) == 6) {
	$id = $_SERVER['QUERY_STRING'];
	$entry = get_entry($id);

	if ($entry === false) {
		append_dialog(make_error('Bad entry id', 'No entry was found with id `' . htmlspecialchars($id) . '` !'));
		$tpl->assign('entries', get_all_entries());
		$tpl->draw('index');
		exit();
	}

	$tpl->assign('entries', array($entry));
	$tpl->draw('index');
	exit();
}

// Get all entries for home page
$tpl->assign('entries', get_all_entries());
$tpl->draw('index');

