<?php

/**
 * Test whether RainTPL dirs have been installed
 */
function is_raintpl_installed() {
	return
		file_exists(DATA_DIR) and
		file_exists(TMP_DIR);
}

/**
 * Test whether Replier has been installed
 */
function is_installed() {
	return
		is_raintpl_installed() and
		file_exists(DB_FILE);
}


/**
 * Create $dir directory
 */
function install_dir($dir) {
	if (!file_exists($dir) || !is_writable($dir)) {
		if (!is_writable($dir) || !mkdir($dir)) {
			return make_error('Permissions error', "Unable to write into `$dir` directory");
		}
	}
}

/**
 * Create and initialize sqlite database
 */
function install_db() {
	if (!in_array('pdo_sqlite', get_loaded_extensions())) {
		return make_error('Missing dependency', 'Module pdo_sqlite not found.');
	}

	$dbh = new PDO('sqlite:'.DB_FILE);

	$dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$dbh->beginTransaction();

	// Create the table to handle users
	$dbh->query('CREATE TABLE IF NOT EXISTS User(
		id INTEGER PRIMARY KEY NOT NULL,
		login TEXT UNIQUE,
		password TEXT,
		salt TEXT,
		remember_token TEXT
	)');

	// Create user
	$salt = uniqid(mt_rand(), true);
	$password = sha1($salt . $_POST['password']);
	$query = $dbh->prepare('INSERT OR IGNORE INTO User(login, password, salt) VALUES(:login, :password, :salt)');
	$query->execute(array(
		':login' => $_POST['login'],
		':password' => $password,
		':salt' => $salt
	));

	// Create table to store entries
	$dbh->query('CREATE TABLE IF NOT EXISTS Entry(
		id VARCHAR(6) PRIMARY KEY NOT NULL,
		replyTo TEXT,  -- URL of entry to which this one is an answer
		content TEXT,
		pubDate INTEGER,
		lastUpdate INTEGER
	)');

	$dbh->commit();
}


/**
 * Installation of elements required by RainTPL
 */
function install_raintpl() {
	$error = install_dir(DATA_DIR);
	if ($error) return $error;
	$error = install_dir(TMP_DIR);
	if ($error) return $error;
}

