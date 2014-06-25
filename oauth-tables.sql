# ************************************************************
# Sequel Pro SQL dump
# Version 4096
#
# http://www.sequelpro.com/
# http://code.google.com/p/sequel-pro/
#
# Host: 190.228.29.67 (MySQL 5.5.24-log)
# Database: kuestydv
# Generation Time: 2014-06-25 12:45:53 +0000
# ************************************************************


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


# Dump of table oauth_client
# ------------------------------------------------------------

DROP TABLE IF EXISTS `oauth_client`;

CREATE TABLE `oauth_client` (
  `id` mediumint(9) NOT NULL AUTO_INCREMENT,
  `name` varchar(32) NOT NULL,
  `description` varchar(255) NOT NULL,
  `oraganization` varchar(64) NOT NULL,
  `url` varchar(64) NOT NULL,
  `version` varchar(16) NOT NULL,
  `versian` varchar(16) NOT NULL,
  `type` enum('standalone','web') NOT NULL,
  `callback` varchar(128) NOT NULL,
  `access` enum('read-write','read-only') NOT NULL,
  `client_key` varchar(30) NOT NULL,
  `client_secret` varchar(10) NOT NULL,
  `status` enum('pending','active','inactive') NOT NULL,
  PRIMARY KEY (`id`),
  KEY `key` (`client_key`,`status`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;



# Dump of table oauth_nonce
# ------------------------------------------------------------

DROP TABLE IF EXISTS `oauth_nonce`;

CREATE TABLE `oauth_nonce` (
  `nonce` varchar(16) NOT NULL,
  `client` mediumint(9) NOT NULL,
  `ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `uniq` (`nonce`,`client`),
  KEY `ts` (`ts`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;



# Dump of table oauth_token
# ------------------------------------------------------------

DROP TABLE IF EXISTS `oauth_token`;

CREATE TABLE `oauth_token` (
  `id` mediumint(9) NOT NULL AUTO_INCREMENT,
  `client` mediumint(9) NOT NULL,
  `user` mediumint(9) NOT NULL,
  `oauth_token` varchar(16) NOT NULL,
  `oauth_token_secret` varchar(16) NOT NULL,
  `oauth_verifier` varchar(16) NOT NULL,
  `token_type` enum('request','verified','access') NOT NULL,
  `fecha` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `fb_access_token` varchar(254) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `client` (`client`,`oauth_token`,`oauth_verifier`,`token_type`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;




/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
