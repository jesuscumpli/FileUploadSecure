-- MariaDB dump 10.19  Distrib 10.6.7-MariaDB, for Win64 (AMD64)
--
-- Host: localhost    Database: FileUploadSecureDB
-- ------------------------------------------------------
-- Server version	10.7.3-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

CREATE DATABASE IF NOT EXISTS FileUploadSecureDB;
USE FileUploadSecureDB;

--
-- Table structure for table `files`
--

DROP TABLE IF EXISTS `files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `files` (
  `filename` varchar(200) NOT NULL,
  `upload_date` datetime DEFAULT NULL,
  `last_modified_date` datetime DEFAULT NULL,
  `last_modified_by` varchar(10) NOT NULL,
  `size` float NOT NULL,
  `hash` varchar(200) NOT NULL,
  `owner` varchar(10) NOT NULL,
  `description` text NOT NULL,
  PRIMARY KEY (`filename`),
  KEY `last_modified_by` (`last_modified_by`),
  KEY `owner` (`owner`),
  CONSTRAINT `files_ibfk_1` FOREIGN KEY (`last_modified_by`) REFERENCES `users` (`username`),
  CONSTRAINT `files_ibfk_2` FOREIGN KEY (`owner`) REFERENCES `users` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `roles`
--

DROP TABLE IF EXISTS `roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `roles` (
  `name` varchar(20) NOT NULL,
  `access` tinyint(1) NOT NULL,
  `write` tinyint(1) DEFAULT NULL,
  `remove` tinyint(1) NOT NULL DEFAULT 0,
  `read` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `username` varchar(10) NOT NULL,
  `password` varchar(200) NOT NULL,
  `role` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`username`),
  KEY `role` (`role`),
  CONSTRAINT `users_ibfk_1` FOREIGN KEY (`role`) REFERENCES `roles` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-04-28  1:57:22


INSERT INTO Roles(`name`, `access`, `write`, `remove`, `read`) VALUES('admin', 1, 1, 1, 1);
INSERT INTO Roles(`name`, `access`, `write`, `remove`, `read`) VALUES('user', 1, 1, 0, 1);
INSERT INTO Roles(`name`, `access`, `write`, `remove`, `read`) VALUES('guest', 1, 0, 0, 0);

CREATE USER 'admin'@localhost IDENTIFIED BY 'admin';
GRANT ALL PRIVILEGES ON FileUploadSecureDB.* TO 'admin'@localhost;
FLUSH PRIVILEGES;