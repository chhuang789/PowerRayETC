-- MariaDB dump 10.19  Distrib 10.8.3-MariaDB, for osx10.17 (x86_64)
--
-- Host: localhost    Database: PowerRayETC
-- ------------------------------------------------------
-- Server version	10.8.3-MariaDB

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

--
-- Table structure for table `batch`
--

DROP TABLE IF EXISTS `batch`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `batch` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `datetime` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scan`
--

DROP TABLE IF EXISTS `scan`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `scan` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `batch_id` int(11) NOT NULL,
  `datetime` datetime NOT NULL DEFAULT current_timestamp(),
  `Model` char(5) DEFAULT '',
  `IP` char(15) DEFAULT '',
  `Worker` char(15) DEFAULT NULL,
  `MAC` char(17) DEFAULT '',
  `ServerID` char(32) DEFAULT '',
  `Status` char(10) DEFAULT '',
  `Progress1` char(7) DEFAULT '',
  `Progress2` char(7) DEFAULT '',
  `Progress3` char(7) DEFAULT '',
  `Progress4` char(7) DEFAULT '',
  `Progress5` char(7) DEFAULT '',
  `Progress6` char(7) DEFAULT '',
  `Progress7` char(7) DEFAULT '',
  `Progress8` char(7) DEFAULT '',
  `PoolHashRate` char(10) DEFAULT NULL,
  `SelfCalHashRate` char(10) DEFAULT NULL,
  `WorkingAsic` char(1) DEFAULT NULL,
  `FAN1` char(5) DEFAULT NULL,
  `FAN2` char(5) DEFAULT NULL,
  `FAN3` char(5) DEFAULT NULL,
  `FAN4` char(5) DEFAULT NULL,
  `FAN5` char(5) DEFAULT NULL,
  `PoolAddress` char(50) DEFAULT NULL,
  `WalletAddress` char(50) DEFAULT NULL,
  `Account` char(20) DEFAULT NULL,
  `Password` char(20) DEFAULT NULL,
  `MinerOPFreq` char(4) DEFAULT NULL,
  `PowerConsumption` char(5) DEFAULT NULL,
  `DHCPorFixedIP` char(7) DEFAULT NULL,
  `BoardTemp1` char(4) DEFAULT NULL,
  `BoardTemp2` char(4) DEFAULT NULL,
  `BoardTemp3` char(4) DEFAULT NULL,
  `BoardTemp4` char(4) DEFAULT NULL,
  `BoardTemp5` char(4) DEFAULT NULL,
  `BoardTemp6` char(4) DEFAULT NULL,
  `BoardTemp7` char(4) DEFAULT NULL,
  `BoardTemp8` char(4) DEFAULT NULL,
  `FailCode` char(1) DEFAULT '0',
  `FailDesc` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ServerID` (`ServerID`),
  KEY `datetime` (`datetime`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-11-02 13:55:02
