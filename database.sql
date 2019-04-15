CREATE TABLE `banned` (
  `BannedID` int(11) NOT NULL AUTO_INCREMENT,
  `IP` varchar(50) NOT NULL,
  PRIMARY KEY (`BannedID`),
  KEY `index_banned_IP` (`IP`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;



CREATE PROCEDURE `sp_get_new_banned`(_LastBannedID INT(11))
BEGIN
	-- Given the BannedID of the last hacker banned, return the new rows to be added to the list of banned hackers.    
    SELECT BannedID,IP
    FROM banned
    WHERE BannedID > _LastBannedID
    ORDER BY BannedID;
END