DROP TABLE IF EXISTS db;
--
CREATE TABLE db (
       version	    INTEGER
);
--
INSERT INTO db (version) VALUES ('1');
--
CREATE TABLE IF NOT EXISTS runs (
       run 	    INTEGER PRIMARY KEY AUTOINCREMENT,
       epoch	    TEXT
);
--
CREATE TABLE IF NOT EXISTS route_summary (
       run   	    INTEGER,
       hostname     TEXT,
       afi          TEXT,
       connected    INTEGER,
       static	    INTEGER,
       local	    INTEGER,
       isis	    INTEGER,
       bgp	    INTEGER,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);
--
CREATE TABLE IF NOT EXISTS isis_neighbour (
       run   	    INTEGER,
       hostname     TEXT,
       neighbour    TEXT,
       interface    TEXT,
       state	    TEXT,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
--
CREATE TABLE IF NOT EXISTS isis_topology (
       run   	    INTEGER,
       hostname     TEXT,
       host    	    TEXT,
       metric	    INTEGER,
       interface    TEXT,
       afi	    TEXT,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
--
CREATE TABLE IF NOT EXISTS bgp (
       run   	    INTEGER,
       hostname     TEXT,
       peer         TEXT,
       asn          INTEGER,
       afi          TEXT,  
       vrf	    TEXT,
       prefixes	    INTEGER,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
--
CREATE TABLE IF NOT EXISTS interface (
       run   	    INTEGER,
       hostname     TEXT,
       descr	    TEXT,
       mtu	    INTEGER,
       adminstatus  TEXT,
       operstatus   TEXT,
       ipv4status   TEXT,
       ipv6status   TEXT,
       speed	    INTEGER,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
--
CREATE TABLE IF NOT EXISTS pwe3 (
       run   	    INTEGER,
       hostname     TEXT,
       interface    TEXT,
       status	    TEXT,
       peer	    TEXT,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
--
CREATE TABLE IF NOT EXISTS vrf (
       run   	    INTEGER,
       hostname     TEXT,
       vrf	    TEXT,
       active	    INTEGER,
       associated   INTEGER,
       FOREIGN KEY(run) REFERENCES runs(run) ON DELETE CASCADE
);   
