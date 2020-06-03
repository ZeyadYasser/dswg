package dswg


const sqliteSchema = `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS [configs]
(
 [id]           INTEGER NOT NULL ,
 [name]         VARCHAR NOT NULL ,
 [enable]       INTEGER NOT NULL ,
 [forward_ipv4] INTEGER NOT NULL,
 [forward_ipv6] INTEGER NOT NULL,
 [nat_enable]   INTEGER NOT NULL,
 [nat_link]     VARCHAR NULL,


 PRIMARY KEY([id])
);

CREATE TABLE IF NOT EXISTS [links]
(
 [id]			INTEGER NOT NULL ,
 [name]         VARCHAR NOT NULL ,
 [enable]       INTEGER NOT NULL ,
 [mtu]          INTEGER NOT NULL ,
 [private_key]  VARCHAR NOT NULL ,
 [port]         INTEGER NOT NULL ,
 [fwmark]       INTEGER NOT NULL ,
 [ipv4_cidr]    VARCHAR NULL ,
 [ipv6_cidr]    VARCHAR NULL ,
 [default_dns1] VARCHAR NULL ,
 [default_dns2] VARCHAR NULL ,
 [postup]		VARCHAR NOT NULL ,
 [postdown]		VARCHAR NOT NULL ,
 [forward]      INTEGER NOT NULL,

 
 PRIMARY KEY([id]) ,
 UNIQUE(name)
);

CREATE TABLE IF NOT EXISTS [link_allowed_ips]
(
 [ip_cidr]  	VARCHAR NOT NULL ,
 [link_id]  	INTEGER NOT NULL ,


 PRIMARY KEY([ip_cidr] ,[link_id]) ,
 FOREIGN KEY([link_id]) REFERENCES [links]([id]) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS [peers]
(
 [id]				INTEGER NOT NULL ,
 [link_id]       	INTEGER NOT NULL ,
 [name]             VARCHAR NOT NULL ,
 [enable]           INTEGER NOT NULL ,
 [public_key]       VARCHAR NOT NULL ,
 [preshared_key]    VARCHAR NULL ,
 [endpoint]         VARCHAR NOT NULL ,
 [keepalive]        INTEGER NOT NULL ,
 [dns1]             VARCHAR NULL ,
 [dns2]             VARCHAR NULL ,


 PRIMARY KEY([id]) ,
 FOREIGN KEY([link_id]) REFERENCES [links]([id]) ON DELETE CASCADE,
 UNIQUE([name], [link_id])
);

CREATE TABLE IF NOT EXISTS [peer_allowed_ips]
(
 [ip_cidr] 			VARCHAR NOT NULL ,
 [peer_id]      	INTEGER NOT NULL ,


 PRIMARY KEY([ip_cidr] , [peer_id]) ,
 FOREIGN KEY([peer_id]) REFERENCES [peers]([id]) ON DELETE CASCADE
);`