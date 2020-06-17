package dswg

import (
	"fmt"
	"strings"
	"database/sql"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type sqliteDB struct {
	conn *sqlx.DB
}

func (db *sqliteDB) AddLink(link Link) error {
	tx, err := db.conn.Beginx()
	if err != nil {
		return err
	}

	postup := strings.Join(link.PostUp, "\n")
	postdown := strings.Join(link.PostDown, "\n")

	 // last two positions are for post(up/down) commands
	const insertLinkStmt = `
		INSERT INTO links (
			name, enable, mtu, private_key,
			port, fwmark, ipv4_cidr, ipv6_cidr,
			default_dns1, default_dns2,
			forward, postup, postdown
		) VALUES (
			:name, :enable, :mtu, :private_key,
			:port, :fwmark, :ipv4_cidr, :ipv6_cidr,
			:default_dns1, :default_dns2,
			:forward, ?, ?)`
	query, args, err := sqlx.Named(insertLinkStmt, &link)
	if err != nil {
		return err
	}

	args = append(args, postup, postdown)
	_, err = tx.Exec(query, args...)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	linkID, err := getLinkID(link.Name, tx)
	if err != nil {
		return err
	}

	const insertIPStmt = `
		INSERT INTO link_allowed_ips
		(ip_cidr, link_id) VALUES (?,?)`
	for _, ip := range link.DefaultAllowedIPs {
		_, err := tx.Exec(insertIPStmt, ip, linkID)
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return rollbackErr
			}
			return err
		}
	}

	return tx.Commit()
}

func (db *sqliteDB) GetLink(name string) (*Link, error) {
	const selectStmt = `
		SELECT
			name, enable, mtu, private_key, port,
			fwmark, ipv4_cidr, ipv6_cidr, default_dns1,
			default_dns2, forward, postup, postdown
		FROM links
		WHERE name = ?`
	row := db.conn.QueryRow(selectStmt, name)
	
	var link Link
	var postup, postdown string
	err := row.Scan(
		&link.Name,
		&link.Enable,
		&link.MTU,
		&link.PrivateKey,
		&link.ListenPort,
		&link.FirewallMark,
		&link.AddressIPv4,
		&link.AddressIPv6,
		&link.DefaultDNS1,
		&link.DefaultDNS2,
		&link.Forward,
		&postup,
		&postdown,
	)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return nil, fmt.Errorf("Link \"%v\" does not exist in database", name)
		default:
			return nil, err
		}
	}

	link.PostUp = strings.Split(postup, "\n")
	link.PostDown = strings.Split(postdown, "\n")

	linkID, err := getLinkID(name, db.conn)
	if err != nil {
		return nil, err
	}

	const selectIPsStmt = `
		SELECT ip_cidr FROM link_allowed_ips
		WHERE link_id = ?`
	err = db.conn.Select(&link.DefaultAllowedIPs, selectIPsStmt, linkID)
	if err != nil {
		return nil, err
	}

	return &link, nil
}

func (db *sqliteDB) GetLinkPeers(name string) ([]Peer, error) {
	linkID, err := getLinkID(name, db.conn)
	if err != nil {
		return nil, err
	}

	var peerNames []string
	const selectPeerNamesStmt = `
		SELECT name FROM peers
		WHERE link_id = ?`
	err = db.conn.Select(&peerNames, selectPeerNamesStmt, linkID)
	if err != nil {
		return nil, err
	}

	peers := make([]Peer, len(peerNames))
	for i, peerName := range peerNames {
		peer, err := db.GetPeer(name, peerName)
		if err != nil {
			return nil, err
		}
		peers[i] = *peer
	}

	return peers, nil
}

func (db *sqliteDB) UpdateLink(name string, link Link) error {
	tx, err := db.conn.Beginx()
	if err != nil {
		return err
	}

	linkID, err := getLinkID(name, tx)
	if err != nil {
		return err
	}

	postup := strings.Join(link.PostUp, "\n")
	postdown := strings.Join(link.PostDown, "\n")

	// post(up/down) commands are handled separately
	const updateStmt = `
		UPDATE links
		SET name = :name,
			enable = :enable,
			mtu = :mtu,
			private_key = :private_key,
			port = :port,
			fwmark = :fwmark,
			ipv4_cidr = :ipv4_cidr,
			ipv6_cidr = :ipv6_cidr,
			default_dns1 = :default_dns1,
			default_dns2 = :default_dns2,
			forward = :forward,
			postup = ?,
			postdown = ?
		WHERE
			id = ?`

	query, args, err := sqlx.Named(updateStmt, &link)
	if err != nil {
		return err
	}

	args = append(args, postup, postdown, linkID)
	_, err = tx.Exec(query, args...)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	// delete old allowed ips
	const deleteIPsStmt = `
		DELETE FROM link_allowed_ips
		WHERE link_id = ?`
	_, err = tx.Exec(deleteIPsStmt, linkID)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	// insert new allowed ips
	const insertIPStmt = `
		INSERT INTO link_allowed_ips
		(ip_cidr, link_id) VALUES (?,?)`
	for _, ip := range link.DefaultAllowedIPs {
		_, err := tx.Exec(insertIPStmt, ip, linkID)
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return rollbackErr
			}
			return err
		}
	}

	return tx.Commit()
}

func (db *sqliteDB) RemoveLink(name string) error {
	tx, err := db.conn.Beginx()
	if err != nil {
		return err
	}

	linkID, err := getLinkID(name, tx)
	if err != nil {
		return err
	}

	// This should cascade the delete to all associated entities
	const deleteLinkStmt = "DELETE FROM links WHERE id = ?"
	_, err = tx.Exec(deleteLinkStmt, linkID)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	return nil
}

func (db *sqliteDB) AddPeer(linkName string, peer Peer) error {
	tx, err := db.conn.Beginx()
	if err != nil {
		return err
	}

	linkID, err := getLinkID(linkName, tx)
	if err != nil {
		return err
	}

	// Last position is for the link ID
	const insertPeerStmt = `
		INSERT INTO peers (
			name, enable, public_key,
			preshared_key, endpoint,
			keepalive, dns1, dns2, link_id
		) VALUES (
			:name, :enable, :public_key,
			:preshared_key, :endpoint,
			:keepalive, :dns1, :dns2, ?)`
	query, args, err := sqlx.Named(insertPeerStmt, &peer)
	if err != nil {
		return err
	}

	args = append(args, linkID)
	_, err = tx.Exec(query, args...)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	peerID, err := getPeerID(linkID, peer.Name, tx)
	if err != nil {
		return err
	}

	const insertIPStmt = `
		INSERT INTO peer_allowed_ips
		(ip_cidr, peer_id, link_id) VALUES (?,?,?)`
	for _, ip := range peer.AllowedIPs {
		_, err := tx.Exec(insertIPStmt, ip, peerID, linkID)
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return rollbackErr
			}
			return err
		}
	}

	return tx.Commit()
}

func (db *sqliteDB) GetPeer(linkName, peerName string) (*Peer, error) {
	linkID, err := getLinkID(linkName, db.conn)
	if err != nil {
		return nil, err
	}

	const selectPeerStmt = `
		SELECT
			name, enable, public_key,
			preshared_key, endpoint,
			keepalive, dns1, dns2
		FROM peers
		WHERE link_id = ? AND name = ?`

	var peer Peer
	err = db.conn.Get(&peer, selectPeerStmt, linkID, peerName)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return nil, fmt.Errorf("Peer \"%v\" does not exist in database", peerName)
		default:
			return nil, err
		}
	}

	peerID, err := getPeerID(linkID, peerName, db.conn)
	if err != nil {
		return nil, err
	}

	const selectIPsStmt = `
		SELECT ip_cidr FROM peer_allowed_ips
		WHERE peer_id = ?`
	err = db.conn.Select(&peer.AllowedIPs, selectIPsStmt, peerID)
	if err != nil {
		return nil, err
	}

	return &peer, nil
}

func (db *sqliteDB) UpdatePeer(linkName, peerName string, peer Peer) error {
	tx, err := db.conn.Beginx()
	if err != nil {
		return err
	}

	linkID, err := getLinkID(linkName, tx)
	if err != nil {
		return err
	}

	peerID, err := getPeerID(linkID, peerName, tx)
	if err != nil {
		return err
	}

	const updateStmt = `
		UPDATE peers
		SET name = :name,
			enable = :enable,
			public_key = :public_key,
			preshared_key = :preshared_key,
			endpoint = :endpoint,
			keepalive = :keepalive,
			dns1 = :dns1,
			dns2 = :dns2
		WHERE
			id = ?`

	query, args, err := sqlx.Named(updateStmt, &peer)
	if err != nil {
		return err
	}

	args = append(args, peerID)
	_, err = tx.Exec(query, args...)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	// Delete old allowed ips
	const deleteIPsStmt = `
		DELETE FROM peer_allowed_ips
		WHERE peer_id = ?`
	_, err = tx.Exec(deleteIPsStmt, peerID)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	// Insert new allowed ips
	const insertIPStmt = `
		INSERT INTO peer_allowed_ips
		(ip_cidr, peer_id, link_id) VALUES (?,?,?)`
	for _, ip := range peer.AllowedIPs {
		_, err := tx.Exec(insertIPStmt, ip, peerID, linkID)
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return rollbackErr
			}
			return err
		}
	}

	return tx.Commit()
}

func (db *sqliteDB) RemovePeer(linkName, peerName string) error {
	tx, err := db.conn.Beginx()
	if err != nil {
		return err
	}

	linkID, err := getLinkID(linkName, tx)
	if err != nil {
		return err
	}
	peerID, err := getPeerID(linkID, peerName, tx)
	if err != nil {
		return err
	}

	// This should cascade the delete to all associated IPs
	const deletePeerStmt = "DELETE FROM peers WHERE link_id = ? AND id = ?"
	_, err = tx.Exec(deletePeerStmt, linkID, peerID)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	return nil
}

func (db *sqliteDB) Close() error {
	return db.conn.Close()
}

func getLinkID(name string, q sqlx.Queryer) (int64, error) {
	const selectStmt = "SELECT id FROM links WHERE name = ?"

	var id int64
	err := sqlx.Get(q, &id, selectStmt, name)
	if err != nil {
		return 0, err
	}

	return id, nil
}

func getPeerID(linkID int64, peerName string, q sqlx.Queryer) (int64, error) {
	const selectStmt = "SELECT id FROM peers WHERE link_id = ? AND name = ?"

	var id int64
	err := sqlx.Get(q, &id, selectStmt, linkID, peerName)
	if err != nil {
		return 0, err
	}

	return id, nil
}

func OpenSqliteDB(dbPath string) (DB, error) {
	conn, err := buildSqliteDB(dbPath)
	if err != nil {
		return nil, err
	}
	
	db := &sqliteDB{
		conn: conn,
	}
	return db, nil
}

func buildSqliteDB(dbPath string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	stmts := strings.Split(sqliteSchema, ";")
	for _, stmt := range stmts {
		_, err := db.Exec(stmt)
		if err != nil {
			return nil, err
		}
	}
	
	return db, nil
}