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
		return err
	}

	linkID, err := getLinkID(link.Name, tx)
	if err != nil {
		return nil
	}

	const insertIPStmt = `
		INSERT INTO link_allowed_ips
		(ip_cidr, link_id) VALUES (?,?)`
	for _, ip := range link.DefaultAllowedIPs {
		_, err := tx.Exec(insertIPStmt, ip, linkID)
		if err != nil {
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
	var allowedIPs []string
	err = db.conn.Select(&allowedIPs, selectIPsStmt, linkID)
	if err != nil {
		return nil, err
	}

	link.DefaultAllowedIPs = make([]IPNet, len(allowedIPs))
	for i := range allowedIPs {
		ip, err := ParseIPNet(allowedIPs[i])
		if err != nil {
			return nil, err
		}
		link.DefaultAllowedIPs[i] = *ip
	}

	return &link, nil
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
		return err
	}

	// delete old allowed ips
	const deleteIPsStmt = `
		DELETE FROM link_allowed_ips
		WHERE link_id = ?`
	_, err = tx.Exec(deleteIPsStmt, linkID)
	if err != nil {
		return err
	}

	// insert new allowed ips
	const insertIPStmt = `
		INSERT INTO link_allowed_ips
		(ip_cidr, link_id) VALUES (?,?)`
	for _, ip := range link.DefaultAllowedIPs {
		_, err := tx.Exec(insertIPStmt, ip, linkID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *sqliteDB) RemoveLink(name string) error {
	// This should cascade the delete to all associated entities
	const deleteLinkStmt = "DELETE FROM links WHERE name = ?"
	_, err := db.conn.Exec(deleteLinkStmt, name)
	switch err {
	case sql.ErrNoRows:
		return fmt.Errorf("Link \"%v\" does not exist in database", name)
	default:
		return err
	}
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