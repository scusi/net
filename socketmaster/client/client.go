package client

import (
	"fmt"
	"net"

	"github.com/hashicorp/yamux"
	"github.com/scusi/net/boxconn"
	"github.com/scusi/socketmaster/protocol"
)

// Listen connects to the socket master, binds a port, and accepts
// multiplexed traffic as new connections
func Listen(socketMasterAddress string, socketDefinition protocol.SocketDefinition, priv, pub [32]byte, allowedKeys ...[32]byte) (net.Listener, error) {
	// connect to the socket master
	conn, err := boxconn.Dial("tcp", socketMasterAddress, priv, pub, allowedKeys)
	if err != nil {
		return nil, err
	}

	// bind to a port
	err = protocol.WriteHandshakeRequest(conn, protocol.HandshakeRequest{
		SocketDefinition: socketDefinition,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}

	// see if that worked
	res, err := protocol.ReadHandshakeResponse(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if res.Status != "OK" {
		conn.Close()
		return nil, fmt.Errorf("%s", res.Status)
	}

	// start a new session
	session, err := yamux.Server(conn, yamux.DefaultConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}

	return session, nil
}
