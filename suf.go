package suf

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"gitea.com/abgr/aerr"
	"github.com/kpango/fastime"
	"golang.org/x/crypto/nacl/box"
)

type Peer struct {
	pk         [32]byte
	sk         [32]byte
	udpConn    *net.UDPConn
	lastPingID []byte
	lastPong   time.Time
	addr       *Addr
}
type Addr struct {
	router *net.UDPAddr
	b      []byte
}

func (Addr) Network() string {
	return "udp+suf"
}
func (addr *Addr) String() string {
	return addr.router.String() + "/" + hex.EncodeToString(addr.b)
}
func ParseAddr(str string) (addr *Addr, err error) {
	parts := strings.Split(str, "/")
	if len(parts) != 2 {
		err = errors.New("invalid addr")
		return
	}
	fmt.Println(parts)
	udpAddr, err := net.ResolveUDPAddr("udp", parts[0])
	if err != nil {
		return
	}
	addr = &Addr{
		router: udpAddr,
	}
	addr.b, err = hex.DecodeString(parts[1])
	return
}

const (
	ping uint8 = 0b100_00000
	pong uint8 = 0b110_00000
	send uint8 = 0b101_00000
	recv uint8 = 0b111_00000
)

type PeerOptions struct {
	PK, SK [32]byte
	Listen net.UDPAddr
	Router net.UDPAddr
	Token  []byte
	Ctx    context.Context
}

func NewOpt(routerPort uint16, routerIP ...byte) *PeerOptions {
	pk, sk, err := box.GenerateKey(rand.Reader)
	aerr.Panicerr(err, nil)
	return &PeerOptions{
		PK:     *pk,
		SK:     *sk,
		Listen: net.UDPAddr{},
		Router: net.UDPAddr{IP: routerIP, Port: int(routerPort)},
		Token:  []byte{},
		Ctx:    context.Background(),
	}
}

func (opt *PeerOptions) SetToken(token []byte) *PeerOptions {
	opt.Token = token
	return opt
}

func (opt *PeerOptions) SetContext(ctx context.Context) *PeerOptions {
	opt.Ctx = ctx
	return opt
}
func (opt *PeerOptions) SetTimeout(d time.Duration) *PeerOptions {
	opt.Ctx, _ = context.WithTimeout(opt.Ctx, d)
	return opt
}
func (opt *PeerOptions) SetKeys(pk, sk [32]byte) *PeerOptions {
	opt.PK = pk
	opt.SK = sk
	return opt
}
func (opt *PeerOptions) SetRouter(addr net.UDPAddr) *PeerOptions {
	opt.Router = addr
	return opt
}
func (opt *PeerOptions) SetListen(addr net.UDPAddr) *PeerOptions {
	opt.Listen = addr
	return opt
}
func NewPeer(opt PeerOptions) (peer *Peer, err error) {
	peer = &Peer{
		pk:         opt.PK,
		sk:         opt.SK,
		udpConn:    &net.UDPConn{},
		lastPingID: []byte{0, 0, 0, 0},
		lastPong:   time.Now(),
		addr:       &Addr{},
	}
	peer.udpConn, err = net.DialUDP("udp", &opt.Listen, &opt.Router)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			peer.udpConn.Close()
		}
	}()
	peer.addr.router = &opt.Router
	err = peer.PingAsync(opt.Token)
	if err != nil {
		return
	}
	err = peer.WaitPong(opt.Ctx)
	return
}
func (peer *Peer) Close() error {
	return peer.udpConn.Close()
}
func (peer *Peer) LocalAddr() *Addr {
	return peer.addr
}

func packSend(to, data []byte) []byte {
	buff := make([]byte, 1+len(to)+len(data))
	buff[0] = uint8(len(to)) - 1 | send
	copy(buff[1:1+len(to)], to)
	copy(buff[1+len(to):], data)
	return buff
}

func (peer *Peer) WriteTo(b []byte, addr *Addr) (int, error) {
	if addr.router == nil {
		addr.router = peer.addr.router
	}
	n, err := peer.udpConn.WriteTo(packSend(addr.b, b), addr.router)
	return n - 1 - len(addr.b), err
}
func unpackPong(pack []byte) (id []byte, peerPk []byte, sealedAddr, extra []byte) {
	id = pack[1 : 1+4]
	peerPk = pack[1+4 : 1+4+32]
	lenSealedAddr := pack[1+4+32]
	sealedAddr = pack[1+4+32+1 : 1+4+32+1+lenSealedAddr]
	extra = pack[1+4+32+1+lenSealedAddr:]
	return
}
func packPing(id []byte, myPk []byte, extra []byte) []byte {
	buff := make([]byte, 1+4+32+len(extra))
	buff[0] = ping
	copy(buff[1:1+4], id)
	copy(buff[1+4:1+4+32], myPk)
	copy(buff[1+4+32:], extra)
	return buff
}
func (peer *Peer) PingAsync(token []byte) error {
	peer.incID()
	_, err := peer.udpConn.Write(packPing(peer.lastPingID, peer.pk[:], token))
	return err
}
func (peer *Peer) incID() {
	atomic.AddUint32((*uint32)(unsafe.Pointer(&peer.lastPingID[0])), 1)
}
func (peer *Peer) ReadFrom(b []byte) (n int, addr *Addr, err error) {
	return peer.ReadFromCtx(context.Background(), b)
}

func (peer *Peer) ReadFromCtx(ctx context.Context, b []byte) (n int, addr *Addr, err error) {
	for ctx.Err() == nil {
		defer aerr.Ignore()
		var router *net.UDPAddr
		n, router, err = peer.udpConn.ReadFromUDP(b)
		if err != nil {
			return
		}
		switch b[0] & 0b111_00000 {
		case pong:
			if !equalUDPAddr(router, peer.addr.router) {
				continue
			}
			id, peerPk, sealedAddr, _ := unpackPong(b[:n])
			if !bytes.Equal(peer.lastPingID, id) {
				continue
			}
			addr, ok := unseal(sealedAddr, peerPk, peer.sk[:])
			if !ok {
				continue
			}
			peer.lastPong = fastime.Now()
			peer.addr.b = addr
			continue
		case recv:
			from, data := unpackRecv(b)
			n = copy(b, data)
			addr = &Addr{
				b:      from,
				router: router,
			}
			return
		default:
			continue
		}
	}
	err = ctx.Err()
	return
}

func (peer *Peer) WaitPong(ctx context.Context) error {
	b := make([]byte, 256)
	for ctx.Err() == nil {
		defer aerr.Ignore()
		var router *net.UDPAddr
		n, router, err := peer.udpConn.ReadFromUDP(b)
		if err != nil {
			return err
		}
		switch b[0] & 0b111_00000 {
		case pong:
			if !equalUDPAddr(router, peer.addr.router) {
				continue
			}
			id, peerPk, sealedAddr, _ := unpackPong(b[:n])
			if !bytes.Equal(peer.lastPingID, id) {
				continue
			}
			addr, ok := unseal(sealedAddr, peerPk, peer.sk[:])
			if !ok {
				return errors.New("unseal failed")
			}
			peer.lastPong = fastime.Now()
			peer.addr.b = addr
			return nil
		default:
			continue
		}
	}
	return ctx.Err()

}
func unpackRecv(pack []byte) (from, data []byte) {
	lenAddr := (pack[0] & 0b000_11111) + 1
	from = pack[1 : lenAddr+1]
	data = pack[1+lenAddr:]
	return
}
func (peer *Peer) SetDeadline(t time.Time) error {
	return peer.udpConn.SetDeadline(t)
}
func (peer *Peer) SetReadDeadline(t time.Time) error {
	return peer.udpConn.SetReadDeadline(t)
}
func (peer *Peer) SetWriteDeadline(t time.Time) error {
	return peer.udpConn.SetDeadline(t)
}
func seal(raw []byte, peerPublic, mySeret []byte) []byte {
	var sk, pk [32]byte
	var nonce [24]byte
	rand.Read(nonce[:])
	copy(peerPublic, pk[:])
	copy(mySeret, sk[:])
	return box.Seal(nonce[:], raw, &nonce, &pk, &sk)
}
func unseal(sealed []byte, peerPublic, mySeret []byte) ([]byte, bool) {
	var sk, pk [32]byte
	var nonce [24]byte
	rand.Read(nonce[:])
	copy(peerPublic, pk[:])
	copy(mySeret, sk[:])
	copy(nonce[:], sealed[:24])
	return box.Open(nil, sealed[24:], &nonce, &pk, &sk)
}

func equalUDPAddr(a1, a2 *net.UDPAddr) bool {
	return a1.Port == a2.Port && bytes.Equal(a1.IP, a2.IP)
}
