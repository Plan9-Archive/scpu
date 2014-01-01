// SSH client program using factotum for auth
//
package main

import (
	"bitbucket.org/mischief/libauth"
	"bufio"
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"crypto"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
)

var (
	user   = flag.String("u", os.Getenv("user"), "username")
	server = flag.String("h", os.Getenv("scpu"), "ssh server")
	port   = flag.String("p", "22", "server port")
	cmd    = flag.String("c", "", "remote command")
	nocr   = flag.Bool("r", false, "strip carriage returns")
)

// ClientPassword implementation
type password struct{}

func (p password) Password(user string) (string, error) {
	pw, err := libauth.Getuserpasswd("proto=pass service=ssh role=client server=%s user=%s", *server, user)
	if err != nil {
		return "", err
	}

	return pw, nil
}

// ClientKeyring implementation
type keyring struct {
	keys []rsa.PublicKey
}

func NewKeyring() *keyring {
	k, err := libauth.Listkeys()
	if err != nil {
		log.Printf("libauth.Listkeys error: %s", err)
		return nil
	}

	return &keyring{k}
}

func (k *keyring) Key(i int) (key ssh.PublicKey, err error) {
	if i < 0 || i >= len(k.keys) {
		return nil, nil
	}

	key, err = ssh.NewPublicKey(&k.keys[i])
	return
}

func (k *keyring) Sign(i int, rand io.Reader, data []byte) (sig []byte, err error) {
	hashfun := crypto.SHA1
	h := hashfun.New()
	h.Write(data)
	digest := h.Sum(nil)

	proxybuf := new(bytes.Buffer)
	proxybuf.Write(digest)
	sig, err = libauth.RsaSign(proxybuf.Bytes())
	return
}

func main() {
	flag.Parse()

	if *user == "" {
		log.Fatal("set $user or -u flag")
	}

	if *server == "" {
		log.Fatal("set $scpu or -h flag")
	}

	ring := NewKeyring()

	config := &ssh.ClientConfig{
		User: *user,
		Auth: []ssh.ClientAuth{
			ssh.ClientAuthKeyring(ring),
			ssh.ClientAuthPassword(password{}),
		},
	}

	dial := fmt.Sprintf("%s:%s", *server, *port)
	conn, err := ssh.Dial("tcp", dial, config)

	if err != nil {
		log.Fatalf("dial: %s", err)
	}

	session, err := conn.NewSession()
	if err != nil {
		log.Fatalf("newsession: %s", err)
	}

	defer session.Close()

	in, err := session.StdinPipe()
	if err != nil {
		log.Fatalf("stdinpipe: %s", err)
	}

	go func() {
		io.Copy(in, os.Stdin)
		session.Close()
	}()

	session.Stdin = os.Stdin

	if *nocr == true {
		session.Stdout = &CrStripper{bufio.NewWriter(os.Stdout)}
		session.Stderr = &CrStripper{bufio.NewWriter(os.Stderr)}
	} else {
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
	}

	if *cmd != "" {
		err = command(session, *cmd)
	} else {
		err = interactive(session)
	}

	if err != nil {
		log.Print(err)
	}

}

func tonumber(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func interactive(session *ssh.Session) error {
	// Set up terminal modes
	modes := ssh.TerminalModes{
		//ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 115200, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 115200, // output speed = 14.4kbaud
	}
	// Request pseudo terminal
	if err := session.RequestPty(os.Getenv("TERM"), tonumber(os.Getenv("LINES")), tonumber(os.Getenv("COLS")), modes); err != nil {
		fmt.Errorf("request for pseudo terminal failed: %s", err)
	}
	// Start remote shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %s", err)
	}

	if err := session.Wait(); err != nil {
		return fmt.Errorf("session: %s", err)
	}

	return nil
}

func command(session *ssh.Session, cmd string) error {
	return session.Run(cmd)
}

type CrStripper struct {
	out *bufio.Writer
}

func (cr *CrStripper) Write(s []byte) (int, error) {
	for _, b := range s {
		if b != '\r' {
			cr.out.WriteByte(b)
		}
	}

	cr.out.Flush()

	return len(s), nil
}
