// SSH client program using factotum for auth
//
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"bitbucket.org/mischief/libauth"
)

var (
	user    = flag.String("u", os.Getenv("user"), "username")
	server  = flag.String("h", os.Getenv("scpu"), "ssh server")
	port    = flag.String("p", "22", "server port")
	cmd     = flag.String("c", "", "remote command")
	nocr    = flag.Bool("r", false, "strip carriage returns")
	resize  = flag.Bool("z", false, "poll environment variables to resize automatically")
	verbose = flag.Bool("v", false, "verbose output on stderr")
)

// ssh.PasswordCallback implementation
func Password() (string, error) {
	pw, err := libauth.Getuserpasswd("proto=pass service=ssh role=client server=%s user=%s", *server, *user)
	if err != nil {
		return "", err
	}

	return pw, nil
}

// ssh.PublicKeys implementation
type rsaSigner struct {
	k rsa.PublicKey
}

func (r *rsaSigner) PublicKey() ssh.PublicKey {
	k, err := ssh.NewPublicKey(&r.k)
	if err != nil {
		log.Fatalf("error parsing key: %s", err)
	}
	return k
}

func (r *rsaSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	hashfun := crypto.SHA1
	h := hashfun.New()
	h.Write(data)
	digest := h.Sum(nil)

	proxybuf := new(bytes.Buffer)
	proxybuf.Write(digest)
	sig, err := libauth.RsaSign(proxybuf.Bytes())

	if err != nil {
		return nil, err
	}

	sshsig := &ssh.Signature{
		Format: "ssh-rsa",
		Blob:   sig,
	}

	return sshsig, nil
}

func GetSigners() ([]ssh.Signer, error) {
	k, err := libauth.Listkeys()
	if err != nil {
		err = fmt.Errorf("libauth.Listkeys error: %s", err)
		return nil, err
	}

	signers := make([]ssh.Signer, len(k))
	for i := range k {
		signers[i] = &rsaSigner{k[i]}
	}

	return signers, nil
}

func main() {
	flag.Parse()

	if *user == "" {
		log.Fatal("set $user or -u flag")
	}

	if *server == "" {
		log.Fatal("set $scpu or -h flag")
	}

	config := &ssh.ClientConfig{
		User: *user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(GetSigners),
			ssh.PasswordCallback(Password),
		},
	}

	dial := *server + ":" + *port
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
		if *verbose {
			log.Printf("remote: %s", err)
		}
		os.Exit(1)
	}
}

func tonumber(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func tonumberu32(s string) uint32 {
	n, _ := strconv.Atoi(s)
	return uint32(n)
}

func envs(key string) string {
	buf, _ := ioutil.ReadFile("/env/" + key)
	return string(buf)
}

func envu32(key string) uint32 {
	buf, _ := ioutil.ReadFile("/env/" + key)
	return tonumberu32(string(buf))
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

	// Possibly auto-resize
	if *resize {
		var wc struct {
			columns   uint32
			rows      uint32
			width_px  uint32
			height_px uint32
		}
		wc.columns = envu32("COLS")
		wc.rows = envu32("LINES")
		go func() {
			for {
				time.Sleep(1 * time.Second)
				if envu32("COLS") != wc.columns {
					wc.columns = envu32("COLS")
					session.SendRequest("window-change", false, ssh.Marshal(wc))
				}
				if envu32("LINES") != wc.rows {
					wc.rows = envu32("LINES")
					session.SendRequest("window-change", false, ssh.Marshal(wc))
				}
			}
		}()
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
