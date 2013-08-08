package main

import (
	"bitbucket.org/mischief/libauth"
	"code.google.com/p/go.crypto/ssh"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	user   = flag.String("u", os.Getenv("user"), "username")
	server = flag.String("h", os.Getenv("scpu"), "ssh server")
	cmd    = flag.String("c", "", "remote command")
)

type password struct{}

func (p password) Password(user string) (string, error) {
	host := strings.Split(*server, ":")[0]
	pw, err := libauth.Getuserpasswd("proto=pass service=ssh role=client server=%s user=%s", host, user)
	if err != nil {
		return "", err
	}

	return pw, nil
}

func main() {
	flag.Parse()

	if *user == "" {
		log.Fatal("set $user or -u flag")
	}

	if *server == "" {
		log.Fatal("set $scpu or -h flag")
	}

	pw := password{}
	if pwstr, err := pw.Password(*user); pwstr == "" || err != nil {
		log.Fatalf("no password: %s", err)
	}

	config := &ssh.ClientConfig{
		User: *user,
		Auth: []ssh.ClientAuth{
			ssh.ClientAuthPassword(password{}),
		},
	}
	conn, err := ssh.Dial("tcp", *server, config)

	if err != nil {
		log.Fatalf("dial: %s", err)
	}

	session, err := conn.NewSession()
	if err != nil {
		fmt.Printf("session: %s", err)
		os.Exit(1)
	}

	defer session.Close()

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if *cmd != "" {
		err = command(session, *cmd)
	} else {
		err = interactive(session)
	}

	if err != nil {
		log.Fatal(err)
	}

}

func interactive(session *ssh.Session) error {
	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	// Request pseudo terminal
	if err := session.RequestPty("xterm", 80, 24, modes); err != nil {
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
