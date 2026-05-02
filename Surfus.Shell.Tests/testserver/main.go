package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"crypto/x509"

	"golang.org/x/crypto/ssh"
)

func main() {
	port := flag.String("port", "0", "listen port (0 = random)")
	user := flag.String("user", "testuser", "accepted username")
	pass := flag.String("pass", "testpass", "accepted password")
	hostKeyType := flag.String("hostkey", "ed25519", "host key type: ed25519, rsa, ecdsa256, ecdsa384, ecdsa521")
	shellMode := flag.String("shell", "echo", "shell mode: echo, cisco")
	timeoutSec := flag.Int("timeout", 0, "auto-shutdown after N seconds (0 = no timeout)")
	kexAlgos := flag.String("kex", "", "comma-separated kex algorithms (empty = all supported)")
	ciphers := flag.String("ciphers", "", "comma-separated ciphers (empty = all supported)")
	macs := flag.String("macs", "", "comma-separated MACs (empty = all supported)")
	flag.Parse()

	signer := generateHostKey(*hostKeyType)

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == *user && string(p) == *pass {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if c.User() != *user {
				return nil, fmt.Errorf("invalid user")
			}
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) == 1 && answers[0] == *pass {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}

	config.AddHostKey(signer)

	// Configure algorithms
	if *kexAlgos != "" {
		config.KeyExchanges = splitCSV(*kexAlgos)
	}
	if *ciphers != "" {
		config.Ciphers = splitCSV(*ciphers)
	}
	if *macs != "" {
		config.MACs = splitCSV(*macs)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:"+*port)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Printf("LISTENING:%d\n", listener.Addr().(*net.TCPAddr).Port)
	fmt.Printf("HOSTKEY:%s\n", ssh.FingerprintSHA256(signer.PublicKey()))
	os.Stdout.Sync()

	// Shutdown on signal or timeout
	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		close(done)
	}()
	if *timeoutSec > 0 {
		go func() {
			time.Sleep(time.Duration(*timeoutSec) * time.Second)
			close(done)
		}()
	}

	// Accept loop with shutdown
	go func() {
		<-done
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}
		go handleConn(conn, config, *shellMode)
	}
}

func handleConn(conn net.Conn, config *ssh.ServerConfig, shellMode string) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("handshake error: %v", err)
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go handleSession(channel, requests, shellMode)
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, shellMode string) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "pty-req":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			switch shellMode {
			case "cisco":
				runCiscoShell(channel)
			default:
				runEchoShell(channel)
			}
			return
		case "exec":
			req.Reply(true, nil)
			handleExec(channel, req.Payload)
			return
		case "subsystem":
			req.Reply(false, nil)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// --- Echo shell: echoes input, responds to "exit" ---

func runEchoShell(ch ssh.Channel) {
	defer ch.Close()
	ch.Write([]byte("$ "))

	buf := make([]byte, 4096)
	var line strings.Builder
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		data := string(buf[:n])
		ch.Write(buf[:n]) // echo

		line.WriteString(data)
		if strings.Contains(data, "\n") || strings.Contains(data, "\r") {
			cmd := strings.TrimSpace(line.String())
			line.Reset()
			if cmd == "exit" {
				ch.Write([]byte("\r\nbye\r\n"))
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
				return
			}
			ch.Write([]byte("\r\n$ "))
		}
	}
}

// --- Cisco IOS shell simulator ---

type ciscoState int

const (
	ciscoUser ciscoState = iota
	ciscoPrivileged
	ciscoConfig
)

func runCiscoShell(ch ssh.Channel) {
	defer ch.Close()

	hostname := "Router"
	state := ciscoUser
	enablePass := "enable"

	writePrompt := func() {
		switch state {
		case ciscoUser:
			ch.Write([]byte(hostname + ">"))
		case ciscoPrivileged:
			ch.Write([]byte(hostname + "#"))
		case ciscoConfig:
			ch.Write([]byte(hostname + "(config)#"))
		}
	}

	ch.Write([]byte("\r\n" + hostname + ">"))

	buf := make([]byte, 4096)
	var line strings.Builder
	waitingForPassword := false

	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		data := string(buf[:n])
		ch.Write(buf[:n]) // echo

		line.WriteString(data)
		if !strings.Contains(data, "\n") && !strings.Contains(data, "\r") {
			continue
		}

		cmd := strings.TrimSpace(line.String())
		line.Reset()

		if waitingForPassword {
			waitingForPassword = false
			if cmd == enablePass {
				state = ciscoPrivileged
				ch.Write([]byte("\r\n"))
				writePrompt()
			} else {
				ch.Write([]byte("\r\n% Bad secrets\r\n\r\n"))
				writePrompt()
			}
			continue
		}

		switch {
		case cmd == "enable" && state == ciscoUser:
			ch.Write([]byte("\r\nPassword: "))
			waitingForPassword = true
		case cmd == "disable" && state == ciscoPrivileged:
			state = ciscoUser
			ch.Write([]byte("\r\n"))
			writePrompt()
		case cmd == "configure terminal" && state == ciscoPrivileged:
			state = ciscoConfig
			ch.Write([]byte("\r\nEnter configuration commands, one per line.  End with CNTL/Z.\r\n"))
			writePrompt()
		case cmd == "end" && state == ciscoConfig:
			state = ciscoPrivileged
			ch.Write([]byte("\r\n"))
			writePrompt()
		case cmd == "exit":
			switch state {
			case ciscoConfig:
				state = ciscoPrivileged
				ch.Write([]byte("\r\n"))
				writePrompt()
			case ciscoPrivileged:
				state = ciscoUser
				ch.Write([]byte("\r\n"))
				writePrompt()
			case ciscoUser:
				ch.Write([]byte("\r\n"))
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
				return
			}
		case strings.HasPrefix(cmd, "show version"):
			ch.Write([]byte("\r\nCisco IOS Software, Test Version 15.1(4)M\r\nRouter uptime is 0 minutes\r\n"))
			writePrompt()
		case strings.HasPrefix(cmd, "show running-config"):
			ch.Write([]byte("\r\nBuilding configuration...\r\n\r\nCurrent configuration : 0 bytes\r\nhostname " + hostname + "\r\nend\r\n"))
			writePrompt()
		case cmd == "terminal length 0" || cmd == "terminal pager 0":
			ch.Write([]byte("\r\n"))
			writePrompt()
		case cmd == "":
			ch.Write([]byte("\r\n"))
			writePrompt()
		default:
			ch.Write([]byte("\r\n% Unknown command: " + cmd + "\r\n"))
			writePrompt()
		}
	}
}

// --- Exec handler ---

func handleExec(ch ssh.Channel, payload []byte) {
	defer ch.Close()

	if len(payload) < 4 {
		return
	}
	cmdLen := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+cmdLen {
		return
	}
	command := string(payload[4 : 4+cmdLen])

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		ch.Write([]byte(err.Error() + "\n"))
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{1}))
		return
	}
	io.Copy(ch, stdout)
	cmd.Wait()

	exitCode := uint32(0)
	if cmd.ProcessState != nil && !cmd.ProcessState.Success() {
		exitCode = 1
	}
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{exitCode}))
}

// --- Key generation ---

func generateHostKey(keyType string) ssh.Signer {
	var privKey interface{}
	var err error

	switch keyType {
	case "rsa":
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ecdsa256":
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa384":
		privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ecdsa521":
		privKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default: // ed25519
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		log.Fatalf("failed to generate %s key: %v", keyType, err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Fatal(err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	signer, err := ssh.ParsePrivateKey(pemBlock)
	if err != nil {
		log.Fatal(err)
	}
	return signer
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
