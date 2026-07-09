package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"p2p"
)

func main() {
	port := flag.String("port", "9000", "local listen port")
	peer := flag.String("peer", "", "peer address to connect to")
	name := flag.String("name", "", "peer name")
	flag.Parse()

	if *name != "" {
		fmt.Printf("starting peer %s\n", *name)
	}

	storage, err := p2p.InitStorage("p2p.db", []byte("secure-passphrase"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "storage init failed: %v\n", err)
		os.Exit(1)
	}
	defer storage.Close()

	mgr := p2p.NewConnManager(storage)
	client := p2p.NewClient(mgr, storage)

	listenAddr := fmt.Sprintf(":%s", *port)
	go func() {
		if err := mgr.ListenAndServe(listenAddr, 30*time.Second, 30*time.Second, 5*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "listen failed: %v\n", err)
		}
	}()

	if *peer != "" {
		if err := client.ConnectPeer(*peer); err != nil {
			fmt.Fprintf(os.Stderr, "connect failed: %v\n", err)
		}
	}

	client.StartInboundHandler(func(msg p2p.InboundMessage) {
		fmt.Printf("INBOUND from %s: %s\n", msg.PeerID, string(msg.Frame.Payload))
	})

	scan := bufio.NewScanner(os.Stdin)
	fmt.Println("p2p client ready. commands: send, peers, history, addcontact, contacts, connect, exit")
	for {
		fmt.Print("> ")
		if !scan.Scan() {
			break
		}
		line := strings.TrimSpace(scan.Text())
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "send":
			if len(parts) < 3 {
				fmt.Println("usage: send <peer-address> <message>")
				continue
			}
			peer := parts[1]
			msg := strings.Join(parts[2:], " ")
			if err := client.SendMessage(peer, msg); err != nil {
				fmt.Println("send failed:", err)
			}
		case "peers":
			for _, peer := range client.ListPeers() {
				fmt.Printf("%s last seen %s\n", peer.Address, peer.LastSeen.Format(time.RFC3339))
			}
		case "history":
			msgs, err := client.ConversationHistory(1, 50)
			if err != nil {
				fmt.Println("history failed:", err)
				continue
			}
			for _, rec := range msgs {
				fmt.Printf("[%s] %s from %s status=%d\n", time.Unix(rec.Timestamp, 0).Format(time.RFC3339), string(rec.Body), rec.Sender, rec.Status)
			}
		case "addcontact":
			if len(parts) < 3 {
				fmt.Println("usage: addcontact <public-key> <alias>")
				continue
			}
			if err := client.AddContact(parts[1], strings.Join(parts[2:], " ")); err != nil {
				fmt.Println("addcontact failed:", err)
			}
		case "contacts":
			contacts, err := client.ListContacts()
			if err != nil {
				fmt.Println("contacts failed:", err)
				continue
			}
			for _, c := range contacts {
				fmt.Printf("%s (%s) added %s\n", c.Alias, c.PublicKey, c.AddedAt.Format(time.RFC3339))
			}
		case "connect":
			if len(parts) != 2 {
				fmt.Println("usage: connect <peer-address>")
				continue
			}
			if err := client.ConnectPeer(parts[1]); err != nil {
				fmt.Println("connect failed:", err)
			}
		case "exit":
			client.Shutdown(context.Background())
			return
		default:
			fmt.Println("unknown command")
		}
	}
}
