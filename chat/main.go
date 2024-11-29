package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
)

var serverPort, peerAddr, password *string
var chatLog *string

func main() {

	var wg sync.WaitGroup
	wg.Add(2)

	serverPort = flag.String("port", "8443", "服务器监听的端口")
	peerAddr = flag.String("peer", "", "对方的地址（如 localhost:8443）")
	certFile := flag.String("cert", "peer.crt", "证书文件路径")
	keyFile := flag.String("key", "peer.key", "密钥文件路径")
	caFile := flag.String("ca", "ca.crt", "CA 证书文件路径")
	chatLog = flag.String("history", "chat.log", "聊天记录文件路径")
	password = flag.String("password", "your-password", "口令")
	flag.Parse()

	go startServer(*serverPort, *certFile, *keyFile, *caFile, &wg)
	go startClient(*peerAddr, *certFile, *keyFile, *caFile, &wg)

	wg.Wait()
}

func startServer(port, certFile, keyFile, caFile string, wg *sync.WaitGroup) {
	defer wg.Done()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	certPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Rand:         rand.Reader,
	}

	listener, err := tls.Listen("tcp", ":"+port, config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Printf("正在监听端口 %s，等待连接...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func startClient(peerAddr, certFile, keyFile, caFile string, wg *sync.WaitGroup) {
	defer wg.Done()

	if peerAddr == "" {
		fmt.Println("未提供对方的地址，跳过客户端启动。")
		return
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	certPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            certPool,
		InsecureSkipVerify: true,
		Rand:               rand.Reader,
	}

	conn, err := tls.Dial("tcp", peerAddr, config)
	if err != nil {
		log.Println("无法连接到对方，请确保对方已启动并监听端口。")
		return
	}
	defer conn.Close()

	fmt.Println("已连接到对方，可以开始聊天。")
	go readMessages(conn)

	reader := bufio.NewReader(os.Stdin)
	for {
		//fmt.Print("我：")
		text, _ := reader.ReadString('\n')
		_, err := conn.Write([]byte(text))
		if err != nil {
			log.Println(err)
			return
		}
		// 加密并保存聊天记录
		saveChatLog("我："+text, *chatLog, *password)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Println("对方已连接，可以开始聊天。")
	go readMessages(conn)

	reader := bufio.NewReader(os.Stdin)
	for {
		//fmt.Print("我：")
		text, _ := reader.ReadString('\n')
		_, err := conn.Write([]byte(text))
		if err != nil {
			log.Println(err)
			return
		}
		// 加密并保存聊天记录
		saveChatLog("我："+text, *chatLog, *password)
	}
}

func readMessages(conn net.Conn) {
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			return
		}
		message := string(buf[:n])
		fmt.Printf("对方：%s", message)
		// 加密并保存聊天记录
		saveChatLog("对方："+message, *chatLog, *password)
	}
}

func saveChatLog(message string, logFile string, password string) {
	encryptedData, err := encrypt([]byte(message), password)
	if err != nil {
		return
	}
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(encryptedData)
	f.Write([]byte("\n"))
}

func encrypt(data []byte, password string) ([]byte, error) {
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]

	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}
