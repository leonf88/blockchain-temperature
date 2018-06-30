package main

import (
	"github.com/boltdb/bolt"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"os"

	//net change
	"errors"
	"io/ioutil"
	"net"
	//"strconv"
	"strings"
	"sync"
	"time"
)

const targetBits = 24

//net change
const port = "8081"
const dbFile = "blockchain_" + port + ".db"
const blockBucket = "blocks"
const blockOrder = "orders"
const nodeAddress = ":" + port
const CommandLength = 20
const NailAddr = ":8080"

var (
	maxNonce = math.MaxInt64
	//net chage
	mux       sync.Mutex
	tempmux   sync.Mutex
	miningmux sync.Mutex

	temperature float64
	knownNode   = []string{NailAddr}
	mine        = true
	db, dberr   = bolt.Open(dbFile, 0600, nil)
)

type Version struct {
	Height        int
	BlockHash     []byte
	ClientAddress []string
	ServerAddress string
}

type RequireBlock struct {
	Height  int
	Address string
}

func LocalAction() {
	var bc *Blockchain
	var sumElapsed time.Duration
	var i float64 = 1
	var err error

	var searchhash []byte
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blockBucket))
		searchhash = b.Get([]byte("l"))
		return nil
	})

	//fmt.Println("LocalAction searchhash: ", searchhash, len(searchhash))
	if len(searchhash) != 0 {
		bc = NewBlockchain()
	} else {
		start := time.Now()
		bc, err = CreateBlockchain()
		if err != nil {
			fmt.Println("Err ", err)
			bc = NewBlockchain()
		}
		elapsed := time.Since(start)
		sumElapsed = sumElapsed + elapsed
		fmt.Println("time eplase:", elapsed)
		fmt.Println("average time eplased:", sumElapsed.Seconds()/i)
		i++
	}

	for {
		start := time.Now()

		tempmux.Lock()
		temperature, _ = Simulator()
		temp := temperature
		tempmux.Unlock()

		_, err = bc.MineBlock(temp)
		if err != nil {
			continue
		}

		elapsed := time.Since(start)
		sumElapsed = sumElapsed + elapsed
		fmt.Println("time eplase: ", elapsed)
		fmt.Println("average time eplased: ", sumElapsed.Seconds()/i)
		i++
	}
}

func Simulator() (float64, int64) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	temp := r1.Float64()
	timeStamp := time.Now().UnixNano()
	return temp, timeStamp
}

type Block struct {
	Timestamp    int64
	Data         float64
	PreBlockHash []byte
	Nonce        int
	Height       int
	NodeAddr     string
	Hash         []byte
}

func NewBlock(data float64, preBlockHash []byte, height int, nodeAddr string) (*Block, error) {
	block := &Block{time.Now().UnixNano(), data, preBlockHash, 0, height, nodeAddr, []byte{}}

	//	fmt.Println("NewBlock block:")
	//	fmt.Println(block)
	pow := NewProofWork(block)
	var err error
	block.Nonce, block.Hash, err = pow.Run()
	//	fmt.Println("NewBlock block2:")
	//	fmt.Println(block)
	return block, err
}

func NewGenesisBlock() (*Block, error) {
	tempmux.Lock()
	temperature, _ = Simulator()
	temp := temperature
	tempmux.Unlock()

	b, err := NewBlock(temp, []byte{}, 1, nodeAddress)
	if err != nil {
		return nil, err
	}
	return b, nil
}

type ProofOfWork struct {
	block  *Block
	target *big.Int
}

func NewProofWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}
	return pow
}

func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join([][]byte{
		pow.block.PreBlockHash,
		IntToHex(float64(pow.block.Timestamp)),
		IntToHex(pow.block.Data),
		IntToHex(float64(nonce)),
		IntToHex(float64(pow.block.Height)),
	}, []byte{})
	return data
}

func IntToHex(num float64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}

func (pow *ProofOfWork) Run() (int, []byte, error) {
	var hashInt big.Int
	var hash [32]byte
	nonce := 0

	fmt.Println()
	fmt.Println("Mining a block!")

	for nonce < maxNonce {
		miningmux.Lock()
		if !mine {
			mine = true
			miningmux.Unlock()
			err := errors.New("Accept new block!")
			time.Sleep(5 * time.Second)
			return 0, []byte{}, err
		}
		miningmux.Unlock()

		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)
		/*	if math.Remainder(float64(nonce), 100000) == 0 {

			fmt.Printf("\r%x", hash)
		}*/
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {

			nonce++
		}
	}

	return nonce, hash[:], nil
}

func (pow *ProofOfWork) Validate() bool {

	var hashInt big.Int

	data := pow.prepareData(pow.block.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])

	isValid := hashInt.Cmp(pow.target) == -1
	return isValid
}

type Blockchain struct {
	tip []byte
	db  *bolt.DB
}

func CreateBlockchain() (*Blockchain, error) {
	var tip []byte
	gensisBlock, err := NewGenesisBlock()
	if err != nil {
		return nil, err
	}
	fmt.Println("genesisblock:", gensisBlock)
	if dberr != nil {
		log.Panic(dberr)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		/*	b, err := tx.CreateBucket([]byte(blockBucket))
			if err != nil {
				log.Panic(err)
			}

			o, err := tx.CreateBucket([]byte(blockOrder))
			if err != nil {
				log.Panic(err)
			}

		*/
		b := tx.Bucket([]byte(blockBucket))
		o := tx.Bucket([]byte(blockOrder))

		err := b.Put(gensisBlock.Hash, gensisBlock.Serialize())
		if err != nil {
			log.Panic(err)
		}

		err = b.Put([]byte("l"), gensisBlock.Hash)

		if err != nil {
			log.Panic(err)
		}

		err = o.Put(IntToHex(float64(gensisBlock.Height)), gensisBlock.Hash)
		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	BatchBrocastNewBlock(gensisBlock.Serialize())

	tip = gensisBlock.Hash
	bc := Blockchain{tip, db}

	return &bc, nil
}

func NewBlockchain() *Blockchain {
	var tip []byte
	if dberr != nil {
		log.Panic(dberr)
	}

	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blockBucket))
		tip = b.Get([]byte("l"))
		fmt.Println("lastblock hash: ", tip)
		return nil
	})

	if err != nil {
		log.Panic(err)
	}

	bc := Blockchain{tip, db}
	return &bc
}

func (bc *Blockchain) AddBlock(block *Block) {
	err := bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blockBucket))

		blockInDb := b.Get(block.Hash)

		if blockInDb != nil {
			return nil
		}

		blockData := block.Serialize()
		err := b.Put(block.Hash, blockData)
		if err != nil {
			log.Panic(err)
		}

		lastHash := b.Get([]byte("l"))
		lastBlockData := b.Get(lastHash)
		lastBlock := Deserialize(lastBlockData)

		if block.Height > lastBlock.Height {
			err = b.Put([]byte("l"), block.Hash)
			if err != nil {
				log.Panic(err)
			}
			bc.tip = block.Hash

		}
		return nil
	})
	if err != nil {

		log.Panic(err)
	}

}

func (bc *Blockchain) MineBlock(temp float64) (*Block, error) {
	var lastHash []byte
	var lastHeight int

	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blockBucket))
		lastHash = b.Get([]byte("l"))
		fmt.Println("Mine lastblock hash: ", lastHash)

		blockData := b.Get(lastHash)
		fmt.Println("blockData: ", blockData)
		block := Deserialize(blockData)

		lastHeight = block.Height
		//	fmt.Println("MineBlock lastHash  lastHeight:")
		//	fmt.Println(lastHash, lastHeight)
		return nil

	})
	if err != nil {
		log.Panic(err)
	}

	newBlock, err := NewBlock(temp, lastHash, lastHeight+1, nodeAddress)
	if err != nil {
		return newBlock, err
	}

	byteNewBlock := newBlock.Serialize()
	fmt.Println("MineBlock block:", newBlock.Height)

	err = bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blockBucket))
		err := b.Put(newBlock.Hash, byteNewBlock)
		if err != nil {
			log.Panic(err)
		}

		err = b.Put([]byte("l"), newBlock.Hash)
		if err != nil {
			log.Panic(err)
		}

		o := tx.Bucket([]byte(blockOrder))

		err = o.Put([]byte(IntToHex(float64(newBlock.Height))), newBlock.Hash)
		if err != nil {
			log.Panic(err)
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	BatchBrocastNewBlock(byteNewBlock)

	bc.tip = newBlock.Hash
	//	fmt.Println("MineBlock Hash:")
	//	fmt.Println(newBlock.Hash)
	return newBlock, nil

}

func DBExists(dbFile string) bool {
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		return false
	}
	return true
}

func (v *Version) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(v)
	if err != nil {
		log.Panic(err)
	}

	return result.Bytes()
}

func (b *Block) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(b)
	if err != nil {
		fmt.Println("Serialize Err: ", err)
	}

	return result.Bytes()
}

func (v *RequireBlock) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(v)
	if err != nil {
		log.Panic(err)
	}

	return result.Bytes()
}

func Deserialize(d []byte) *Block {
	var block Block
	decoder := gob.NewDecoder(bytes.NewReader(d))
	err := decoder.Decode(&block)
	if err != nil {
		log.Panic(err)
	}
	return &block
}

func DeserializeVersion(d []byte) *Version {
	var version Version
	decoder := gob.NewDecoder(bytes.NewReader(d))
	err := decoder.Decode(&version)
	if err != nil {
		log.Panic(err)
	}
	return &version
}

func DeserializeRequireBlock(d []byte) *RequireBlock {
	var requireBlock RequireBlock
	decoder := gob.NewDecoder(bytes.NewReader(d))
	err := decoder.Decode(&requireBlock)
	if err != nil {
		log.Panic(err)
	}
	return &requireBlock
}

//Read Database
func HexToInt(d []byte) float64 {
	var num float64
	buf := bytes.NewReader(d)
	err := binary.Read(buf, binary.BigEndian, &num)
	if err != nil {
		fmt.Println("HexToInt err: ", err)
	}

	return num
}

func DBsearchByHeight(height int) []byte {
	if !DBExists(dbFile) {
		fmt.Println("DBsearchByHeight DB doesn't exist!")
		return []byte{}
	}

	if dberr != nil {
		fmt.Println("DB Err: ", dberr)
		return []byte{}
	}
	//defer db.Close()

	var hash []byte
	db.View(func(tx *bolt.Tx) error {
		o := tx.Bucket([]byte("orders"))
		hash = o.Get(IntToHex(float64(height)))
		return nil
	})

	return hash
}

func DBsearchByHash(hash []byte) []byte {
	fmt.Println("Enter Dbsearchbyhash")
	if !DBExists(dbFile) {
		fmt.Println("DBsearchByHash DB doesn't exist!")
		return []byte{}
	}

	if dberr != nil {
		fmt.Println("DB Err: ", dberr)
		return []byte{}
	}
	//defer db.Close()

	var content []byte
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		content = b.Get(hash)
		return nil
	})

	return content
}

func LatestBlock() ([]byte, []byte, error) {
	fmt.Println("Enter LatestBlock")
	if !DBExists(dbFile) {
		err := errors.New("LatestBlock DB doesn't exist!")
		fmt.Println(err)
		return []byte{}, []byte{}, err
	}

	//db problem
	if dberr != nil {
		fmt.Println("DB Err: ", dberr)
		return []byte{}, []byte{}, dberr
	}

	//fmt.Println("Successful Enter!")
	var latestblockhash []byte
	var latestblockcontent []byte
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		latestblockhash = b.Get([]byte("l"))
		latestblockcontent = b.Get(latestblockhash)
		return nil
	})
	if err != nil {
		fmt.Println("LatestBlock db.View Err: ", err)
		return []byte{}, []byte{}, err
	}

	return latestblockhash, latestblockcontent, nil
}

//net change
func Listen() {
	fmt.Println("Enter listening")
	ln, err := net.Listen("tcp", nodeAddress)
	if err != nil {
		fmt.Println("ln Err: ", err)
	}

	n := 1
	for {
		fmt.Println("Enter for ", n)
		conn, err := ln.Accept()
		fmt.Println("Receive conn: ", conn)
		if err != nil {
			fmt.Println("Conn Err: ")
		}

		HandleConnection(conn)
		n++
	}
}

func HandleConnection(conn net.Conn) {
	fmt.Println("Enter HandleConnection")
	byteInfo, err := ioutil.ReadAll(conn)
	if err != nil {
		fmt.Println("ioutil Err: ", err)
		return
	}

	if len(byteInfo) == 0 {
		return
	}

	//fmt.Println("HandleConnection: ", byteInfo)
	byteCmd := byteInfo[:CommandLength]
	bytePayload := byteInfo[CommandLength:]

	command := ByteToCommand(byteCmd)
	fmt.Println("handleConnection command received: ", command)

	switch command {
	case "version":
		HandleVersion(bytePayload)
	case "block":
		HandleBlock(bytePayload)
	case "requireblock":
		HandleRequireBlock(bytePayload)
	case "newblock":
		HandleNewBlock(bytePayload)
	default:
		fmt.Println("No such command: ", command)
	}
	defer conn.Close()
}

func HandleRequireBlock(bytePayload []byte) error {
	requireBlock := DeserializeRequireBlock(bytePayload)
	address := requireBlock.Address
	height := requireBlock.Height
	fmt.Println("Enter HandleRequireBlock: msg from", address)
	fmt.Println("HandleRequireBlock height: ", height)

	var content []byte
	err := db.View(func(tx *bolt.Tx) error {
		o := tx.Bucket([]byte(blockOrder))
		b := tx.Bucket([]byte(blockBucket))

		hash := o.Get(IntToHex(float64(height)))
		content = b.Get(hash)
		return nil
	})
	if err != nil {
		fmt.Println("HandleRequireBlock dbView Err:", err)
		return err
	}
	//fmt.Println("handleRequireBlock content: ", content)

	byteInfo := CommandToByte("block")
	for i := 0; i < len(content); i++ {
		byteInfo = append(byteInfo, content[i])
	}

	err = SendData(address, byteInfo)
	return err

}

func HandleVersion(bytePayload []byte) error {
	info := DeserializeVersion(bytePayload)

	sendNode := info.ServerAddress
	getNode := info.ClientAddress
	getNode = append(getNode, sendNode)
	DealNode(sendNode, getNode)
	fmt.Println("Enter HandleVersion: msg from ", sendNode)

	height := info.Height
	blockhash := info.BlockHash
	//fmt.Println("Height,blockhash:", height, blockhash)
	_, latestblockcontent, err := LatestBlock()
	//fmt.Println("HandleVersion latestblock", latestblockcontent)

	var bestheight int
	var latestBlockHash []byte
	if err != nil || len(latestblockcontent) == 0 {
		bestheight = 0
		latestBlockHash = []byte{}
	} else {
		latestblock := Deserialize(latestblockcontent)
		bestheight = latestblock.Height
		latestBlockHash = latestblock.Hash
		//fmt.Println("latest block: ", latestblock, bestheight, latestBlockHash)
	}

	if height == bestheight {
		fmt.Println("Enter =")
		if ByteChange(blockhash) != ByteChange(latestBlockHash) {
			err := RequireBlocks(height, sendNode)
			fmt.Println("handleversion: ", err)
			return err
		}
		return nil
	} else if height > bestheight {
		fmt.Println("Enter >")
		miningmux.Lock()
		mine = false
		miningmux.Unlock()
		err := BatchRequireBlock(height, bestheight, sendNode)
		return err
	} else {
		fmt.Println("Enter <")
		err := SendVersion(sendNode)
		return err
	}
}

func ByteChange(input []byte) [32]byte {
	var result [32]byte

	for i := 0; i < len(input); i++ {
		result[i] = input[i]
	}

	return result
}

func SendData(address string, data []byte) error {
	fmt.Println("Enter SendData")
	conn, err := net.Dial("tcp", address)
	if err != nil {
		DeleteKnownNode(address)
		fmt.Println("SendData Err: ", err)
		return err
	}
	//fmt.Println("Send Data: ", data)
	conn.Write(data)
	conn.Close()
	return nil
}

func SendVersion(address string) error {
	fmt.Println("Enter SendVersion")
	_, latestblockcontent, err := LatestBlock()

	var latestblock *Block
	var bestheight int
	var dbblockhash []byte
	if err != nil || len(latestblockcontent) == 0 {
		bestheight = 0
		dbblockhash = []byte{}
	} else {
		latestblock = Deserialize(latestblockcontent)
		bestheight = latestblock.Height
		dbblockhash = latestblock.Hash
	}

	var version *Version
	version = &Version{bestheight, dbblockhash, knownNode, nodeAddress}
	byteversion := version.Serialize()

	byteInfo := CommandToByte("version")
	for i := 0; i < len(byteversion); i++ {
		byteInfo = append(byteInfo, byteversion[i])
	}

	err = SendData(address, byteInfo)
	return err
}

func CommandToByte(command string) []byte {
	byteStdCmd := make([]byte, CommandLength)
	byteCmd := []byte(command)

	for i := 0; i < len(byteCmd); i++ {
		byteStdCmd[i] = byteCmd[i]
	}

	return byteStdCmd
}

func ByteToCommand(byteCmd []byte) string {
	if len(byteCmd) == 0 {
		fmt.Println("ByteToCommand contains no value")
		return ""
	}

	var trimByteCmd []byte
	for _, b := range byteCmd {
		if b != 0x0 {
			trimByteCmd = append(trimByteCmd, b)
		}
	}

	command := string(trimByteCmd)
	return command
}

func DeleteKnownNode(address string) []string {
	fmt.Println("DeleteKnownNode is here")

	if IsKNEmpty() || len(knownNode) == 1 {
		knownNode = []string{}
		return knownNode
	}

	result, index := FindANode(address)

	n := len(knownNode) - 1
	fmt.Println("index: ", index, " n: ", n, " result: ", result)
	if result {
		if index != n {
			knownNode[index] = knownNode[n]
		}
		knownNode = knownNode[:n]
	}
	return knownNode

}

func IsKNEmpty() bool {
	if len(knownNode) == 0 {
		return true
	} else {
		return false
	}
}

func FindANode(address string) (bool, int) {
	if IsKNEmpty() {
		return false, -1
	}

	for k, ad := range knownNode {
		if strings.Compare(address, ad) == 0 {
			return true, k
		}
	}
	return false, -1
}

func BatchRequireBlock(height int, bestheight int, sendNode string) error {
	fmt.Println("Enter BatchRequireBlock", height, bestheight)
	for i := bestheight + 1; i < height+1; i++ {
		err := RequireBlocks(i, sendNode)
		if err != nil {

			return err
		}

		if i%100 == 0 {
			SendVersion(sendNode)
			return nil
		}
		/*
			fmt.Println("BatchRB: ", i, i%100)
			if i%100 == 0 {
				time.Sleep(1 * time.Second)
				fmt.Println("Sleep")
			}
		*/
	}
	fmt.Println("This is the end of batchrequireblock")
	return nil
}

func RequireBlocks(height int, sendNode string) error {
	fmt.Println("Enter RequireBlock")
	byteinfo := CommandToByte("requireblock")
	var requireBlock *RequireBlock
	requireBlock = &RequireBlock{height, nodeAddress}
	content := requireBlock.Serialize()

	for i := 0; i < len(content); i++ {
		byteinfo = append(byteinfo, content[i])
	}

	err := SendData(sendNode, byteinfo)
	return err
}

func DealNode(address string, getAddr []string) []string {

	fmt.Println("Enter renewknownnode")
	//fmt.Println("getAddr: ", getAddr)
	mux.Lock()
	defer mux.Unlock()
	if len(knownNode) == 0 {
		for _, ad := range getAddr {
			if len(ad) != 0 && strings.Compare(ad, nodeAddress) != 0 {
				//fmt.Println("new Node: ", ad)
				knownNode = append(knownNode, ad)
				if strings.Compare(ad, address) != 0 {
					SendVersion(ad)
				}
			}
		}
	} else {

		for _, ad1 := range getAddr {
			newNode := true
			for _, ad2 := range knownNode {
				if strings.Compare(ad1, nodeAddress) == 0 || strings.Compare(ad1, ad2) == 0 {
					newNode = false
					fmt.Println("It is not a new Node", ad1, knownNode)
					break
				}

			}
			if len(ad1) != 0 && newNode {
				fmt.Println("new Node", ad1)
				knownNode = append(knownNode, ad1)
				if strings.Compare(ad1, address) != 0 {
					SendVersion(ad1)
				}

			}
		}

	}
	fmt.Println("knownNode: ", knownNode)
	return knownNode

}

func HandleBlock(bytePayload []byte) error {
	fmt.Println("Enter handleBlock")
	info := Deserialize(bytePayload)
	timeStamp := info.Timestamp
	data := info.Data
	preBlockHash := info.PreBlockHash
	height := info.Height
	hash := info.Hash
	nonce := info.Nonce
	//mineNodeAddr := info.NodeAddr

	//valid data correctness
	//whether it already exists

	diff := temperature - data
	if math.Abs(diff) > 1 {
		err := errors.New("Data is wrong")
		return err
	}
	//
	//
	//preblock in the database
	//
	var isFork bool
	if height != 1 {
		dbContent := DBsearchByHash(hash)
		if len(dbContent) != 0 {
			err := errors.New("Block already exists!")
			fmt.Println("HandleBlock err: ", err)
			return err
		}

		dbContent = DBsearchByHash(preBlockHash)
		if len(dbContent) == 0 {
			//
			err := errors.New("No such preBlock")
			return err
		}

		//
		//time check
		dbBlock := Deserialize(dbContent)
		timestamp := dbBlock.Timestamp
		tDiff := math.Abs(float64(timestamp - timeStamp))
		//
		if tDiff > 60 {
			//	err := errors.New("timestamp err")
			//	return err
			//
		}

		//puzzle check
		pow := NewProofWork(info)
		vData := pow.prepareData(nonce)
		vHash := sha256.Sum256(vData)
		if vHash != ByteChange(hash) {
			err := errors.New("Hash is not correct!")
			//
			return err
		}

		//fork check
		isFork = false
		_, dbLatestBlock, _ := LatestBlock()
		latestBlock := Deserialize(dbLatestBlock)
		dbHeight := latestBlock.Height
		if dbHeight > height || dbHeight == height {
			if math.Abs(float64(dbHeight-height)) > 0 {
				err := errors.New("Suspected block")
				fmt.Println("HandleVersion Err: ", err)
				return err
			}
			fmt.Println("There is a fork")
			isFork = true

		}
	}

	//
	//
	//
	//db manipulation
	byteBlock := info.Serialize()
	if dberr != nil {
		log.Panic(dberr)
	}
	//defer db.Close()

	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		err := b.Put(hash, byteBlock)
		if err != nil {
			log.Panic(err)
		}

		o := tx.Bucket([]byte("orders"))
		if !isFork {
			err = b.Put([]byte("l"), hash)
			if err != nil {
				log.Panic(err)
			}
			err = o.Put(IntToHex(float64(height)), hash)
			if err != nil {
				log.Panic(err)
			}
		}

		//Here might be changed to a loop in order to change to another branch
		checkHash := DBsearchByHeight(height - 1)
		if ByteChange(checkHash) != ByteChange(preBlockHash) {
			err = o.Put(IntToHex(float64(height-1)), preBlockHash)
		}

		return nil
	})

	fmt.Println("HandleBlock successsful!")

	miningmux.Lock()
	mine = false
	miningmux.Unlock()
	return nil
}

func main() {
	db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucket([]byte(blockOrder))
		tx.CreateBucket([]byte(blockBucket))
		return nil
	})

	go SendVersion(NailAddr)
	go LocalAction()
	Listen()
}

func BatchBrocastNewBlock(payload []byte) error {
	fmt.Println("Enter BatchBrocastNewBlock:", knownNode)

	if len(knownNode) == 0 {
		err := errors.New("No address")
		fmt.Println("BatchBrocastNewBlock Err: ", err)
		return err
	}

	for _, addr := range knownNode {
		fmt.Println("BrocastNewBlock to: ", addr)
		err := BrocastNewBlock(payload, addr)
		if err != nil {
			return err
		}
	}
	return nil
}

func BrocastNewBlock(payload []byte, address string) error {
	fmt.Println("Enter BrocastNewBlock")
	byteInfo := CommandToByte("newblock")
	for i := 0; i < len(payload); i++ {
		byteInfo = append(byteInfo, payload[i])
	}

	err := SendData(address, byteInfo)
	return err

}

func HandleNewBlock(payload []byte) error {
	err := HandleBlock(payload)
	if err != nil {
		fmt.Println("HandleNewBlock Err: ", err)
		return err
	}

	time.Sleep(1 * time.Second)
	err = BatchBrocastNewBlock(payload)
	if err == nil {
		fmt.Println("Handle new block successfully!")
	}
	return err
}
