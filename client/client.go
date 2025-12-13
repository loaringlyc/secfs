package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	_ "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

/*
********************************************
**      Global Stucts and Functions       **
********************************************
 */

type DatastoreEntry struct {
	Ciphertext []byte
	Hash       []byte
}

func encryptData(encKey []byte, hashKey []byte, msg []byte) (encBytes []byte, err error) {
	var entry = DatastoreEntry{}

	// encypt text
	if len(encKey) != 16 {
		return []byte{}, errors.New("encryption key for SymEnc must be 16 bytes")
	}
	iv := userlib.RandomBytes(16)
	entry.Ciphertext = userlib.SymEnc(encKey, iv, msg)

	// hash ciphertext
	if len(hashKey) != 16 {
		return []byte{}, errors.New("encryption key for HMACEval must be 16 bytes")
	}
	var hashRes []byte
	hashRes, err = userlib.HMACEval(hashKey, entry.Ciphertext)
	if err != nil {
		return []byte{}, err
	}
	entry.Hash = hashRes

	// Serialize
	encBytes, err = json.Marshal(entry)
	if err != nil {
		return []byte{}, err
	}

	return encBytes, nil
}

func verifyAndDecryptData(hashKey []byte, encKey []byte, storedData []byte) (plainBytes []byte, err error) {
	// Get datastore entry
	var entry DatastoreEntry
	err = json.Unmarshal(storedData, &entry)
	if err != nil {
		return nil, err
	}

	// Check integrity
	if len(hashKey) != 16 {
		return []byte{}, errors.New("encryption key for HMACEval must be 16 bytes")
	}
	var hashResExp []byte
	hashResExp, err = userlib.HMACEval(hashKey, entry.Ciphertext)
	if err != nil {
		return []byte{}, err
	}
	if !userlib.HMACEqual(hashResExp, entry.Hash) {
		return []byte{}, errors.New("stored data has been tampered")
	}

	// Decrypt data
	if len(encKey) != 16 {
		return []byte{}, errors.New("encryption key for SymEnc must be 16 bytes")
	}
	if len(entry.Ciphertext) < userlib.AESBlockSizeBytes {
		return nil, errors.New("ciphertext is less than the length of one cipher block")
	}
	plainBytes = userlib.SymDec(encKey, entry.Ciphertext) // TODO: nosense codes?
	return plainBytes, nil
}

/*
********************************************
**   User Struct and User Authentication  **
**          UserInit, GetUser             **
********************************************
 */

// Compute the userUUID from passwdKey
func getUserUUIDByInfo(passwdKey []byte) (userUUID uuid.UUID, err error) {
	var uuidBytes []byte
	uuidBytes, err = userlib.HashKDF(passwdKey, []byte("user-uuid"))
	if err != nil {
		return uuid.Nil, err
	}
	userUUID, err = uuid.FromBytes(uuidBytes[:16])
	if err != nil {
		return uuid.Nil, err
	}
	return userUUID, nil
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string

	SourceKey []byte

	PkeEncKey userlib.PKEEncKey
	PkeDecKey userlib.PKEDecKey

	DsSigKey userlib.DSSignKey
	DsVerKey userlib.DSVerifyKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type UserFileList struct {
	FileList map[string]uuid.UUID
	KeyList  map[string][]byte // 16 bytes
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username

	userdata.SourceKey = userlib.RandomBytes(16)

	// Generate root key from password & username (used as salt)
	var passwdKey []byte = userlib.Argon2Key([]byte(password), []byte(username), 16)

	userlib.DebugMsg("[InitUser] Generate non-symmetric keys for user: " + username)
	// Generate keys for public key encryption
	userdata.PkeEncKey, userdata.PkeDecKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"_pke", userdata.PkeEncKey)
	if err != nil {
		return nil, err
	}

	// Generate keys for data sign
	userdata.DsSigKey, userdata.DsVerKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"_ds", userdata.DsVerKey)
	if err != nil {
		return nil, err
	}

	userlib.DebugMsg("[InitUser] Encrypt and store user data for user: " + username)
	// Get user bytes, encryption key and hash key
	var userBytes []byte
	userBytes, err = json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	var userInfoEncKey []byte
	userInfoEncKey, err = userlib.HashKDF(passwdKey, []byte("user-info-encryption"))
	if err != nil {
		return nil, err
	}
	var hashKey []byte
	hashKey, err = userlib.HashKDF(passwdKey, []byte("ciphertext-hash"))
	if err != nil {
		return nil, err
	}

	// Get encryption results
	var encRes []byte
	encRes, err = encryptData(userInfoEncKey[:16], hashKey[:16], userBytes) // Symmetric Encryption use 16-byte key
	if err != nil {
		return nil, err
	}

	// Get userUUID and store
	var userUUID uuid.UUID
	userUUID, err = getUserUUIDByInfo(passwdKey)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userUUID, encRes)

	userlib.DebugMsg("[InitUser] Encrypt and store user file list for user: " + username)
	// Encrypt and store file list information
	var fileList = UserFileList{
		FileList: make(map[string]uuid.UUID), // initialize empty map
		KeyList:  make(map[string][]byte),
	}

	// Get filelist uuid and store
	var fileListUUID uuid.UUID
	fileListUUID, err = uuid.FromBytes(userlib.Hash([]byte("file-list-" + username))[:16])
	if err != nil {
		return nil, err
	}
	err = storeFileList(fileList, userdata.SourceKey, fileListUUID)
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var passwdKey []byte = userlib.Argon2Key([]byte(password), []byte(username), 16)
	var userUUID userlib.UUID
	userUUID, err = getUserUUIDByInfo(passwdKey)
	if err != nil {
		return nil, err
	}

	// Get ciphertext
	storedUserData, ok := userlib.DatastoreGet(userUUID)
	if !ok || storedUserData == nil {
		return nil, errors.New("cannot find user information")
	}

	// Check data integrity and decrypt user data
	var hashKey []byte
	hashKey, err = userlib.HashKDF(passwdKey, []byte("ciphertext-hash"))
	if err != nil {
		return nil, err
	}
	var userInfoEncKey []byte
	userInfoEncKey, err = userlib.HashKDF(passwdKey, []byte("user-info-encryption"))
	if err != nil {
		return nil, err
	}
	var userBytes []byte
	userBytes, err = verifyAndDecryptData(hashKey[:16], userInfoEncKey[:16], storedUserData)
	if err != nil {
		return nil, err
	}

	// Deserialize bytes to User structure
	var userdata User
	err = json.Unmarshal(userBytes, &userdata)
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}

/*
********************************************
**            File Operations             **
**   StoreFile, AppendToFile, LoadFile    **
********************************************
 */

type FileNode struct {
	Content []byte
	Next    uuid.UUID
}

type FileMetadata struct {
	Owner string

	FirstFileNode uuid.UUID
}

// Used for file list
func getFileListKeys(sourceKey []byte) (listEncKey []byte, listHashKey []byte, err error) {
	listEncKey, err = userlib.HashKDF(sourceKey, []byte("user-file-list-enc"))
	if err != nil {
		return []byte{}, []byte{}, err
	}
	listHashKey, err = userlib.HashKDF(sourceKey, []byte("user-file-list-hash"))
	if err != nil {
		return []byte{}, []byte{}, err
	}
	return listEncKey[:16], listHashKey[:16], nil // return 16 bytes keys
}

func getFileListByUUID(fileListUUID uuid.UUID, sourceKey []byte) (fileList UserFileList, err error) {
	fileListEncBytes, exist := userlib.DatastoreGet(fileListUUID)
	if !exist {
		return UserFileList{}, errors.New("cannot find file list with UUID: " + fileListUUID.String())
	}

	// Get file list related keys
	fileListEncKey, fileListHashKey, err := getFileListKeys(sourceKey)
	if err != nil {
		return UserFileList{}, err
	}
	fileListBytes, err := verifyAndDecryptData(fileListHashKey, fileListEncKey, fileListEncBytes)
	if err != nil {
		return UserFileList{}, err
	}

	err = json.Unmarshal(fileListBytes, &fileList)
	if err != nil {
		return UserFileList{}, err
	}

	return fileList, nil
}

func storeFileList(fileList UserFileList, sourceKey []byte, listUUID uuid.UUID) (err error) {
	fileListBytes, err := json.Marshal(fileList)
	if err != nil {
		return err
	}
	// Get file list related keys
	fileListEncKey, fileListHashKey, err := getFileListKeys(sourceKey)
	if err != nil {
		return err
	}
	fileListEncBytes, err := encryptData(fileListEncKey, fileListHashKey, fileListBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(listUUID, fileListEncBytes)
	return nil
}

func getMetadataByUUID(metadataUUID uuid.UUID, sourceKey []byte) (metadata FileMetadata, err error) {
	metadataEncBytes, exist := userlib.DatastoreGet(metadataUUID)
	if !exist {
		return FileMetadata{}, errors.New("cannot find file metadata in datastore")
	}
	metaEncKey, metaHashKey, err := getFileNodeKeys(sourceKey, metadataUUID)
	if err != nil {
		return FileMetadata{}, err
	}
	metadataBytes, err := verifyAndDecryptData(metaHashKey, metaEncKey, metadataEncBytes)
	if err != nil {
		return FileMetadata{}, err
	}

	err = json.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		return FileMetadata{}, err
	}
	return metadata, nil
}

func storeMetadata(metadata FileMetadata, sourceKey []byte, metadataUUID uuid.UUID) (err error) {
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	// Encrypt and store newly created metadata
	metaEncKey, metaHashKey, err := getFileNodeKeys(sourceKey, metadataUUID)
	if err != nil {
		return err
	}
	metadataEncBytes, err := encryptData(metaEncKey, metaHashKey, metadataBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(metadataUUID, metadataEncBytes)
	return nil
}

// Used for fileNode & file metadata
func getFileNodeKeys(sourceKey []byte, nodeUUID uuid.UUID) (nodeEncKey []byte, nodeHashKey []byte, err error) {
	nodeHashKey, err = userlib.HashKDF(sourceKey, []byte("ciphertext-hash-"+nodeUUID.String()))
	if err != nil {
		return []byte{}, []byte{}, err
	}
	nodeEncKey, err = userlib.HashKDF(sourceKey, []byte("file-encryption-"+nodeUUID.String()))
	if err != nil {
		return []byte{}, []byte{}, err
	}
	return nodeEncKey[:16], nodeHashKey[:16], nil // Return 16-byte keys
}

func getNodeByUUID(sourceKey []byte, nodeUUID uuid.UUID) (currNode FileNode, err error) {
	// Get nodeBytes
	userlib.DebugMsg("[getNodeByUUID] Getting bytes for fileNode with UUID: %v", nodeUUID)
	nodeStoredBytes, ok := userlib.DatastoreGet(nodeUUID)
	if !ok {
		return FileNode{}, errors.New("cannot find current UUID in datastore: " + nodeUUID.String())
	}

	// Verify and get plaintext of curr fileNode
	userlib.DebugMsg("[getNodeByUUID] Verify and decrypt the filenode with UUID: %v", nodeUUID)
	var nodeHashKey, fileNodeEncKey []byte
	fileNodeEncKey, nodeHashKey, err = getFileNodeKeys(sourceKey, nodeUUID)
	if err != nil {
		return FileNode{}, err
	}

	var nodeBytes []byte
	nodeBytes, err = verifyAndDecryptData(nodeHashKey, fileNodeEncKey, nodeStoredBytes)
	if err != nil {
		return FileNode{}, err
	}

	// Deserialize the bytes
	var currFileNode FileNode
	err = json.Unmarshal(nodeBytes, &currFileNode)
	if err != nil {
		return FileNode{}, err
	}
	userlib.DebugMsg("[getNodeByUUID] Get fileNode with content: %s", currFileNode)

	return currFileNode, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	userlib.DebugMsg("[StoreFile] Get user file list from datastore for user: %v", userdata.Username)
	// Get user file list
	var fileListUUID uuid.UUID
	fileListUUID, err = uuid.FromBytes(userlib.Hash([]byte("file-list-" + userdata.Username))[:16])
	if err != nil {
		return err
	}

	var fileList UserFileList
	fileList, err = getFileListByUUID(fileListUUID, userdata.SourceKey)
	if err != nil {
		return err
	}

	// Encrypt source key for this file
	// 	For shared files, different users have same metadata
	// 	Temporary set to self file source key
	var fileSourceKey []byte
	fileSourceKey, err = userlib.HashKDF(userdata.SourceKey, []byte("file-"+filename))
	if err != nil {
		return err
	}
	fileSourceKey = fileSourceKey[:16]

	// Get node UUID for new node
	var nodeUUID uuid.UUID
	nodeUUID, err = uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return err
	}

	// Get or update file metadata
	metadataUUID, exist := fileList.FileList[filename]
	if !exist { // first created, use self file source key
		userlib.DebugMsg("[StoreFile] Create metadata for new file: %v", filename)
		// Create metadata UUID and update fileList
		metadataUUID, err = uuid.FromBytes(userlib.RandomBytes(16))
		if err != nil {
			return err
		}
		fileList.FileList[filename] = metadataUUID
		fileList.KeyList[filename] = fileSourceKey

		var metadata = FileMetadata{
			Owner:         userdata.Username,
			FirstFileNode: nodeUUID,
		}
		storeMetadata(metadata, fileSourceKey, metadataUUID)

		userlib.DebugMsg("[StoreFile] Store updated user file list to datastore for user: %v", userdata.Username)
		err = storeFileList(fileList, userdata.SourceKey, fileListUUID)
		if err != nil {
			return err
		}
	} else { // metadata already exist
		userlib.DebugMsg("[StoreFile] Get stored metadata for file: %v", filename)

		fileSourceKey, exist = fileList.KeyList[filename]
		if !exist {
			return errors.New("cannot find encrypt source key for file: " + filename)
		}
		var metadata FileMetadata
		metadata, err = getMetadataByUUID(metadataUUID, fileSourceKey)
		if err != nil {
			return err
		}

		userlib.DebugMsg("[StoreFile] Determine the place to store file node")
		nodeUUID = metadata.FirstFileNode // ensure no change of metadata
		// TODO: delete pre stored file nodes
	}

	// Get data to be stored
	userlib.DebugMsg("[StoreFile] Create a fileNode for nodeUUID: %v", nodeUUID)
	var fileNode = FileNode{
		Content: content,
		Next:    uuid.Nil,
	}
	var plainData []byte
	plainData, err = json.Marshal(fileNode)
	if err != nil {
		return err
	}

	// Get file encrypt key and store
	userlib.DebugMsg("[StoreFile] Encrypt data for nodeUUID: %v", nodeUUID)
	fileSourceKey, err = userlib.HashKDF(userdata.SourceKey, []byte("file-"+filename))
	if err != nil {
		return err
	}
	fileSourceKey = fileSourceKey[:16]

	// Serialize and encrypt
	var nodeEncKey, hashKey []byte
	nodeEncKey, hashKey, err = getFileNodeKeys(fileSourceKey, nodeUUID)
	if err != nil {
		return err
	}

	// Get encryption result
	var fileEncRes []byte
	fileEncRes, err = encryptData(nodeEncKey, hashKey, plainData)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(nodeUUID, fileEncRes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	userlib.DebugMsg("[AppendToFile] Get user file list from datastore for user: %v", userdata.Username)
	// Get user file list
	var fileListUUID uuid.UUID
	fileListUUID, err = uuid.FromBytes(userlib.Hash([]byte("file-list-" + userdata.Username))[:16])
	if err != nil {
		return err
	}

	var fileList UserFileList
	fileList, err = getFileListByUUID(fileListUUID, userdata.SourceKey)
	if err != nil {
		return err
	}

	userlib.DebugMsg("[AppendToFile] Get metadata for file: %v", filename)
	// Get encryption source key for file
	var exist bool
	var fileSourceKey []byte
	fileSourceKey, exist = fileList.KeyList[filename]
	if !exist {
		return errors.New("cannot find file encryption source key for file: " + filename)
	}

	// Get encryption bytes and decrypt
	var metadataUUID uuid.UUID
	metadataUUID, exist = fileList.FileList[filename]
	if !exist {
		return errors.New("cannot find file metadata UUID in file list for file: " + filename)
	}

	var metadata FileMetadata
	metadata, err = getMetadataByUUID(metadataUUID, fileSourceKey)
	if err != nil {
		return err
	}

	userlib.DebugMsg("[AppendToFile] Store new file node for file: %v", filename)
	// Data to be stored
	var thisUUID uuid.UUID
	thisUUID, err = uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return err
	}

	userlib.DebugMsg("[AppendToFile] Create and store the new fileNode with nodeUUID: %v", thisUUID)
	var newFileNode = FileNode{
		Content: content,
		Next:    uuid.Nil,
	}
	var plainNodeBytes []byte
	plainNodeBytes, err = json.Marshal(newFileNode)
	if err != nil {
		return err
	}

	// Serialize and encrypt
	var nodeEncKey, hashKey []byte
	nodeEncKey, hashKey, err = getFileNodeKeys(fileSourceKey, thisUUID)
	if err != nil {
		return err
	}

	// Get encryption result and store
	var nodeEncRes []byte
	nodeEncRes, err = encryptData(nodeEncKey, hashKey, plainNodeBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(thisUUID, nodeEncRes)

	// Get UUID of first file node
	userlib.DebugMsg("[AppendToFile] Find first fileNode for file: %v", filename)
	var firstNodeUUID = metadata.FirstFileNode
	if firstNodeUUID == uuid.Nil {
		userlib.DebugMsg("metadata: %v", metadata)
		return errors.New("find first file node to be uuid.Nil in metadata")
	}

	// Get the node to be modified
	userlib.DebugMsg("[AppendToFile] Find last fileNode for file: %v", filename)
	var currNode FileNode
	currNode, err = getNodeByUUID(fileSourceKey, firstNodeUUID)
	if err != nil {
		return err
	}
	var currNodeUUID = firstNodeUUID
	var nextNodeUUID = currNode.Next
	for nextNodeUUID != uuid.Nil {
		currNodeUUID = nextNodeUUID
		currNode, err = getNodeByUUID(fileSourceKey, currNodeUUID)
		if err != nil {
			return err
		}
		nextNodeUUID = currNode.Next
	}

	// Change previous content
	userlib.DebugMsg("[AppendToFile] Change last fileNode content with nodeUUID: %v", currNodeUUID)
	currNode.Next = thisUUID
	plainNodeBytes, err = json.Marshal(currNode)
	if err != nil {
		return err
	}
	// userlib.DebugMsg("[AppendToFile] Change last fileNode to: %v", currNode)
	nodeEncKey, hashKey, err = getFileNodeKeys(fileSourceKey, currNodeUUID)
	if err != nil {
		return err
	}

	nodeEncRes, err = encryptData(nodeEncKey, hashKey, plainNodeBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(currNodeUUID, nodeEncRes)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	userlib.DebugMsg("[LoadFile] Get user file list from datastore for user: %v", userdata.Username)
	// Get user file list
	var fileListUUID uuid.UUID
	fileListUUID, err = uuid.FromBytes(userlib.Hash([]byte("file-list-" + userdata.Username))[:16])
	if err != nil {
		return []byte{}, err
	}

	var fileList UserFileList
	fileList, err = getFileListByUUID(fileListUUID, userdata.SourceKey)
	if err != nil {
		return []byte{}, err
	}

	userlib.DebugMsg("[LoadFile] Get metadata for file: %v", filename)
	// Get encryption source key for file
	var exist bool
	var fileSourceKey []byte
	fileSourceKey, exist = fileList.KeyList[filename]
	if !exist {
		return []byte{}, errors.New("cannot find file encryption source key for file: " + filename)
	}

	// Get encryption bytes and decrypt
	var metadataUUID uuid.UUID
	metadataUUID, exist = fileList.FileList[filename]
	if !exist {
		return []byte{}, errors.New("cannot find file metadata UUID in file list for file: " + filename)
	}

	var metadata FileMetadata
	metadata, err = getMetadataByUUID(metadataUUID, fileSourceKey)
	if err != nil {
		return []byte{}, err
	}

	// Get first node
	var firstNodeUUID = metadata.FirstFileNode
	if firstNodeUUID == uuid.Nil {
		return nil, errors.New("find first file node to be uuid.Nil in metadata")
	}

	// Loop over the nodes
	var currNode FileNode
	var currUUID, nextUUID uuid.UUID
	currUUID = firstNodeUUID
	currNode, err = getNodeByUUID(fileSourceKey, currUUID)
	if err != nil {
		return []byte{}, err
	}
	content = append(content, currNode.Content...)
	nextUUID = currNode.Next
	for nextUUID != uuid.Nil {
		currNode, err = getNodeByUUID(fileSourceKey, nextUUID)
		if err != nil {
			return []byte{}, err
		}
		content = append(content, currNode.Content...)
		nextUUID = currNode.Next
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
