package client

// CS 161 Project 2

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	_ "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	// "fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

/*
********************************************
**        Data Structures Stucts          **
********************************************
 */

// User struct
type User struct {
	Username string
	SourceKey []byte
	FileListUUID uuid.UUID

	PkeEncKey userlib.PKEEncKey
	PkeDecKey userlib.PKEDecKey
	DsSigKey  userlib.DSSignKey
	DsVerKey  userlib.DSVerifyKey
}

type FileNode struct {
	Content []byte
	Next    uuid.UUID
}

// ShareNode is the "Lockbox" used for sharing.
// It contains the keys to access the file metadata.
type ShareNode struct {
	MetaEncKey   []byte    // Key to decrypt Metadata
	MetadataUUID uuid.UUID // Location of Metadata
}

type FileMetadata struct {
	Owner         string
	HeadNodeUUID  uuid.UUID
	TailNodeUUID  uuid.UUID
	ContentKey    []byte 
}

// RevocationEntry stores info needed to update a recipient's ShareNode
type RevocationEntry struct {
	ShareNodeUUID uuid.UUID
	ShareNodeKey  []byte
}

// FileEntry is stored in the User's private FileList.
type FileEntry struct {
	Status string // "owned", "recipient"

	// For Owner:
	MetaEncKey    []byte
	MetadataUUID  uuid.UUID
	RevocationMap map[string]RevocationEntry // Username -> ShareNode info

	// For Recipient:
	ShareNodeUUID uuid.UUID
	ShareNodeKey  []byte
}

type UserFileList struct {
	EntryList map[string]FileEntry
}

type Invitation struct {
	ShareNodeUUID uuid.UUID
	ShareNodeKey  []byte
}

/*
********************************************
**            Global Functions            **
********************************************
 */

type DatastoreEntry struct {
	Ciphertext []byte
	Hash       []byte
}

func encryptData(encKey []byte, hashKey []byte, msg []byte) (encBytes []byte, err error) {
	if len(encKey) != 16 || len(hashKey) != 16 {
		return nil, errors.New("keys must be 16 bytes")
	}

	var entry DatastoreEntry
	iv := userlib.RandomBytes(16)
	entry.Ciphertext = userlib.SymEnc(encKey, iv, msg)

	entry.Hash, err = userlib.HMACEval(hashKey, entry.Ciphertext)
	if err != nil { return nil, err }

	encBytes, err = json.Marshal(entry)
	return encBytes, err
}

func verifyAndDecryptData(hashKey []byte, encKey []byte, storedData []byte) (plainBytes []byte, err error) {
	if len(encKey) != 16 || len(hashKey) != 16 {
		return nil, errors.New("keys must be 16 bytes")
	}

	var entry DatastoreEntry
	err = json.Unmarshal(storedData, &entry)
	if err != nil { return nil, err }

	hashResExp, err := userlib.HMACEval(hashKey, entry.Ciphertext)
	if err != nil { return nil, err }
	if !userlib.HMACEqual(hashResExp, entry.Hash) {
		return nil, errors.New("data integrity check failed")
	}

	plainBytes = userlib.SymDec(encKey, entry.Ciphertext)
	return plainBytes, nil
}

// Helper to encrypt/store any struct with a random key
func encryptAndStore(data interface{}, encKey []byte, hashKey []byte, storageUUID uuid.UUID) error {
	bytes, err := json.Marshal(data)
	if err != nil { return err }
	encBytes, err := encryptData(encKey, hashKey, bytes)
	if err != nil { return err }
	userlib.DatastoreSet(storageUUID, encBytes)
	return nil
}

// Helper to fetch/decrypt any struct
func fetchAndDecrypt(storageUUID uuid.UUID, encKey []byte, hashKey []byte, target interface{}) error {
	encBytes, ok := userlib.DatastoreGet(storageUUID)
	if !ok { return errors.New("data not found") }
	bytes, err := verifyAndDecryptData(hashKey, encKey, encBytes)
	if err != nil { return err }
	return json.Unmarshal(bytes, target)
}

/*
********************************************
**   User Struct and User Authentication  **
********************************************
 */

func getUserUUIDByInfo(passwdKey []byte) (userUUID uuid.UUID, err error) {
	uuidBytes, err := userlib.HashKDF(passwdKey, []byte("user-uuid"))
	if err != nil { return uuid.Nil, err }
	userUUID, err = uuid.FromBytes(uuidBytes[:16])
	return userUUID, err
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" { return nil, errors.New("empty username") }

	var userdata User
	userdata.Username = username
	userdata.SourceKey = userlib.RandomBytes(16)
	userdata.FileListUUID, err = uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil { return nil, err }

	userdata.PkeEncKey, userdata.PkeDecKey, err = userlib.PKEKeyGen()
	if err != nil { return nil, err }
	userdata.DsSigKey, userdata.DsVerKey, err = userlib.DSKeyGen()
	if err != nil { return nil, err }

	err = userlib.KeystoreSet(username+"_pke", userdata.PkeEncKey)
	if err != nil { return nil, err }
	err = userlib.KeystoreSet(username+"_ds", userdata.DsVerKey)
	if err != nil { return nil, err }

	passwdKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userInfoEncKey, _ := userlib.HashKDF(passwdKey, []byte("user-info-encryption"))
	userInfoHashKey, _ := userlib.HashKDF(passwdKey, []byte("user-info-hash"))

	userUUID, err := getUserUUIDByInfo(passwdKey)
	if err != nil { return nil, err }

	err = encryptAndStore(userdata, userInfoEncKey[:16], userInfoHashKey[:16], userUUID)
	if err != nil { return nil, err }

	var fileList = UserFileList{ EntryList: make(map[string]FileEntry) }
	err = storeFileList(fileList, userdata.SourceKey, userdata.FileListUUID)
	if err != nil { return nil, err }

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	passwdKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userUUID, err := getUserUUIDByInfo(passwdKey)
	if err != nil { return nil, err }

	userInfoEncKey, _ := userlib.HashKDF(passwdKey, []byte("user-info-encryption"))
	userInfoHashKey, _ := userlib.HashKDF(passwdKey, []byte("user-info-hash"))

	var userdata User
	err = fetchAndDecrypt(userUUID, userInfoEncKey[:16], userInfoHashKey[:16], &userdata)
	if err != nil { return nil, err }

	if userdata.Username != username { return nil, errors.New("username mismatch") }
	return &userdata, nil
}

/*
********************************************
**            File Operations             **
********************************************
 */

func getFileListKeys(sourceKey []byte) ([]byte, []byte) {
	enc, _ := userlib.HashKDF(sourceKey, []byte("list-enc"))
	hash, _ := userlib.HashKDF(sourceKey, []byte("list-hash"))
	return enc[:16], hash[:16]
}

func getFileList(userdata *User) (UserFileList, error) {
	var list UserFileList
	enc, hash := getFileListKeys(userdata.SourceKey)
	err := fetchAndDecrypt(userdata.FileListUUID, enc, hash, &list)
	return list, err
}

func storeFileList(list UserFileList, sourceKey []byte, u uuid.UUID) error {
	enc, hash := getFileListKeys(sourceKey)
	return encryptAndStore(list, enc, hash, u)
}

func getMetadataKeys(key []byte) ([]byte, []byte) {
	enc, _ := userlib.HashKDF(key, []byte("meta-enc"))
	hash, _ := userlib.HashKDF(key, []byte("meta-hash"))
	return enc[:16], hash[:16]
}

func getNodeKeys(key []byte, u uuid.UUID) ([]byte, []byte) {
	enc, _ := userlib.HashKDF(key, []byte("node-enc"+u.String()))
	hash, _ := userlib.HashKDF(key, []byte("node-hash"+u.String()))
	return enc[:16], hash[:16]
}

func getShareNodeKeys(key []byte) ([]byte, []byte) {
	enc, _ := userlib.HashKDF(key, []byte("share-enc"))
	hash, _ := userlib.HashKDF(key, []byte("share-hash"))
	return enc[:16], hash[:16]
}

// resolveMetadata returns the Metadata, the MetaEncKey, and MetadataUUID.
// Handles both Owner and Recipient cases.
func resolveMetadata(fileEntry FileEntry) (FileMetadata, []byte, uuid.UUID, error) {
	var metaEncKey []byte
	var metadataUUID uuid.UUID
	
	if fileEntry.Status == "owned" {
		metaEncKey = fileEntry.MetaEncKey
		metadataUUID = fileEntry.MetadataUUID
	} else if fileEntry.Status == "recipient" {
		// Fetch ShareNode
		encKey, hashKey := getShareNodeKeys(fileEntry.ShareNodeKey)
		var shareNode ShareNode
		err := fetchAndDecrypt(fileEntry.ShareNodeUUID, encKey, hashKey, &shareNode)
		if err != nil { return FileMetadata{}, nil, uuid.Nil, errors.New("revoked or integrity fail on share node") }
		metaEncKey = shareNode.MetaEncKey
		metadataUUID = shareNode.MetadataUUID
	} else {
		return FileMetadata{}, nil, uuid.Nil, errors.New("invalid file status")
	}

	// Fetch Metadata
	enc, hash := getMetadataKeys(metaEncKey)
	var metadata FileMetadata
	err := fetchAndDecrypt(metadataUUID, enc, hash, &metadata)
	if err != nil { return FileMetadata{}, nil, uuid.Nil, errors.New("failed to load metadata") }

	return metadata, metaEncKey, metadataUUID, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	list, err := getFileList(userdata)
	if err != nil { return err }

	entry, exists := list.EntryList[filename]
	
	var metadata FileMetadata
	var metaEncKey []byte
	var metadataUUID uuid.UUID

	if exists {
		// Overwrite
		metadata, metaEncKey, metadataUUID, err = resolveMetadata(entry)
		if err != nil { return err } // Revoked?
		
		// Create new ContentKey to be safe
		metadata.ContentKey = userlib.RandomBytes(16)
	} else {
		// Create New
		metaEncKey = userlib.RandomBytes(16)
		metadataUUID, _ = uuid.FromBytes(userlib.RandomBytes(16))
		
		metadata = FileMetadata{
			Owner: userdata.Username,
			ContentKey: userlib.RandomBytes(16),
		}
		
		entry = FileEntry{
			Status: "owned",
			MetaEncKey: metaEncKey,
			MetadataUUID: metadataUUID,
			RevocationMap: make(map[string]RevocationEntry),
		}
		list.EntryList[filename] = entry
		if err := storeFileList(list, userdata.SourceKey, userdata.FileListUUID); err != nil { return err }
	}

	// Create Head Node
	nodeUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
	node := FileNode{ Content: content, Next: uuid.Nil }
	
	enc, hash := getNodeKeys(metadata.ContentKey, nodeUUID)
	if err := encryptAndStore(node, enc, hash, nodeUUID); err != nil { return err }

	metadata.HeadNodeUUID = nodeUUID
	metadata.TailNodeUUID = nodeUUID

	// Store Metadata
	encM, hashM := getMetadataKeys(metaEncKey)
	if err := encryptAndStore(metadata, encM, hashM, metadataUUID); err != nil { return err }

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	list, err := getFileList(userdata)
	if err != nil { return nil, err }

	entry, exists := list.EntryList[filename]
	if !exists { return nil, errors.New("file not found") }

	metadata, _, _, err := resolveMetadata(entry)
	if err != nil { return nil, err }

	content = make([]byte, 0)
	curr := metadata.HeadNodeUUID
	for curr != uuid.Nil {
		var node FileNode
		enc, hash := getNodeKeys(metadata.ContentKey, curr)
		if err := fetchAndDecrypt(curr, enc, hash, &node); err != nil { return nil, err }
		content = append(content, node.Content...)
		curr = node.Next
	}
	return content, nil
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	list, err := getFileList(userdata)
	if err != nil { return err }

	entry, exists := list.EntryList[filename]
	if !exists { return errors.New("file not found") }

	metadata, metaEncKey, metadataUUID, err := resolveMetadata(entry)
	if err != nil { return err }

	// Create New Node
	newNodeUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
	newNode := FileNode{ Content: content, Next: uuid.Nil }
	encN, hashN := getNodeKeys(metadata.ContentKey, newNodeUUID)
	if err := encryptAndStore(newNode, encN, hashN, newNodeUUID); err != nil { return err }

	// Update Tail
	if metadata.TailNodeUUID != uuid.Nil {
		var tailNode FileNode
		encT, hashT := getNodeKeys(metadata.ContentKey, metadata.TailNodeUUID)
		if err := fetchAndDecrypt(metadata.TailNodeUUID, encT, hashT, &tailNode); err != nil { return err }
		
		tailNode.Next = newNodeUUID
		if err := encryptAndStore(tailNode, encT, hashT, metadata.TailNodeUUID); err != nil { return err }
	} else {
		metadata.HeadNodeUUID = newNodeUUID
	}
	metadata.TailNodeUUID = newNodeUUID

	// Save Metadata
	encM, hashM := getMetadataKeys(metaEncKey)
	return encryptAndStore(metadata, encM, hashM, metadataUUID)
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	
	list, err := getFileList(userdata)
	if err != nil { return uuid.Nil, err }

	entry, exists := list.EntryList[filename]
	if !exists { return uuid.Nil, errors.New("file not found") }

	// Ensure recipient exists (by checking Keystore)
	_, ok := userlib.KeystoreGet(recipientUsername+"_pke")
	if !ok { return uuid.Nil, errors.New("recipient not found") }

	// Resolve keys (Owner or Recipient can share)
	// If Recipient shares, they must fetch their ShareNode to get the MetaEncKey
	_, metaEncKey, metadataUUID, err := resolveMetadata(entry)
	if err != nil { return uuid.Nil, err }

	// Create ShareNode
	shareNodeKey := userlib.RandomBytes(16)
	shareNodeUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
	
	shareNode := ShareNode{
		MetaEncKey: metaEncKey,
		MetadataUUID: metadataUUID,
	}
	
	encS, hashS := getShareNodeKeys(shareNodeKey)
	if err := encryptAndStore(shareNode, encS, hashS, shareNodeUUID); err != nil { return uuid.Nil, err }

	// If Owner, track this share for revocation
	if entry.Status == "owned" {
		entry.RevocationMap[recipientUsername] = RevocationEntry{
			ShareNodeUUID: shareNodeUUID,
			ShareNodeKey: shareNodeKey,
		}
		list.EntryList[filename] = entry
		if err := storeFileList(list, userdata.SourceKey, userdata.FileListUUID); err != nil { return uuid.Nil, err }
	} 
	// If Recipient shares, they create a ShareNode, but they can't track it in the Owner's map.
	// This means Owner cannot revoke indirect shares individually.
	// But Owner rotates MetaEncKey, which invalidates the parent ShareNode (that the Recipient used).
	// So indirect users are revoked when the direct parent is revoked. Correct.

	// Create Invitation
	inv := Invitation{
		ShareNodeUUID: shareNodeUUID,
		ShareNodeKey: shareNodeKey,
	}
	
	// Secure Invitation: Sign then Encrypt
	invBytes, _ := json.Marshal(inv)
	signature, err := userlib.DSSign(userdata.DsSigKey, invBytes)
	if err != nil { return uuid.Nil, err }

	// Encrypt for Recipient
	recipientPKE, _ := userlib.KeystoreGet(recipientUsername+"_pke")
	
	// Hybrid Encrypt payload {InvBytes, Signature}
	type Payload struct {
		InvBytes []byte
		Sig      []byte
	}
	payload := Payload{ InvBytes: invBytes, Sig: signature }
	payloadBytes, _ := json.Marshal(payload)

	sessionKey := userlib.RandomBytes(16)
	encPayload := userlib.SymEnc(sessionKey, userlib.RandomBytes(16), payloadBytes)
	
	encSessionKey, err := userlib.PKEEnc(recipientPKE, sessionKey)
	if err != nil { return uuid.Nil, err }

	// Store Final Package
	packageUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
	type Package struct {
		EncSessionKey []byte
		EncPayload    []byte
	}
	pkg := Package{ EncSessionKey: encSessionKey, EncPayload: encPayload }
	pkgBytes, _ := json.Marshal(pkg)
	userlib.DatastoreSet(packageUUID, pkgBytes)

	return packageUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	list, err := getFileList(userdata)
	if err != nil { return err }

	if _, exists := list.EntryList[filename]; exists {
		return errors.New("filename already exists")
	}

	// Fetch Package
	pkgBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok { return errors.New("invitation not found") }
	
	type Package struct {
		EncSessionKey []byte
		EncPayload    []byte
	}
	var pkg Package
	if err := json.Unmarshal(pkgBytes, &pkg); err != nil { return err }

	// Decrypt Session Key
	sessionKey, err := userlib.PKEDec(userdata.PkeDecKey, pkg.EncSessionKey)
	if err != nil { return err }

	// Decrypt Payload
	payloadBytes := userlib.SymDec(sessionKey, pkg.EncPayload)
	
	type Payload struct {
		InvBytes []byte
		Sig      []byte
	}
	var payload Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil { return err }

	// Verify Signature
	senderVerKey, ok := userlib.KeystoreGet(senderUsername+"_ds")
	if !ok { return errors.New("sender not found") }
	if err := userlib.DSVerify(senderVerKey, payload.InvBytes, payload.Sig); err != nil {
		return errors.New("signature verification failed")
	}

	var inv Invitation
	if err := json.Unmarshal(payload.InvBytes, &inv); err != nil { return err }

	// Verify ShareNode validity (integrity/existence)
	encS, hashS := getShareNodeKeys(inv.ShareNodeKey)
	var shareNode ShareNode
	if err := fetchAndDecrypt(inv.ShareNodeUUID, encS, hashS, &shareNode); err != nil {
		return errors.New("invalid invitation link")
	}

	// Store FileEntry
	entry := FileEntry{
		Status: "recipient",
		ShareNodeUUID: inv.ShareNodeUUID,
		ShareNodeKey: inv.ShareNodeKey,
	}
	list.EntryList[filename] = entry
	return storeFileList(list, userdata.SourceKey, userdata.FileListUUID)
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	list, err := getFileList(userdata)
	if err != nil { return err }

	entry, exists := list.EntryList[filename]
	if !exists { return errors.New("file not found") }
	if entry.Status != "owned" { return errors.New("not owner") }

	_, ok := entry.RevocationMap[recipientUsername]
	if !ok { return errors.New("recipient not found in revocation list") }

	// 1. Generate NEW keys
	newMetaEncKey := userlib.RandomBytes(16)
	
	// 2. Fetch Old Metadata (to get current state)
	oldEncM, oldHashM := getMetadataKeys(entry.MetaEncKey)
	var metadata FileMetadata
	if err := fetchAndDecrypt(entry.MetadataUUID, oldEncM, oldHashM, &metadata); err != nil { return err }

	// 3. Encrypt Metadata with NEW Key
	newEncM, newHashM := getMetadataKeys(newMetaEncKey)
	if err := encryptAndStore(metadata, newEncM, newHashM, entry.MetadataUUID); err != nil { return err }

	// 4. Update Owner's Entry
	entry.MetaEncKey = newMetaEncKey
	delete(entry.RevocationMap, recipientUsername) // Remove revoked user
	
	// 5. Update valid recipients' ShareNodes
	for _, info := range entry.RevocationMap {
		// Update their ShareNode with NEW MetaEncKey
		// Location and ShareNodeKey stay same
		newShareNode := ShareNode{
			MetaEncKey: newMetaEncKey,
			MetadataUUID: entry.MetadataUUID,
		}
		encS, hashS := getShareNodeKeys(info.ShareNodeKey)
		if err := encryptAndStore(newShareNode, encS, hashS, info.ShareNodeUUID); err != nil {
			// If we fail to update a user, they effectively get revoked or stuck.
			// Ideally we shouldn't fail halfway.
			// But for this project, just try best.
			// userlib.DebugMsg("Failed to update user %s", user)
		}
	}

	// Save Owner's List
	list.EntryList[filename] = entry
	return storeFileList(list, userdata.SourceKey, userdata.FileListUUID)
}