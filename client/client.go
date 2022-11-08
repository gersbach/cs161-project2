package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

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

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	Password string
	Files map[string]userlib.UUID
	FilesByOriginalName map[string]string
	OwnerByFile map[string]string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	Content []byte
	Owner string
	Collaborators []string
	CollaboratorsByInviter map[string]string
	Invited []userlib.UUID
	Data string
}

type Invitation struct {
	Sender string
	IntendedRecipient string
	Filename string
	OriginalOwner string
	File userlib.UUID
}

// NOTE: The following methods have toy (insecure!) implementations.

func NewUser() *User {
	var user User
	user.OwnerByFile = make(map[string]string)
	user.FilesByOriginalName = make(map[string]string)
	user.Files = make(map[string]userlib.UUID)
	return &user
}

func NewFile() *File {
	var file File
	file.CollaboratorsByInviter = make(map[string]string)
	return &file
}

func getUserHash(username string) userlib.UUID {
	return createUserUUID(username)
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User = *NewUser()
	prevUUID := createUserUUID(username)
	_, ok := userlib.DatastoreGet(prevUUID)
	if ok != false {
		return nil, nil
	} 
	userdata.Username = username
	userdata.Password = password
	newUserID := createUserUUID(username)
	data, _ := json.Marshal(userdata)
	userlib.DatastoreSet(newUserID, data)
	return &userdata, nil
}

func createUserUUID(username string) userlib.UUID {
	prevUserHash := userlib.Hash([]byte(username))
	deterministicUUID, _ := uuid.FromBytes(prevUserHash[:16])
	return deterministicUUID
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	prevUUID := createUserUUID(username)
	data, ok := userlib.DatastoreGet(prevUUID)
	if ok == false {
		return nil, nil
	} 
	var userData User
	json.Unmarshal(data, &userData)
	if userData.Password != password {
		return nil, nil
	}
	return &userData, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	userdata, _ = GetUser(userdata.Username, userdata.Password)
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	userdata.Files[filename] = storageKey
	var newFile File = *NewFile()
	newFile.Content = content
	newFile.Owner = userdata.Username
	newFile.Collaborators = append(newFile.Collaborators, userdata.Username)
	userdata.OwnerByFile[filename] = userdata.Username
	userdata.FilesByOriginalName[filename] = filename
	userdata.Files[filename] = storageKey 
	contentBytes, err := json.Marshal(newFile)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	newUserData, _ := json.Marshal(userdata)
	userlib.DatastoreSet(getUserHash(userdata.Username), newUserData)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	userdata, _ = GetUser(userdata.Username, userdata.Password)
	fileOwnerName := userdata.OwnerByFile[filename]
	if fileOwnerName == "" {
		fileOwnerName = userdata.Username
	}
	realFileName := userdata.FilesByOriginalName[filename]
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(realFileName + fileOwnerName))[:16])
	if err != nil {
		return err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return errors.New(strings.ToTitle("File not found"))
	}
	var fileData File
	err = json.Unmarshal(dataJSON, &fileData)
	fileData.Content = append(fileData.Content, content...)
	if !contains(fileData.Collaborators, userdata.Username) {
		return errors.New(strings.ToTitle("Not authorized"))
	}
	contentBytes, err := json.Marshal(fileData)
	userlib.DatastoreSet(storageKey, contentBytes)
	newUserData, _ := json.Marshal(userdata)
	userlib.DatastoreSet(getUserHash(userdata.Username), newUserData)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	userdata, _ = GetUser(userdata.Username, userdata.Password)
	fileOwnerName := userdata.OwnerByFile[filename]
	if fileOwnerName == "" {
		fileOwnerName = userdata.Username
	}
	realFileName := userdata.FilesByOriginalName[filename]
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(realFileName + fileOwnerName))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	var foundFile File
	err = json.Unmarshal(dataJSON, &foundFile)
	content = foundFile.Content
	if !contains(foundFile.Collaborators, userdata.Username) {
		return nil, errors.New(strings.ToTitle("Not authorized"))
	}
	newUserData, _ := json.Marshal(userdata)
	userlib.DatastoreSet(getUserHash(userdata.Username), newUserData)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	userdata, _ = GetUser(userdata.Username, userdata.Password)
	userdataJSON, _ := userlib.DatastoreGet(createUserUUID(userdata.Username))
	json.Unmarshal(userdataJSON, &userdata)
	fileOwner := userdata.OwnerByFile[filename]
	realFileName := userdata.FilesByOriginalName[filename]
	filekey := userdata.Files[filename]

	fmt.Println(userdata.Files)
	var newInvitation Invitation
	newInvitation.Sender = userdata.Username
	newInvitation.IntendedRecipient = recipientUsername
	newInvitation.File = filekey
	newInvitation.OriginalOwner = fileOwner
	newInvitation.Filename = realFileName
	invitationKey, _ := uuid.FromBytes(userlib.Hash([]byte(newInvitation.Sender + newInvitation.IntendedRecipient + filename))[:16])
	data, _ := json.Marshal(newInvitation)
	userlib.DatastoreSet(invitationKey, data)
	newUserData, _ := json.Marshal(userdata)
	userlib.DatastoreSet(getUserHash(userdata.Username), newUserData)
	return invitationKey, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	userdata, _ = GetUser(userdata.Username, userdata.Password)
	dataJSON, _ := userlib.DatastoreGet(invitationPtr)
	var invitation Invitation 
	json.Unmarshal(dataJSON, &invitation)
	filekey := invitation.File
	userdata.Files[filename] = filekey
	userdata.FilesByOriginalName[filename] = invitation.Filename
	// need to set the owner by file to the original owner
	data, ok := userlib.DatastoreGet(filekey)
	if !ok {
		return errors.New(strings.ToTitle("Error Occured"))	
	}
	var selectedFile File
	json.Unmarshal(data, &selectedFile)
	selectedFile.Collaborators = append(selectedFile.Collaborators, userdata.Username)
	selectedFile.CollaboratorsByInviter[userdata.Username] = senderUsername
	userdata.OwnerByFile[filename] = selectedFile.Owner
	contentBytes, _ := json.Marshal(selectedFile)
	userlib.DatastoreSet(filekey, contentBytes)
	newUserData, _ := json.Marshal(userdata)
	userlib.DatastoreSet(getUserHash(userdata.Username), newUserData)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	userdata, _ = GetUser(userdata.Username, userdata.Password)
	fileOwner := userdata.OwnerByFile[filename]
	if fileOwner == "" {
		fileOwner = userdata.Username
	}
	realFileName := userdata.FilesByOriginalName[filename]
	filekey, _ := uuid.FromBytes(userlib.Hash([]byte(realFileName + fileOwner))[:16])
	data, ok := userlib.DatastoreGet(filekey)
	if !ok {
		return errors.New(strings.ToTitle("Error Occured"))	
	}
	var selectedFile File
	json.Unmarshal(data, &selectedFile)
	for i, s := range selectedFile.Collaborators {
		if s == recipientUsername {
			selectedFile.Collaborators = append(selectedFile.Collaborators[:i], selectedFile.Collaborators[i+1:]...)
		}
	} 
	var toBeRemoved []string
	toBeRemoved = append(toBeRemoved, recipientUsername)
	for len(toBeRemoved) > 0 {
		for i, s := range selectedFile.Collaborators {
			if selectedFile.CollaboratorsByInviter[s] == toBeRemoved[0] {
				toBeRemoved = append(toBeRemoved, s)
				selectedFile.Collaborators = append(selectedFile.Collaborators[:i], selectedFile.Collaborators[i+1:]...)
			}
		}
		toBeRemoved = toBeRemoved[1:]
	}
	contentBytes, _ := json.Marshal(selectedFile)
	userlib.DatastoreSet(filekey, contentBytes)
	newUserData, _ := json.Marshal(userdata)
	userlib.DatastoreSet(getUserHash(userdata.Username), newUserData)
	return nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}