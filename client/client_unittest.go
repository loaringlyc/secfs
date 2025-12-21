package client

import (
	"testing"
	userlib "github.com/cs161-staff/project2-userlib"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Unit Tests")
}

var _ = Describe("Client Unit Tests", func() {

	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Phase 1 & 2: Auth and Basic Files", func() {
		Specify("Should allow store and load", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			content := []byte("hello world")
			err = alice.StoreFile("file1", content)
			Expect(err).To(BeNil())

			loadedContent, err := alice.LoadFile("file1")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(content))
		})

		Specify("Should allow overwrite", func() {
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			err = alice.StoreFile("file1", []byte("version 1"))
			Expect(err).To(BeNil())

			err = alice.StoreFile("file1", []byte("version 2"))
			Expect(err).To(BeNil())

			loadedContent, err := alice.LoadFile("file1")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal([]byte("version 2")))
		})

		Specify("Should allow append", func() {
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			err = alice.StoreFile("file1", []byte("part 1"))
			Expect(err).To(BeNil())

			err = alice.AppendToFile("file1", []byte(" part 2"))
			Expect(err).To(BeNil())

			loadedContent, err := alice.LoadFile("file1")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal([]byte("part 1 part 2")))
		})

		Specify("Should handle multiple files", func() {
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			err = alice.StoreFile("fileA", []byte("A"))
			Expect(err).To(BeNil())
			err = alice.StoreFile("fileB", []byte("B"))
			Expect(err).To(BeNil())

			valA, err := alice.LoadFile("fileA")
			Expect(err).To(BeNil())
			Expect(valA).To(Equal([]byte("A")))

			valB, err := alice.LoadFile("fileB")
			Expect(err).To(BeNil())
			Expect(valB).To(Equal([]byte("B")))
		})

		Specify("Should persist across logins", func() {
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())
			err = alice.StoreFile("file1", []byte("secret"))
			Expect(err).To(BeNil())

			// Simulate logout/login
			alice2, err := GetUser("alice", "password")
			Expect(err).To(BeNil())

			val, err := alice2.LoadFile("file1")
			Expect(err).To(BeNil())
			Expect(val).To(Equal([]byte("secret")))
		})
	})
})
