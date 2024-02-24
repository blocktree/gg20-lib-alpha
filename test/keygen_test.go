package test

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/blocktree/gg20-lib-alpha/ecdsa/keygen"
	"github.com/blocktree/gg20-lib-alpha/gg20"
	"github.com/blocktree/gg20-lib-alpha/utils"
	"github.com/stretchr/testify/assert"
)

func Test_genkey(t *testing.T) {
	setUp("fatal")

	threshold := testThreshold
	pIDs := gg20.GenerateTestPartyIDs(testParticipants)

	p2pCtx := gg20.NewPeerContext(pIDs)
	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	errCh := make(chan *gg20.Error, len(pIDs))
	outCh := make(chan gg20.Message, len(pIDs))
	endCh := make(chan keygen.LocalPartySaveData, len(pIDs))

	updater := sharedPartyUpdater

	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *keygen.LocalParty
		params := gg20.NewParameters(p2pCtx, pIDs[i], len(pIDs), threshold)

		P = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)

		parties = append(parties, P)
		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			utils.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					fmt.Println("---------- : ", msg.GetFrom().Index, " broadcast!")
					fmt.Println("----", msg.String(), "----")
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				fmt.Println("---------- : ", "From: ", msg.GetFrom().Index, " to: ", dest[0].Index)
				fmt.Println("----", msg.String(), "----")
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, index, save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)
				// for i := range data {
				// 	data[i] = byte(i)
				// }
				// r, s, err := ecdsa.Sign(rand.Reader, &sk, data)
				// assert.NoError(t, err, "sign should not throw an error")
				// ok := ecdsa.Verify(&pk, data, r, s)
				// assert.True(t, ok, "signature should be ok")
				// t.Log("ECDSA signing test done.")

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}
