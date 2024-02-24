package test

import (
	"encoding/hex"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/blocktree/gg20-lib-alpha/ecdsa/signing"
	"github.com/blocktree/gg20-lib-alpha/gg20"
	"github.com/blocktree/gg20-lib-alpha/utils"
	"github.com/stretchr/testify/assert"
)

func Test_sign(t *testing.T) {
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := gg20.NewPeerContext(signPIDs)
	parties := make([]*signing.LocalParty, 0, len(signPIDs))

	errCh := make(chan *gg20.Error, len(signPIDs))
	outCh := make(chan gg20.Message, len(signPIDs))
	endCh := make(chan *signing.SignatureData, len(signPIDs))

	updater := sharedPartyUpdater

	// init the parties
	msg := utils.GetRandomPrimeInt(256)
	for i := 0; i < len(signPIDs); i++ {
		params := gg20.NewParameters(p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := signing.NewLocalParty(msg, params, keys[i], outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			utils.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					fmt.Println("From : ", msg.GetFrom(), "   Broadcast !")
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				fmt.Println("From : ", msg.GetFrom(), "   To : ", msg.GetTo())
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case data := <-endCh:
			fmt.Println("Signature result : \n R :", hex.EncodeToString(data.GetSignature().GetR()), "\n S :", hex.EncodeToString(data.GetSignature().GetS()))
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants !", ended)

				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				break signing
			}
		}
	}
}
