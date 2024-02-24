package test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/blocktree/gg20-lib-alpha/ecdsa/keygen"
	"github.com/blocktree/gg20-lib-alpha/gg20"
	"github.com/stretchr/testify/assert"

	"github.com/ipfs/go-log"
)

func setUp(level string) {
	if err := log.SetLogLevel("gg20-lib", level); err != nil {
		panic(err)
	}
}

func Test_2_of_3_key_generation(t *testing.T) {

	setUp("fatal")

	// step 0
	// 确定参与方数量与门限值，并将相关信息进行分发
	// 门限值
	threshold := 2
	// 参与方 ID
	ID_0, _ := hex.DecodeString("70c7b2ed9ba7a8b261fc6f784d22ed0cb25cee6d1415225f49929c411e2da162")
	ID_1, _ := hex.DecodeString("7169251bcf59ff6eeb29456a58e8b4a5e4e9ebc69c89a13b0129e8963e1e6e6d")
	ID_2, _ := hex.DecodeString("72ff14c18ce296ca010eee6b946363dbfa9d7a170e987e785e52ca46cc9b84c6")

	// 将上述信息分发给所有参与方

	// step 1

	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-0

	// 构建参数
	P0_pIDs := gg20.GeneratePartyIDs([][]byte{ID_0, ID_1, ID_2})
	P0_outCh := make(chan gg20.Message, len(P0_pIDs))
	P0_endCh := make(chan keygen.LocalPartySaveData, len(P0_pIDs))
	P0_p2pCtx := gg20.NewPeerContext(P0_pIDs)
	var P0_local *keygen.LocalParty
	P0_params := gg20.NewParameters(P0_p2pCtx, P0_pIDs[0], len(P0_pIDs), threshold)

	P0_local = keygen.NewLocalParty(P0_params, P0_outCh, P0_endCh).(*keygen.LocalParty)

	// 参与方-0 第1轮计算
	P0_local.Start()

	// 参与方-0 对第1轮计算结果进行分发
	fmt.Println("参与方-0  :  Round 1 !")
	tmp := <-P0_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}

	tmp_bytes, _, _ := tmp.WireBytes()
	// 接收方将接收的数据恢复成ParsedMessage，为方便测试，此处直接完成转换
	P0r1msg, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	//
	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-1

	// 构建参数
	P1_pIDs := gg20.GeneratePartyIDs([][]byte{ID_0, ID_1, ID_2})
	P1_outCh := make(chan gg20.Message, len(P1_pIDs))
	P1_endCh := make(chan keygen.LocalPartySaveData, len(P1_pIDs))
	P1_p2pCtx := gg20.NewPeerContext(P1_pIDs)
	var P1_local *keygen.LocalParty
	P1_params := gg20.NewParameters(P1_p2pCtx, P1_pIDs[1], len(P1_pIDs), threshold)
	P1_local = keygen.NewLocalParty(P1_params, P1_outCh, P1_endCh).(*keygen.LocalParty)

	// 参与方-1 第1轮计算
	P1_local.Start()

	// 参与方-1 对第1轮计算结果进行分发
	fmt.Println("参与方-1  :  Round 1 !")
	tmp = <-P1_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}

	tmp_bytes, _, _ = tmp.WireBytes()
	// 接收方将接收的数据恢复成ParsedMessage，为方便测试，此处直接完成转换
	P1r1msg, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	//
	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-2

	// 构建参数
	P2_pIDs := gg20.GeneratePartyIDs([][]byte{ID_0, ID_1, ID_2})
	P2_outCh := make(chan gg20.Message, len(P2_pIDs))
	P2_endCh := make(chan keygen.LocalPartySaveData, len(P2_pIDs))
	P2_p2pCtx := gg20.NewPeerContext(P2_pIDs)
	var P2_local *keygen.LocalParty
	P2_params := gg20.NewParameters(P2_p2pCtx, P2_pIDs[2], len(P2_pIDs), threshold)
	P2_local = keygen.NewLocalParty(P2_params, P2_outCh, P2_endCh).(*keygen.LocalParty)

	// 参与方-2 第1轮计算
	P2_local.Start()

	// 参与方-2 对第1轮计算结果进行分发
	fmt.Println("参与方-2  :  Round 1 !")
	tmp = <-P2_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}

	tmp_bytes, _, _ = tmp.WireBytes()
	// 接收方将接收的数据恢复成ParsedMessage，为方便测试，此处直接完成转换
	P2r1msg, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	// step 2

	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-0

	// 接收来自其他参与方的首轮消息，并完成计算
	P0_local.Update(P1r1msg)
	P0_local.Update(P2r1msg)

	// 对本轮消息进行分发
	fmt.Println("参与方-0  :  Round 2 !")

	tmp = <-P0_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P0r2msg1, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	tmp = <-P0_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P0r2msg2, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	tmp = <-P0_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P0r2msg3, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	//
	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-1

	// 接收来自其他参与方的首轮消息，并完成计算
	P1_local.Update(P0r1msg)
	P1_local.Update(P2r1msg)

	// 对本轮消息进行分发
	fmt.Println("参与方-1  :  Round 2 !")

	tmp = <-P1_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P1r2msg1, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	tmp = <-P1_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P1r2msg2, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	tmp = <-P1_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P1r2msg3, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	//
	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-2

	// 接收来自其他参与方的首轮消息，并完成计算
	P2_local.Update(P0r1msg)
	P2_local.Update(P1r1msg)

	// 对本轮消息进行分发
	fmt.Println("参与方-2  :  Round 2 !")

	tmp = <-P2_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P2r2msg1, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	tmp = <-P2_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P2r2msg2, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	tmp = <-P2_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P2r2msg3, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	// step 3

	//
	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-0

	// 接收其他参与方的第二轮计算结果，并完成本轮计算
	P0_local.Update(P1r2msg1)
	P0_local.Update(P1r2msg3)
	P0_local.Update(P2r2msg1)
	P0_local.Update(P2r2msg3)

	// 本轮结果分发
	fmt.Println("参与方-0  :  Round 3 !")
	tmp = <-P0_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P0r3msg, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	//
	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-1

	// 接收其他参与方的第二轮计算结果，并完成本轮计算
	P1_local.Update(P0r2msg1)
	P1_local.Update(P0r2msg3)
	P1_local.Update(P2r2msg2)
	P1_local.Update(P2r2msg3)

	// 本轮结果分发
	fmt.Println("参与方-1  :  Round 3 !")
	tmp = <-P1_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P1r3msg, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	//
	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-2

	// 接收其他参与方的第二轮计算结果，并完成本轮计算
	P2_local.Update(P0r2msg2)
	P2_local.Update(P0r2msg3)
	P2_local.Update(P1r2msg2)
	P2_local.Update(P1r2msg3)

	// 本轮结果分发
	fmt.Println("参与方-2  :  Round 3 !")
	tmp = <-P2_outCh
	// 通过GetFrom()方法查看消息的发送方
	fmt.Println("Message from : ", tmp.GetFrom())
	if tmp.IsBroadcast() {
		// 判断是否为broadcast消息， 如果是，将该消息发送给其他所有的参与方
		fmt.Println("Broadcast!")
	} else {
		// 如果不是broadcast消息， 则将该消息发送给指定的接收方
		fmt.Println("Message to : ", tmp.GetTo())
	}
	tmp_bytes, _, _ = tmp.WireBytes()
	P2r3msg, _ := gg20.ParseWireMessage(tmp_bytes, tmp.GetFrom(), tmp.IsBroadcast())

	// step 4

	//
	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-0

	// 接收其他参与方的第3轮计算结果，并完成本轮计算
	P0_local.Update(P1r3msg)
	P0_local.Update(P2r3msg)

	// 完成计算后，获得最终结果并保存
	P0_save := <-P0_endCh
	fmt.Println("参与方-0 最终派生的公钥为 : \n", hex.EncodeToString(P0_save.ECDSAPub.Bytes()))
	P0_index, _ := P0_save.OriginalIndex()
	tryWriteTestFixtureFile(t, P0_index, P0_save)

	//
	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-1

	// 接收其他参与方的第3轮计算结果，并完成本轮计算
	P1_local.Update(P0r3msg)
	P1_local.Update(P2r3msg)

	// 完成计算后，获得最终结果并保存
	P1_save := <-P1_endCh
	fmt.Println("参与方-1 最终派生的公钥为 : \n", hex.EncodeToString(P1_save.ECDSAPub.Bytes()))
	P1_index, _ := P1_save.OriginalIndex()
	tryWriteTestFixtureFile(t, P1_index, P1_save)

	//
	//⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎⬇︎
	//                        参与方-2

	// 接收其他参与方的第3轮计算结果，并完成本轮计算
	P2_local.Update(P0r3msg)
	P2_local.Update(P1r3msg)

	// 完成计算后，获得最终结果并保存
	P2_save := <-P2_endCh
	fmt.Println("参与方-2 最终派生的公钥为 : \n", hex.EncodeToString(P2_save.ECDSAPub.Bytes()))
	P2_index, _ := P2_save.OriginalIndex()
	tryWriteTestFixtureFile(t, P2_index, P2_save)

	assert.Equal(t, P0_save.ECDSAPub.Bytes(), P1_save.ECDSAPub.Bytes())
	assert.Equal(t, P0_save.ECDSAPub.Bytes(), P2_save.ECDSAPub.Bytes())

	fmt.Println("FINISH!")

}
