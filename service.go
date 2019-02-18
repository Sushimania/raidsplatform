package main

import (
	"encoding/json"
	"fmt"
	"github.com/dchest/blake2b"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	difficulty = 5
	blockReward = 100.0
)

func getAuthToken(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	// ----------------------------- Post 확인 -----------------------------
	decoder := json.NewDecoder(r.Body)
	var authToken AuthToken
	err := decoder.Decode(&authToken)
	if err != nil {
		LogicException(ctx, w, err, http.StatusInternalServerError)
		return
	}

	if authToken.EosAccountName == "" || authToken.MachineId == "" {
		LogicException(ctx, w, fmt.Errorf("InvalidOrMissing"), http.StatusUnauthorized)
		return
	}

	// ----------------------------- 토큰 생성 -----------------------------
	xAuthToken := CreateToken(authToken.EosAccountName, authToken.MachineId)

	// ----------------------------- 클라이언트에 응답 -----------------------------
	type AuthTokenResponse struct {
		XAuthToken string
	}
	authTokenResponse := AuthTokenResponse{}
	authTokenResponse.XAuthToken = xAuthToken
	resultJson, err := json.Marshal(authTokenResponse)
	if err != nil {
		LogicException(ctx, w, err, http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, string(resultJson))
}

func submitPow(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	// 토큰 검증
	tokenFlag, eosAccountName := ValidateToken(r.Header.Get("X-Auth-Token"))
	if !tokenFlag {
		LogicException(ctx, w, fmt.Errorf("AuthTokenWasInvalid"), http.StatusUnauthorized)
		return
	} else {
		log.Infof(ctx, "token access: %v", eosAccountName)
	}

	// ----------------------------- Post 확인 -----------------------------
	decoder := json.NewDecoder(r.Body)
	var submitPow SubmitPow
	err := decoder.Decode(&submitPow)
	if err != nil {
		LogicException(ctx, w, err, http.StatusInternalServerError)
		return
	}

	blockParams := BlockParams{}

	// 이미 찾은 nonce 값인가?(기존에 찾은 Nonce 값은 보상을 지급하지 않는다)
	q2 := datastore.NewQuery("Block").Filter("Nonce =", submitPow.Nonce)
	if _, err := q2.GetAll(ctx, &blockParams.Blocks); err != nil {
		LogicException(ctx, w, err, http.StatusInternalServerError)
		return
	}

	// 이미 찾은 nonce 값인가?
	if blockParams.Blocks != nil {
		LogicException(ctx, w, fmt.Errorf("DuplicateNonce"), http.StatusInternalServerError)
		return
	}

	//// submitPow.Nonce 복호화 하기
	//decrypted, err := Decrypt([]byte(properties.RAIDERS_MESSAGE_KEY), submitPow.Nonce)
	//if err != nil {
	//	LogicException(ctx, w, err, http.StatusInternalServerError)
	//	return
	//}

	// private key 가 비트코인 개인키가 맞는지 검증
	wif, err := ImportWIF(submitPow.Nonce)
	if err != nil {
		LogicException(ctx, w, fmt.Errorf("InvalidNonce_Wif"), http.StatusInternalServerError)
		return
	}

	if submitPow.Nonce != wif.String() {
		LogicException(ctx, w, fmt.Errorf("InvalidNonce_Wif"), http.StatusInternalServerError)
		return
	}

	// 난이도 확인
	difficultyPrefix := ""
	for i := 0; i < difficulty; i++ {
		difficultyPrefix += "0"
	}

	// blake2b 로 해싱했을때 현재 난이도에 맞는 결과가 나오는지 확인
	h := blake2b.New256()
	h.Write([]byte(submitPow.Nonce + BLAKE2B_SALT))
	hashResult := fmt.Sprintf("%x", h.Sum(nil))

	if !strings.HasPrefix(hashResult, difficultyPrefix) {
		LogicException(ctx, w, fmt.Errorf("InvalidNonce_Hash"), http.StatusInternalServerError)
		return
	}

	// 가장 최신 블록의 height 값 가져오기
	q2 = datastore.NewQuery("Block").Order("-Timestamp").Limit(1)
	if _, err := q2.GetAll(ctx, &blockParams.Blocks); err != nil {
		LogicException(ctx, w, err, http.StatusInternalServerError)
		return
	}

	// ----------------------------- 새 블록 -----------------------------
	block := Block{}

	if blockParams.Blocks == nil {
		// 제네시스 블록
		block.Height = 1
	} else {
		block.Height = blockParams.Blocks[0].Height + 1
	}

	// hmac
	// from + to + quantity + memo
	//tempHmac := hashMAC(sendToAddress.ToAddress + strconv.FormatFloat(sendToAddress.Amount, 'f', 0, 64) + strconv.Itoa(sendToAddress.Timestamp), raidAddressParams.RaidAddresses[0].PrivateKey)
	//fmt.Fprint(w, tempHmac)
	//return
	message := "eosraidscoin" + eosAccountName + fmt.Sprintf("%.4f", blockReward) +" RAIDS" + "Block Height " + strconv.FormatInt(block.Height, 10) + ", Hash " + hashResult
	hmac := hashMAC(message, EOS_HMAC_SECURE_KEY)

	log.Infof(ctx, "message: %v", message)
	log.Infof(ctx, "hmac: %v", hmac)

	// ----------------------------- 검증이 완료됐으면 eosAccountName 으로 RAIDS 보상 지급 -----------------------------
	client := urlfetch.Client(ctx)
	url := EOS_NODEJS_SERVER_URL + "/issue"
	payload := strings.NewReader("{\n\t\"from\" : \"eosraidscoin\",\n\t\"to\" : \"" + eosAccountName + "\",\n\t\"quantity\" : \"" + fmt.Sprintf("%.4f", blockReward) + " RAIDS\",\n\t\"memo\" : \"Block Height " + strconv.FormatInt(block.Height, 10) + ", Hash " + hashResult + "\",\n\t\"hmac\" : \"" + hmac + "\"\n}")
	req, _ := http.NewRequest("POST", url, payload)
	req.Header.Add("Content-Type", "application/json")
	res, _ := client.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	log.Infof(ctx, "%v", string(body))

	var issueResponse IssueResponse
	_ = json.Unmarshal(body, &issueResponse)

	//if !issueResponse.Broadcast {
	//	LogicException(ctx, w, fmt.Errorf("BroadcastError"), http.StatusInternalServerError)
	//	return
	//}

	// ----------------------------- 블록 정보 저장 -----------------------------
	block.Nonce = submitPow.Nonce
	block.Timestamp = int(time.Now().Unix())
	block.RelayedBy = eosAccountName
	if !issueResponse.Broadcast {
		block.BlockReward = 0	// EOS 오류로 리워드가 지급 안된 경우
	} else {
		block.BlockReward = blockReward
	}
	block.Difficulty = difficulty
	block.HashResult = hashResult

	// DB에 저장
	requestKey := datastore.NewKey(ctx, "Block", strconv.FormatInt(block.Height, 10), 0, nil)
	if _, err := datastore.Put(ctx, requestKey, &block); err != nil {
		LogicException(ctx, w, err, http.StatusInternalServerError)
		return
	}

	block.Nonce = ""

	// ----------------------------- 클라이언트에 응답 -----------------------------
	resultJson, err := json.Marshal(block)
	if err != nil {
		LogicException(ctx, w, err, http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, string(resultJson))
}

// [cron] 10분마다 expire 된 hashrate 값 삭제하기
func deleteExpireHashrate(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	nowTimestamp := int(time.Now().Unix())

	hashrateParams := HashrateParams{}

	q := datastore.NewQuery("Hashrate")
	if _, err := q.GetAll(ctx, &hashrateParams.Hashrates); err != nil {
		LogicException(ctx, w, err, http.StatusInternalServerError)
		return
	}

	var keysUser []*datastore.Key
	for i := 0; i < len(hashrateParams.Hashrates); i++ {
		// 10분이 지난 데이터인가?
		if hashrateParams.Hashrates[i].Timestamp + 3600 >= nowTimestamp {
			continue
		}

		// 10분이 지났다
		// 업데이트할 유저 키 보관
		keysUser = append(keysUser, datastore.NewKey(ctx, "Hashrate", hashrateParams.Hashrates[i].DeviceId, 0, nil))
	}
	log.Infof(ctx, "keysUser: %v", keysUser)
	// delete 실행
	err := datastore.DeleteMulti(ctx, keysUser)
	if err != nil {
		LogicException(ctx, w, err, http.StatusInternalServerError)
		return
	}
}
