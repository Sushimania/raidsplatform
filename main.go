package main

import (
	"github.com/gorilla/mux"
	"google.golang.org/appengine"
	"net/http"
)

var (
	//indexTemplate = template.Must(template.ParseFiles("index.html"))
)

func main() {
	r := mux.NewRouter()
	r.Use(commonMiddleware)

	// 프론트 렌더링
	// r.HandleFunc("/", indexHandler)
	// r.HandleFunc("/ico", icoHandler)
	// r.HandleFunc("/blocks", blocksHandler)
	// r.HandleFunc("/richlist", richlistHandler)
	// r.HandleFunc("/account/{accountName}", indexHandler)

	// 백엔드 API
	r.HandleFunc("/api/getauthtoken", getAuthToken)
	// 탐색 속도 체크용
	//r.HandleFunc("/api/sethashrate", setHashrate)
	// 클라이언트에서 찾은 해시 정답 확인후 보상 지급
	r.HandleFunc("/api/submitpow", submitPow)
	// 보물을 받을 BTC 주소 연결
	//r.HandleFunc("/api/setbtcaddress", setBtcAddress)

	// ---------------------------- Cron 작업 ----------------------------
	r.HandleFunc("/api/deleteexpirehashrate", deleteExpireHashrate)

	// The path "/" matches everything not matched by some other path.
	http.Handle("/", r)
	appengine.Main()
}

func commonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filter(w, r) {
			w.Header().Add("Content-Type", "application/json")
			next.ServeHTTP(w, r)
		}
	})
}

func filter(w http.ResponseWriter, r *http.Request) bool {
	// 접속한 ip 확인
	//ip := strings.Split(r.RemoteAddr,":")[0]
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE")
	w.Header().Set("Access-Control-Max-Age", "3600")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, X-Auth-Token, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(203)
		return true
	}

	if r.Header.Get("Authorization") != BASIC_AUTH_KEY {
		http.Error(w, "", 401)
		return false
	}

	return true
}