package main

type AuthToken struct {
	EosAccountName string
	MachineId string
}

type Hashrate struct {
	DeviceId string
	Address string
	Ip string
	Hashrate int
	Timestamp int
	Hmac string
}

type HashrateParams struct {
	Hashrates []Hashrate
}

type SubmitPow struct {
	Nonce string
}

type Block struct {
	Height int64
	Nonce string	`json:",omitempty"`
	Timestamp int
	RelayedBy string
	Difficulty int
	HashResult string
	BlockReward float64
}

type BlockParams struct {
	Blocks []Block
}

type IssueResponse struct {
	Broadcast   bool `json:"broadcast"`
	Transaction struct {
		Compression string `json:"compression"`
		Transaction struct {
			Expiration         string        `json:"expiration"`
			RefBlockNum        int           `json:"ref_block_num"`
			RefBlockPrefix     int64         `json:"ref_block_prefix"`
			NetUsageWords      int           `json:"net_usage_words"`
			MaxCPUUsageMs      int           `json:"max_cpu_usage_ms"`
			DelaySec           int           `json:"delay_sec"`
			ContextFreeActions []interface{} `json:"context_free_actions"`
			Actions            []struct {
				Account       string `json:"account"`
				Name          string `json:"name"`
				Authorization []struct {
					Actor      string `json:"actor"`
					Permission string `json:"permission"`
				} `json:"authorization"`
				Data string `json:"data"`
			} `json:"actions"`
			TransactionExtensions []interface{} `json:"transaction_extensions"`
		} `json:"transaction"`
		Signatures []string `json:"signatures"`
	} `json:"transaction"`
	TransactionID string `json:"transaction_id"`
	Processed     struct {
		ID              string      `json:"id"`
		BlockNum        int         `json:"block_num"`
		BlockTime       string      `json:"block_time"`
		ProducerBlockID interface{} `json:"producer_block_id"`
		Receipt         struct {
			Status        string `json:"status"`
			CPUUsageUs    int    `json:"cpu_usage_us"`
			NetUsageWords int    `json:"net_usage_words"`
		} `json:"receipt"`
		Elapsed      int  `json:"elapsed"`
		NetUsage     int  `json:"net_usage"`
		Scheduled    bool `json:"scheduled"`
		ActionTraces []struct {
			Receipt struct {
				Receiver       string          `json:"receiver"`
				ActDigest      string          `json:"act_digest"`
				GlobalSequence int             `json:"global_sequence"`
				RecvSequence   int             `json:"recv_sequence"`
				AuthSequence   [][]interface{} `json:"auth_sequence"`
				CodeSequence   int             `json:"code_sequence"`
				AbiSequence    int             `json:"abi_sequence"`
			} `json:"receipt"`
			Act struct {
				Account       string `json:"account"`
				Name          string `json:"name"`
				Authorization []struct {
					Actor      string `json:"actor"`
					Permission string `json:"permission"`
				} `json:"authorization"`
				Data struct {
					To       string `json:"to"`
					Quantity string `json:"quantity"`
					Memo     string `json:"memo"`
				} `json:"data"`
				HexData string `json:"hex_data"`
			} `json:"act"`
			ContextFree      bool        `json:"context_free"`
			Elapsed          int         `json:"elapsed"`
			Console          string      `json:"console"`
			TrxID            string      `json:"trx_id"`
			BlockNum         int         `json:"block_num"`
			BlockTime        string      `json:"block_time"`
			ProducerBlockID  interface{} `json:"producer_block_id"`
			AccountRAMDeltas []struct {
				Account string `json:"account"`
				Delta   int    `json:"delta"`
			} `json:"account_ram_deltas"`
			Except       interface{} `json:"except"`
			InlineTraces []struct {
				Receipt struct {
					Receiver       string          `json:"receiver"`
					ActDigest      string          `json:"act_digest"`
					GlobalSequence int             `json:"global_sequence"`
					RecvSequence   int             `json:"recv_sequence"`
					AuthSequence   [][]interface{} `json:"auth_sequence"`
					CodeSequence   int             `json:"code_sequence"`
					AbiSequence    int             `json:"abi_sequence"`
				} `json:"receipt"`
				Act struct {
					Account       string `json:"account"`
					Name          string `json:"name"`
					Authorization []struct {
						Actor      string `json:"actor"`
						Permission string `json:"permission"`
					} `json:"authorization"`
					Data struct {
						From     string `json:"from"`
						To       string `json:"to"`
						Quantity string `json:"quantity"`
						Memo     string `json:"memo"`
					} `json:"data"`
					HexData string `json:"hex_data"`
				} `json:"act"`
				ContextFree      bool        `json:"context_free"`
				Elapsed          int         `json:"elapsed"`
				Console          string      `json:"console"`
				TrxID            string      `json:"trx_id"`
				BlockNum         int         `json:"block_num"`
				BlockTime        string      `json:"block_time"`
				ProducerBlockID  interface{} `json:"producer_block_id"`
				AccountRAMDeltas []struct {
					Account string `json:"account"`
					Delta   int    `json:"delta"`
				} `json:"account_ram_deltas"`
				Except       interface{} `json:"except"`
				InlineTraces []struct {
					Receipt struct {
						Receiver       string          `json:"receiver"`
						ActDigest      string          `json:"act_digest"`
						GlobalSequence int             `json:"global_sequence"`
						RecvSequence   int             `json:"recv_sequence"`
						AuthSequence   [][]interface{} `json:"auth_sequence"`
						CodeSequence   int             `json:"code_sequence"`
						AbiSequence    int             `json:"abi_sequence"`
					} `json:"receipt"`
					Act struct {
						Account       string `json:"account"`
						Name          string `json:"name"`
						Authorization []struct {
							Actor      string `json:"actor"`
							Permission string `json:"permission"`
						} `json:"authorization"`
						Data struct {
							From     string `json:"from"`
							To       string `json:"to"`
							Quantity string `json:"quantity"`
							Memo     string `json:"memo"`
						} `json:"data"`
						HexData string `json:"hex_data"`
					} `json:"act"`
					ContextFree      bool          `json:"context_free"`
					Elapsed          int           `json:"elapsed"`
					Console          string        `json:"console"`
					TrxID            string        `json:"trx_id"`
					BlockNum         int           `json:"block_num"`
					BlockTime        string        `json:"block_time"`
					ProducerBlockID  interface{}   `json:"producer_block_id"`
					AccountRAMDeltas []interface{} `json:"account_ram_deltas"`
					Except           interface{}   `json:"except"`
					InlineTraces     []interface{} `json:"inline_traces"`
				} `json:"inline_traces"`
			} `json:"inline_traces"`
		} `json:"action_traces"`
		Except interface{} `json:"except"`
	} `json:"processed"`
}