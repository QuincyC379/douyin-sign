package main

import (
	"net/url"
	"fmt"
	"sort"
	"yx.com/common/lib/crypto2"
	"time"
	"strconv"
	"net/http"
	"strings"
	"encoding/json"
	"bytes"
	"io"
	"io/ioutil"
	"math/rand"
)

const HIDDEN_RSTR = "AAAAAAAA"
const HIDDEN_ORDER1 = "00000000"
const HIDDEN_ORDER2 = "00000000"
const HIDDEN_PPP1 = "A"
const HIDDEN_PPP2 = "0"
const HIDDEN_PPP3 = "A"
const HIDDEN_PPP4 = "0"
const HIDDEN_POS1 = 0
const HIDDEN_POS2 = 0
const HIDDEN_POS3 = 0
const HIDDEN_POS4 = 0
const HIDDEN_CRYPT1 = 0x00
const HIDDEN_CRYPT2 = 0
const HIDDEN_CRYPT3 = 0x00

const apiBase = "http://api.amemv.com/aweme/v1/"
const apiBaseAuth = "https://lf.snssdk.com/"

const API_NAME_FOLLOWERS = "user/follower/list"
const API_NAME_FOLLOWEINGS = "user/following/list"
const API_NAME_USER = "user"
const API_NAME_POSTS = "aweme/post"
const API_NAME_FAVORITES = "aweme/favorite"
const API_NAME_FEEDS = "feed"
const API_NAME_NEARBY_FEEDS = "nearby/feed"
const API_NAME_CATEGORY_LIST = "category/list"
const API_NAME_MUSIC = "music/aweme"
const API_NAME_MUSIC_NEW = "music/fresh/aweme"
const API_NAME_SEARCH_ALL = "general/search"
const API_NAME_SEARCH_USER = "discover/search"
const API_NAME_SEARCH_MUSIC = "music/search"
const API_NAME_SEARCH_CHALLENGE = "challenge/search"

const API_NAME_AUTH_LOGIN_MOBILE = "user/mobile/login/v2"

var deviceId int
var installId int
var uuid string
var openUuid string

//入口
func main() {
	//生成设备信息
	deviceId, installId, uuid, openUuid, _ = getDeviceId()

	//使用手机和密码登录
	loginWithMobilePwd("18888888888", "123456")

	//获取首页feed流
	getFeeds()
	//其他接口都一样
}

//获取首页feed流
func getFeeds() {
	params := make(url.Values)
	params.Set("type", "0")
	params.Set("count", "100")
	params.Set("max_cursor", "0")
	params.Set("min_cursor", "0")
	urlRequest, _ := wrapRequest(API_NAME_FEEDS, params)
	httpGet(urlRequest)
}

func loginWithMobilePwd(mobile, password string) (err error) {
	postParams := make(url.Values)
	postParams.Set("mobile", crypt(mobile))
	postParams.Set("password", crypt(password))
	postParams.Set("mix_mode", "1")
	postParams.Set("captcha", "frde")
	setDefaultArgs(&postParams)

	urlRequest := fmt.Sprintf("%s%s/", apiBaseAuth, API_NAME_AUTH_LOGIN_MOBILE)
	req, _ := http.NewRequest("POST", urlRequest, strings.NewReader(postParams.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("user-agent", "okhttp/3.8.1")
	req.Header.Add("Save-Data", "on")
	resp, err := http.Client{}.Do(req)
	if err == nil {
		if resp.StatusCode == 200 {
			//保存cookie，用于后续的需要验证的请求
			cookies := resp.Cookies()
			fmt.Println(cookies)
		}
	}
	return
}

func wrapRequest(apiName string, params url.Values) (urlRequest string, err error) {
	urlRequest = fmt.Sprintf("%s%s/", apiBase, apiName)
	urlObj, err := url.Parse(urlRequest)
	urlObj.RawQuery = params.Encode()
	if err == nil {
		sign(urlObj)
		urlRequest = fmt.Sprintf("%s://%s%s", urlObj.Scheme, urlObj.Host, urlObj.RequestURI())
		return
	}
	return
}

func sign(urlObj *url.URL, timeStraps ...int) {
	timeStrap := int(time.Now().Unix())

	if len(timeStraps) > 0 {
		timeStrap = timeStraps[0]
	}
	query := urlObj.Query()
	setDefaultArgs(&query)

	query.Set("ts", strconv.Itoa(timeStrap))

	query.Set("rstr", HIDDEN_RSTR)
	query.Set("_rticket", fmt.Sprintf("%d", time.Now().UnixNano()))

	var keys []string
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var values []string
	for _, k := range keys {
		v := query[k][0]
		v = strings.Replace(v, "+", "a", -1)
		v = strings.Replace(v, " ", "a", -1)
		values = append(values, v)
	}
	urlParams := strings.Join(values, "")

	paramsMd5 := crypto2.Md5(urlParams)
	if timeStrap&1 != 0 {
		paramsMd5 = crypto2.Md5(paramsMd5)
	}
	//fmt.Println(paramsMd5, timeStrap&1, timeStrap)

	hexTime := fmt.Sprintf("%x", timeStrap)

	aa := shuffle(hexTime, HIDDEN_ORDER1)

	bb := shuffle(hexTime, HIDDEN_ORDER2)
	as, cp := ppp(paramsMd5, aa, bb)
	query.Set("as", as)
	query.Set("cp", cp)
	query.Del("rstr")
	urlObj.RawQuery = query.Encode()
}
func ppp(pMd5, key1, key2 string) (as, cp string) {
	rst := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}

	rst[0] = HIDDEN_PPP1

	rst[1] = HIDDEN_PPP2

	rst[34] = HIDDEN_PPP3

	rst[35] = HIDDEN_PPP4

	indexMax := 8
	index := 0
	for {

		rst[2*(index+HIDDEN_POS1)] = string([]rune(pMd5)[index])

		rst[2*index+HIDDEN_POS2] = string([]rune(key2)[index])

		rst[2*index+HIDDEN_POS3] = string([]rune(key1)[index])

		rst[2*index+HIDDEN_POS4] = string([]rune(pMd5)[index+24])
		index++
		if index == indexMax {
			break
		}
	}
	ascp := strings.Join(rst, "")
	as = ascp[0:18]
	cp = ascp[18:]
	return
}

func shuffle(value string, poss string) (string) {
	loopSize := len(poss)
	index := 0
	rst := ""
	for {
		idx, _ := strconv.Atoi(string([]rune(poss)[index]))
		rst = rst + string([]rune(value)[idx-1])
		index++
		if index == loopSize {
			break
		}

	}
	return rst
}

func crypt(val string) string {
	bytes := []byte(val)
	bytesLen := len(bytes)
	chars := []rune{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
	for i := 0; i < bytesLen; i++ {
		bytes[i] = bytes[i] ^ 5
	}
	rst := make([]rune, bytesLen*2)
	i := 0
	j := 0
	for {

		k := bytes[i+0] & HIDDEN_CRYPT1
		m := j + 1

		rst[j] = chars[k>>HIDDEN_CRYPT2]
		j = m + 1

		rst[m] = chars[k&HIDDEN_CRYPT3]
		i += 1
		if i >= bytesLen {
			break
		}
	}

	return string(rst)
}
func setDefaultArgs(query *url.Values) {

	query.Set("iid", strconv.Itoa(installId))
	query.Set("device_id", strconv.Itoa(deviceId))

	query.Set("channel", "360")
	query.Set("resolution", "1080*1920")
	query.Set("dpi", "420")
	query.Set("app_name", "aweme")
	query.Set("device_platform", "android")
	query.Set("ssmix", "a")
	query.Set("device_type", "ONEPLUS+A5000")
	query.Set("device_brand", "OnePlus")
	query.Set("language", "zh")
	query.Set("os_api", "27")
	query.Set("os_version", "8.1.0")
	query.Set("ac", "wifi")

	query.Set("uuid", uuid)
	query.Set("openudid", openUuid)
	query.Set("retry_type", "no_retry")
	query.Set("update_version_code", "1692")
	query.Set("manifest_version_code", "169")
	query.Set("version_code", "169")
	query.Set("version_name", "1.6.9")
	query.Set("aid", "1128")
}

type deviceHttpRequest struct {
	MagicTag string `json:"magic_tag"`
	Header struct {
		UDID     string `json:"udid"`
		OpenUDID string `json:"openudid"`
	} `json:"header"`
	GenTime int64 `json:"_gen_time"`
}
type DeviceHttpResponse struct {
	DeviceId  int `json:"device_id"`
	InstallId int `json:"install_id"`
}

func getDeviceId() (deviceId, installId int, uuid, openUuid string, err error) {
	uuid = intString(15)
	openUuid = intString(16)

	params := deviceHttpRequest{}
	params.GenTime = time.Now().UnixNano()
	params.MagicTag = "ss_app_log"

	params.Header.UDID = uuid
	params.Header.OpenUDID = openUuid

	var deviceInfo DeviceHttpResponse
	data, _ := json.Marshal(params)
	req, _ := http.NewRequest("POST", "http://log.snssdk.com/service/2/app_log_config/", bytes.NewReader(data))
	req.Header.Add("user-agent", "okhttp/3.8.1")
	req.Header.Add("Save-Data", "on")
	resp, err := http.Client{}.Do(req)
	if err == nil {
		if resp.StatusCode == 200 {
			reader := resp.Body.(io.Reader)
			if err = json.NewDecoder(reader).Decode(deviceInfo); err != nil {
				respBody, _ := ioutil.ReadAll(resp.Body)
				fmt.Println("c", err, string(respBody))
				return
			}
			deviceId = deviceInfo.DeviceId
			installId = deviceInfo.InstallId
		}
	}
	return
}

func httpGet(urlRequest string) {
	req, _ := http.NewRequest("GET", urlRequest, nil)
	req.Header.Add("user-agent", "okhttp/3.8.1")
	req.Header.Add("Save-Data", "on")
	resp, err := http.Client{}.Do(req)
	if err == nil {
		if resp.StatusCode == 200 {
			//	......
		}
	}
}

const charsetInt = "0123456789"

var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}
func intString(length int) string {
	return StringWithCharset(length, charsetInt)
}
