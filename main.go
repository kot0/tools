package tools

import "regexp"
import "os"
import "bufio"
import "encoding/base64"
import "github.com/tidwall/gjson"
import "compress/zlib"
import "bytes"
import "io/ioutil"
import "fmt"
import "encoding/json"
import "encoding/hex"

const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"

func ToJson(input interface{}) string {
	data, _ := json.Marshal(input)
	return string(data)
}

func Parsejson(data string, path string) string {
	return gjson.Get(data, path).String()
}

// Deprecated: use ParsevalueDynamicCompile() or ParsevalueStaticCompile()
func Parsevalue(text string, reg string) string {
	r := regexp.MustCompile(reg)

	tmp := r.FindStringSubmatch(text)

	if len(tmp) != 2 {
		return ""
	}

	return tmp[1]
}

func ParsevalueDynamicCompile(text string, reg string) string {
	r := regexp.MustCompile(reg)

	tmp := r.FindStringSubmatch(text)

	if len(tmp) != 2 {
		return ""
	}

	return tmp[1]
}

var regexpCompileCache = make(map[string]*regexp.Regexp)
func ParsevalueStaticCompile(text string, reg string) string {
	var r *regexp.Regexp
	if regexpCompileCache[reg] == nil {
		r = regexp.MustCompile(reg)
		regexpCompileCache[reg] = r
	} else {
		r = regexpCompileCache[reg]
	}

	tmp := r.FindStringSubmatch(text)

	if len(tmp) != 2 {
		return ""
	}

	return tmp[1]
}

func Readfiletoarray(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func ClearArrray(array []string) []string {
	var out []string

	for _, e := range array {
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

func Addlinetofile(path string, text string) {
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, os.ModeAppend)
	f.WriteString(text)
	f.Close()
}

func Readfromconsole() string {
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return text
}

func Tobase64(data string) string {
	return string(base64.StdEncoding.EncodeToString([]byte(data)))
}

func Frombase64(data string) string {
	result, _ := base64.StdEncoding.DecodeString(data)
	return string(result)
}

func Urlencode(s string) (result string){
	for _, c := range s {
		if c <= 0x7f {
			result += fmt.Sprintf("%%%X", c)
		} else if c > 0x1fffff {
			result += fmt.Sprintf("%%%X%%%X%%%X%%%X",
				0xf0 + ((c & 0x1c0000) >> 18),
				0x80 + ((c & 0x3f000) >> 12),
				0x80 + ((c & 0xfc0) >> 6),
				0x80 + (c & 0x3f),
			)
		} else if c > 0x7ff {
			result += fmt.Sprintf("%%%X%%%X%%%X",
				0xe0 + ((c & 0xf000) >> 12),
				0x80 + ((c & 0xfc0) >> 6),
				0x80 + (c & 0x3f),
			)
		} else {
			result += fmt.Sprintf("%%%X%%%X",
				0xc0 + ((c & 0x7c0) >> 6),
				0x80 + (c & 0x3f),
			)
		}
	}

	return result
}

func UniqueSlice(slice []string) []string {
	var keys = make(map[string]bool)
	var list []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func FileExist(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func ZlibCompress(data []byte) ([]byte, error) {
	var buff bytes.Buffer

	w := zlib.NewWriter(&buff)

	_, err := w.Write(data)
	if err != nil {
		return nil, err
	}

	err2 := w.Close()
	if err2 != nil {
		return nil, err2
	}

	return buff.Bytes(), nil
}

func ZlibDeCompress(data []byte) ([]byte, error) {
	r, _ := zlib.NewReader(bytes.NewBuffer(data))

	dedata, _ := ioutil.ReadAll(r)

	err2 := r.Close()
	if err2 != nil {
		return nil, err2
	}

	return dedata, nil
}

func OnErrorLog(err error) bool {
	if err != nil {
		println("error is: " + err.Error())
		return true
	}
	return false
}

func TryDeleteFile(file string) {
	_ = os.Remove(file)
	return
}

func TryDeleteFiles(files []string) {
	for _, file := range files {
		TryDeleteFile(file)
	}
}

func GetFilesFromFolder(folder string) []string {
	var files []string

	tmpFiles, _ := ioutil.ReadDir(folder)

	for _, f := range tmpFiles {
		files = append(files, f.Name())
	}

	return files
}

func GetFileSize(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}

	fi, err := file.Stat()
	if err != nil {
		return 0, err
	}

	return int(fi.Size()), nil
}

func FromHex(in string) string {
	data, err := hex.DecodeString(in)
	if err != nil {
		return ""
	}
	return string(data)
}

func ToHex(in string) string {
	data := hex.EncodeToString([]byte(in))
	return data
}
