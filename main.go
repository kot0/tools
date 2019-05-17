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

const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36"

func Parsejson(data string, path string) string {
	return gjson.Get(data, path).String()
}

func Parsevalue(text string, reg string) string {
	r := regexp.MustCompile(reg)

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
