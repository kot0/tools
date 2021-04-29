package tools

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/spf13/cast"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
const TimeFormat = `2006-01-02 15:04:05`

const TimeFormatOnlyTime = `15:04:05`
const TimeFormatOnlyDate = `2006-01-02`

func ToJson(input interface{}) string {
	data, _ := json.Marshal(input)
	return string(data)
}

func ParsevalueDynamicCompile(text string, reg string) string {
	r := regexp.MustCompile(reg)

	tmp := r.FindStringSubmatch(text)

	if len(tmp) < 2 {
		return ""
	}

	tmp[1] = (" " + tmp[1])[1:] //memory leak fix

	return tmp[1]
}

var regexpCompileCache = make(map[string]*regexp.Regexp)
var m sync.Mutex

func ParsevalueStaticCompile(text string, reg string) string {
	var r *regexp.Regexp
	m.Lock()
	if regexpCompileCache[reg] == nil {
		m.Unlock()
		r = regexp.MustCompile(reg)
		m.Lock()
		regexpCompileCache[reg] = r
		m.Unlock()
	} else {
		m.Unlock()
		r = regexpCompileCache[reg]
	}

	tmp := r.FindStringSubmatch(text)

	if len(tmp) < 2 {
		return ""
	}

	tmp[1] = (" " + tmp[1])[1:] //memory leak fix

	return tmp[1]
}

func ParsevaluesStaticCompile(text string, reg string) []string {
	var r *regexp.Regexp
	m.Lock()
	if regexpCompileCache[reg] == nil {
		m.Unlock()
		r = regexp.MustCompile(reg)
		m.Lock()
		regexpCompileCache[reg] = r
		m.Unlock()
	} else {
		m.Unlock()
		r = regexpCompileCache[reg]
	}

	tmp := r.FindAllStringSubmatch(text, -1)

	var result []string

	for _, v := range tmp {
		if len(v) < 2 {
			continue
		}

		v[1] = (" " + v[1])[1:] //memory leak fix

		result = append(result, v[1])
	}

	return result
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
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	f.WriteString(text)
	f.Close()
}

func Readfromconsole() string {
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return text
}

func Tobase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func BytesTobase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64ToBytes(data string) []byte {
	result, _ := base64.StdEncoding.DecodeString(data)
	return result
}

func Frombase64(data string) string {
	result, _ := base64.StdEncoding.DecodeString(data)
	return string(result)
}

func Urlencode(s string) (result string) {
	for _, c := range s {
		if c <= 0x7f {
			result += fmt.Sprintf("%%%X", c)
		} else if c > 0x1fffff {
			result += fmt.Sprintf("%%%X%%%X%%%X%%%X",
				0xf0+((c&0x1c0000)>>18),
				0x80+((c&0x3f000)>>12),
				0x80+((c&0xfc0)>>6),
				0x80+(c&0x3f),
			)
		} else if c > 0x7ff {
			result += fmt.Sprintf("%%%X%%%X%%%X",
				0xe0+((c&0xf000)>>12),
				0x80+((c&0xfc0)>>6),
				0x80+(c&0x3f),
			)
		} else {
			result += fmt.Sprintf("%%%X%%%X",
				0xc0+((c&0x7c0)>>6),
				0x80+(c&0x3f),
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

func BytesToHex(in []byte) string {
	data := hex.EncodeToString(in)
	return data
}

func HexToBytes(in string) []byte {
	data, err := hex.DecodeString(in)
	if err != nil {
		return nil
	}
	return data
}

func OnErrorPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func CheckError(err error) bool {
	if err != nil {
		return true
	}
	return false
}

func Sha1(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	hs := h.Sum(nil)
	return hex.EncodeToString(hs)
}

func Sha256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	hs := h.Sum(nil)
	return hex.EncodeToString(hs)
}

func Sha512(data string) string {
	h := sha512.New()
	h.Write([]byte(data))
	hs := h.Sum(nil)
	return hex.EncodeToString(hs)
}

func Md5(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Md5Bytes(data []byte) string {
	hasher := md5.New()
	hasher.Write(data)
	hash := hex.EncodeToString(hasher.Sum(nil))
	hasher.Reset()
	return hash
}

func Md5BytesToBytes(data []byte) []byte {
	hasher := md5.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	hasher.Reset()
	return hash
}

func Md5File(filePath string) (string, error) {
	var returnMD5String string

	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}
	defer file.Close()

	hash := md5.New()

	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}

	hashInBytes := hash.Sum(nil)[:16]

	returnMD5String = hex.EncodeToString(hashInBytes)

	return returnMD5String, nil

}

func ArrayContains(array []string, data string) bool {
	for _, e := range array {
		if e == data {
			return true
		}
	}
	return false
}

func StringArrayContains(array []string, data string) bool {
	for _, e := range array {
		if e == data {
			return true
		}
	}
	return false
}

func IntArrayContains(array []int, data int) bool {
	for _, e := range array {
		if e == data {
			return true
		}
	}
	return false
}

func ScanFolderRecursive(dirPath string, ignore []string) ([]string, []string) {
	var folders []string
	var files []string

	filepath.Walk(dirPath, func(path string, f os.FileInfo, err error) error {

		_continue := false

		for _, i := range ignore {

			if strings.Index(path, i) != -1 {

				_continue = true
			}
		}

		if _continue == false {

			f, err = os.Stat(path)

			if err != nil {
				log.Fatal(err)
			}

			fMode := f.Mode()

			if fMode.IsDir() {

				folders = append(folders, path)

			} else if fMode.IsRegular() {

				files = append(files, path)
			}
		}

		return nil
	})

	return folders, files
}

func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

func RemoveNewlineChars(text string) string {
	text = strings.ReplaceAll(text, "\n", "")
	text = strings.ReplaceAll(text, "\r", "")
	return text
}

var sqliteEscapeMap = map[string]string{`\\`: `\\\\`, `'`: `''`, `\\0`: `\\\\0`, `\n`: `\\n`, `\r`: `\\r`, `\x1a`: `\\Z`}

func SqliteEscape(text string) string {
	for b, a := range sqliteEscapeMap {
		text = strings.ReplaceAll(text, b, a)
	}

	return text
}

var mySqlEscapeMap = map[string]string{"\\": "\\\\", "'": `\'`, "\\0": "\\\\0", "\n": "\\n", "\r": "\\r", `"`: `\"`, "\x1a": "\\Z"}

func MySqlEscape(value string) string {
	for b, a := range mySqlEscapeMap {
		value = strings.Replace(value, b, a, -1)
	}

	return value
}

var tgEscapeArray = []string{"_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"}

func TgEscape(text string) string {
	for _, char := range tgEscapeArray {
		text = strings.Replace(text, char, `\`+char, -1)
	}

	return text
}

type Logger struct {
	File string
	Name string

	ShowTime           bool
	ShowSourceCodeLine bool
	ShowSourceCodePath bool
}

// Deprecated: use Logger directly
func NewLogger(loggerFile string, loggerName string) Logger {
	return Logger{
		File:     loggerFile,
		Name:     loggerName,
		ShowTime: true,
	}
}

func (logger Logger) Log(text ...interface{}) {
	var out []string

	if logger.Name != "" {
		out = append(out, "["+logger.Name+"] ")
	}

	if logger.ShowTime {
		out = append(out, time.Now().Format(TimeFormat))
	}

	callFile, callLineNumber := getCallLocation(2)

	if logger.ShowSourceCodePath || logger.ShowSourceCodeLine {
		tmp := ""

		if logger.ShowSourceCodePath {
			tmp += callFile
		}

		if logger.ShowSourceCodeLine {
			if logger.ShowSourceCodePath {
				tmp += ":"
			}

			tmp += cast.ToString(callLineNumber)
		}

		out = append(out, tmp)
	}

	finalLogText := strings.Join(out, " ")

	if logger.ShowTime || logger.Name != "" || logger.ShowSourceCodeLine || logger.ShowSourceCodePath {
		finalLogText += ": "
	}

	finalLogText += strings.TrimSuffix(fmt.Sprintln(text...), "\n")

	fmt.Println(finalLogText)

	if logger.File != "" {
		Addlinetofile(logger.File, finalLogText+"\n")
	}
}

func getCallLocation(skipCalls int) (string, int) {
	_, callFile, callLineNumber, _ := runtime.Caller(skipCalls)
	return callFile, callLineNumber
}

func FormatText(text ...interface{}) string {
	return strings.TrimSuffix(fmt.Sprintln(text...), "\n")
}

func ClearSlice(slice []string) []string {
	var outSlice []string
	for _, entry := range slice {
		entry = RemoveNewlineChars(entry)

		if entry == "" {
			continue
		}

		outSlice = append(outSlice, entry)
	}
	return outSlice
}

func AddPrefixToSlice(slice []string, prefix string) []string {
	var outSlice []string
	for _, element := range slice {
		outSlice = append(outSlice, prefix+element)
	}
	return outSlice
}

func ReverseArray(array []string) []string {
	lenx := len(array)
	result := make([]string, lenx)

	for i := 0; i < lenx; i++ {
		j := lenx - (i + 1)
		result[i] = array[j]
	}

	return result
}
