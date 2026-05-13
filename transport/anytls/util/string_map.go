package util

import (
	"strings"
)

type StringMap map[string]string

func (s StringMap) ToBytes() []byte {
	var lines []string
	for k, v := range s {
		lines = append(lines, k+"="+v)
	}
	return []byte(strings.Join(lines, "\n"))
}

func StringMapFromBytes(b []byte) StringMap {
	var m = make(StringMap)
	var lines = strings.Split(string(b), "\n")
	for _, line := range lines {
		// 兼容 CRLF：Windows checkout 时 git autocrlf 把 padding.go 里
		// raw string 的 \n 转成 \r\n，每行末尾会残留 \r，导致后续
		// strconv.ParseInt("30\r") 解析失败 → padding scheme 全部失效
		// → anytls 流量没混淆 → 部分网络环境下被中间盒 RST → EOF。
		line = strings.TrimRight(line, "\r")
		v := strings.SplitN(line, "=", 2)
		if len(v) == 2 {
			m[v[0]] = v[1]
		}
	}
	return m
}
