package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	File       = flag.String("file", "ip.txt", "IP地址文件名称")
	outFile    = flag.String("outfile", "ip.csv", "输出文件名称")
	maxThreads = flag.Int("max", 100, "并发请求最大协程数")
)

type result struct {
	ip       string
	latency  string
	duration time.Duration
}

func main() {
	flag.Parse()

	startTime := time.Now()

	ips, err := readIPs(*File)
	if err != nil {
		fmt.Printf("无法从文件中读取IP: %v\n", err)
		return
	}

	resultChan := make(chan result, len(ips))
	sem := make(chan struct{}, *maxThreads)

	var wg sync.WaitGroup
	wg.Add(len(ips))

	var count int
	total := len(ips)

	for _, ip := range ips {
		sem <- struct{}{}
		go func(ip string) {
			defer func() {
				<-sem
				wg.Done()
				count++
				percentage := float64(count) / float64(total) * 100
				fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\r", count, total, percentage)
				if count == total {
					fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\n", count, total, percentage)
				}
			}()

			latency, duration, err := ping(ip)
			if err != nil {
				fmt.Printf("Ping %s 失败: %v\n", ip, err)
				return
			}

			fmt.Printf("Ping %s 成功, ICMP网络延迟: %s\n", ip, latency)
			resultChan <- result{ip, latency, duration}
		}(ip)
	}

	wg.Wait()
	close(resultChan)

	if len(resultChan) == 0 {
		fmt.Print("\033[2J")
		fmt.Println("没有发现有效的IP")
		return
	}

	var results []result
	for res := range resultChan {
		results = append(results, res)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].duration < results[j].duration
	})

	file, err := os.Create(*outFile)
	if err != nil {
		fmt.Printf("无法创建文件: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Write([]string{"IP地址", "网络延迟"})
	for _, res := range results {
		writer.Write([]string{res.ip, res.latency})
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Printf("写入CSV文件时出现错误: %v\n", err)
		return
	}

	fmt.Printf("成功将结果写入文件 %s，耗时 %d秒\n", *outFile, time.Since(startTime)/time.Second)
}

func readIPs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "/") {
			// CIDR格式，展开成具体的IP地址
			expandedIPs, err := expandCIDR(line)
			if err != nil {
				fmt.Printf("无法解析CIDR %s: %v\n", line, err)
				continue
			}
			ips = append(ips, expandedIPs...)
		} else {
			ips = append(ips, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// 删除网络地址和广播地址（如果适用）
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ping(ip string) (string, time.Duration, error) {
	var conn *icmp.PacketConn
	var err error
	var msgType icmp.Type
	var network string

	if strings.Contains(ip, ":") {
		network = "ip6:ipv6-icmp"
		conn, err = icmp.ListenPacket(network, "::")
		msgType = ipv6.ICMPTypeEchoRequest
	} else {
		network = "ip4:icmp"
		conn, err = icmp.ListenPacket(network, "0.0.0.0")
		msgType = ipv4.ICMPTypeEcho
	}

	if err != nil {
		return "", 0, fmt.Errorf("创建ICMP连接失败: %v", err)
	}
	defer conn.Close()

	data := []byte("abcdefghijklmnopqrstuvwabcdefghi")
	wm := icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: data,
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return "", 0, fmt.Errorf("序列化ICMP消息失败: %v", err)
	}

	start := time.Now()

	dst, err := net.ResolveIPAddr(network[:3], ip)
	if err != nil {
		return "", 0, fmt.Errorf("解析IP地址失败: %v", err)
	}

	if _, err := conn.WriteTo(wb, dst); err != nil {
		return "", 0, fmt.Errorf("发送ICMP请求失败: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	for {
		rb := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return "", 0, fmt.Errorf("接收ICMP回复失败: %v", err)
		}

		if peer.String() == dst.String() {
			duration := time.Since(start)
			rm, err := icmp.ParseMessage(msgType.Protocol(), rb[:n])
			if err != nil {
				return "", 0, fmt.Errorf("解析ICMP回复失败: %v", err)
			}

			switch rm.Type {
			case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
				return strconv.FormatInt(duration.Milliseconds(), 10) + " ms", duration, nil
			default:
				return "", 0, fmt.Errorf("接收到未知的ICMP消息类型: %v", rm.Type)
			}
		}
	}
}
