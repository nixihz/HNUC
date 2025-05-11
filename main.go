package main

import (
	"encoding/json"
	"fmt"
	"image/color"
	"io/ioutil"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	probing "github.com/prometheus-community/pro-bing"
)

type Device struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Remark string `json:"remark"`
	Online bool   // 新增字段，仅用于UI展示
}

type DeviceList struct {
	Devices []Device `json:"devices"`
}

const remarkFile = "device_remarks.json"

// 读取备注
func loadRemarks() map[string]string {
	remarks := make(map[string]string)
	if _, err := os.Stat(remarkFile); err == nil {
		data, err := ioutil.ReadFile(remarkFile)
		if err == nil {
			var list DeviceList
			if json.Unmarshal(data, &list) == nil {
				for _, d := range list.Devices {
					if d.MAC != "" {
						remarks[d.MAC] = d.Remark
					}
				}
			}
		}
	}
	return remarks
}

// 保存备注
func saveRemarks(remarks map[string]string) {
	list := DeviceList{}
	for mac, remark := range remarks {
		list.Devices = append(list.Devices, Device{MAC: mac, Remark: remark})
	}
	data, _ := json.MarshalIndent(list, "", "  ")
	_ = ioutil.WriteFile(remarkFile, data, 0644)
}

// ping 检查 IP 是否在线
func ping(ip string) bool {
	//ip = "192.168.31.208"
	pinger, err := probing.NewPinger(ip)
	if err != nil {
		return false
	}
	pinger.Count = 1
	pinger.Timeout = 1 * time.Second
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		return false
	}
	stats := pinger.Statistics() // get send/receive/duplicate/rtt stats
	return len(stats.TTLs) > 0
}

// 获取所有网卡及其IPv4地址
func getAllInterfaces() ([]string, map[string]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	var names []string
	nameToSubnet := make(map[string]string)
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				ip := ipnet.IP.To4()
				prefix := fmt.Sprintf("%d.%d.%d.", ip[0], ip[1], ip[2])
				name := fmt.Sprintf("%s (%s)", iface.Name, ip.String())
				names = append(names, name)
				nameToSubnet[name] = prefix
			}
		}
	}
	return names, nameToSubnet, nil
}

// 扫描指定网段
// 进度通过 channel 传递
func scanSubnet(subnet string, progress chan<- scanProgress, done func(map[string]struct{})) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	ipSet := make(map[string]struct{})
	total := 254
	var current int
	for i := 1; i < 255; i++ {
		ip := fmt.Sprintf("%s%d", subnet, i)
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if ping(ip) {
				mu.Lock()
				if _, exists := ipSet[ip]; !exists {
					ipSet[ip] = struct{}{}
				}
				mu.Unlock()
			} else {
			}
			mu.Lock()
			current++
			progress <- scanProgress{IP: ip, Current: current, Total: total}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	done(ipSet)
}

type scanProgress struct {
	IP      string
	Current int
	Total   int
}

// 读取 ARP 表，主动 ARP 扫描整个网段，获取所有 IP 和 MAC
func getArpTable(ifaceName string) ([]Device, error) {
	var devices []Device

	// 获取本机网卡信息
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("无法获取网卡地址")
	}
	var srcIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			srcIP = ipnet.IP.To4()
			break
		}
	}
	if srcIP == nil {
		return nil, fmt.Errorf("未找到IPv4地址")
	}

	handle, err := pcap.OpenLive(ifaceName, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// 构造 ARP 请求并发送到整个网段
	ipMacMap := make(map[string]string)
	srcMAC := iface.HardwareAddr
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	// 监听 ARP 回复
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	_ = handle.SetBPFFilter("arp")

	targets := []net.IP{}
	for i := 1; i < 255; i++ {
		target := net.IPv4(srcIP[0], srcIP[1], srcIP[2], byte(i))
		targets = append(targets, target)
	}

	// 发送 ARP 请求
	for _, dstIP := range targets {
		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       bcast,
			EthernetType: layers.EthernetTypeARP,
		}
		arp := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte(srcMAC),
			SourceProtAddress: []byte(srcIP),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    []byte(dstIP.To4()),
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		_ = gopacket.SerializeLayers(buf, opts, eth, arp)
		_ = handle.WritePacketData(buf.Bytes())
	}

	// 收集 ARP 回复，最多等待 3 秒
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		packet, err := packetSource.NextPacket()
		if err != nil {
			continue
		}
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPReply {
				ip := net.IP(arp.SourceProtAddress).String()
				mac := net.HardwareAddr(arp.SourceHwAddress).String()
				if ip != "" && mac != "" {
					ipMacMap[ip] = mac
				}
			}
		}
	}
	for ip, mac := range ipMacMap {
		devices = append(devices, Device{IP: ip, MAC: mac})
	}
	return devices, nil
}

func main() {
	// 设置 slog 日志输出到文件
	logFile, err := os.OpenFile("hnuc.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("无法创建日志文件：", err)
	} else {
		h := slog.NewTextHandler(logFile, nil)
		slog.SetDefault(slog.New(h))
	}

	myApp := app.New()
	myWindow := myApp.NewWindow("局域网设备扫描")

	names, nameToSubnet, err := getAllInterfaces()
	if err != nil || len(names) == 0 {
		dialog.ShowError(fmt.Errorf("未找到可用网卡"), myWindow)
		return
	}
	selectedName := names[0]
	selectedSubnet := nameToSubnet[selectedName]
	selectedIfaceName := strings.Fields(selectedName)[0]

	remarks := loadRemarks()
	var devices []Device
	var table *widget.Table
	var scanBtn *widget.Button
	var ifaceSelect *widget.Select
	var ProgressBarInfinite *widget.ProgressBarInfinite
	var progressLabel *widget.Label

	refreshTable := func() {
		if table != nil {
			table.Refresh()
		}
	}

	table = widget.NewTable(
		func() (int, int) {
			return len(devices) + 1, 5 // IP, MAC, 备注, 状态, 编辑
		},
		func() fyne.CanvasObject {
			return container.NewStack(
				widget.NewLabel(""),
				widget.NewButton("", nil),
			)
		},
		func(id widget.TableCellID, o fyne.CanvasObject) {
			c := o.(*fyne.Container)
			label := c.Objects[0].(*widget.Label)
			btn := c.Objects[1].(*widget.Button)
			if id.Row == 0 {
				label.Show()
				btn.Hide()
				switch id.Col {
				case 0:
					label.SetText("IP")
				case 1:
					label.SetText("MAC")
				case 2:
					label.SetText("Remark/备注")
				case 3:
					label.SetText("Status")
				case 4:
					label.SetText("Edit/编辑")
				}
				return
			}
			dev := devices[id.Row-1]
			if id.Col == 4 {
				label.Hide()
				btn.Show()
				btn.SetIcon(theme.DocumentCreateIcon())
				btn.SetText("")
				btn.OnTapped = func() {
					entry := widget.NewEntry()
					entry.SetText(dev.Remark)
					d := dialog.NewForm("Remark/备注: "+dev.IP, "Save/保存", "Cancel/取消",
						[]*widget.FormItem{
							widget.NewFormItem("Remark/备注", entry),
						},
						func(ok bool) {
							if ok {
								remarks[dev.MAC] = entry.Text
								devices[id.Row-1].Remark = entry.Text
								saveRemarks(remarks)
								refreshTable()
							}
						}, myWindow)
					d.Show()
				}
			} else {
				btn.Hide()
				label.Show()
				switch id.Col {
				case 0:
					label.SetText(dev.IP)
				case 1:
					label.SetText(dev.MAC)
				case 2:
					label.SetText(dev.Remark)
				case 3:
					if dev.Online {
						label.SetText("✅")
					} else {
						label.SetText("🔴")
					}
				}
			}
		},
	)
	// 设置列宽和行高
	table.SetColumnWidth(0, 180) // IP列宽
	table.SetColumnWidth(1, 180) // MAC列宽
	table.SetColumnWidth(2, 200) // 备注列宽
	table.SetColumnWidth(3, 80)  // 状态列宽
	table.SetColumnWidth(4, 40)  // 编辑列宽
	table.SetRowHeight(0, 36)    // 表头高度

	for i := 1; i <= 255; i++ {
		table.SetRowHeight(i, 28) // 数据行高度
	}
	table.OnSelected = func(id widget.TableCellID) {
		if id.Row == 0 {
			return
		}
		// 双击
		dev := devices[id.Row-1]
		if id.Col <= 2 {
			var content string
			switch id.Col {
			case 0:
				content = dev.IP
			case 1:
				content = dev.MAC
			case 2:
				content = dev.Remark
			}
			clip := fyne.CurrentApp().Driver().AllWindows()[0].Clipboard()
			clip.SetContent(content)
			showToast(myWindow, "✅ Copy Success/复制成功")
		}
	}

	ifaceSelect = widget.NewSelect(names, func(name string) {
		selectedName = name
		selectedSubnet = nameToSubnet[name]
	})
	ifaceSelect.SetSelected(selectedName)

	scanBtn = widget.NewButtonWithIcon("扫描局域网(10s)", theme.SearchIcon(), func() {
		// 点击事件
		ProgressBarInfinite = widget.NewProgressBarInfinite()
		progressLabel = widget.NewLabel("")
		table.Hide()
		myWindow.SetContent(
			container.NewBorder(
				container.New(layout.NewVBoxLayout(), ifaceSelect, scanBtn, ProgressBarInfinite, progressLabel),
				nil, nil, nil,
				container.New(layout.NewStackLayout(),
					container.NewVScroll(table)),
			),
		)
		devices = nil
		progressChan := make(chan scanProgress)
		// 启动扫描
		go scanSubnet(selectedSubnet, progressChan, func(onlineIps map[string]struct{}) {
			// done 事件
			slog.Info("start arp")
			devs, err := getArpTable(selectedIfaceName)
			slog.Info("end arp")
			if err != nil {
				slog.Info("读取 ARP 表失败", "err", err)
				progressChan <- scanProgress{IP: "读取 ARP 表失败", Current: 254, Total: 254}
				close(progressChan)
				return
			}
			for _, d := range devs {
				remark := remarks[d.MAC]
				// 判断在线状态（已在ipSet中即为在线）
				online := false
				if _, ok := onlineIps[d.IP]; ok {
					online = true
				}
				devices = append(devices, Device{IP: d.IP, MAC: d.MAC, Remark: remark, Online: online})
			}
			// 按 IP 升序排序
			sort.Slice(devices, func(i, j int) bool {
				return ipLess(devices[i].IP, devices[j].IP)
			})
			slog.Info(fmt.Sprintf("扫描完成，共找到 %d 个设备\n", len(devices)))
			progressChan <- scanProgress{IP: "扫描完成", Current: 254, Total: 254}
			close(progressChan)
		})

		// goroutine监听进度并刷新UI（只刷新已存在控件内容，不用SetContent）
		go func() {
			for msg := range progressChan {
				fyne.CurrentApp().Driver().DoFromGoroutine(func() {
					if msg.IP == "扫描完成" {
						ProgressBarInfinite.Hide()
						progressLabel.Hide()
						table.Show()
						refreshTable()
					} else if msg.IP == "读取 ARP 表失败" {
						progressLabel.SetText("读取 ARP 表失败")
					}
				}, false)
			}
		}()
	})
	scanBtn.Theme()

	myWindow.SetContent(container.NewVBox(ifaceSelect, scanBtn))
	myWindow.Resize(fyne.NewSize(800, 600))
	myWindow.ShowAndRun()
}

// 显示自定义 toast
func showToast(win fyne.Window, msg string) {
	toast := widget.NewLabel(msg)
	bg := canvas.NewRectangle(&color.RGBA{0, 0, 0, 80})
	bg.SetMinSize(fyne.NewSize(120, 36))
	toast.TextStyle = fyne.TextStyle{
		Bold:      true,
		Italic:    false,
		Monospace: false,
		Symbol:    false,
		TabWidth:  0,
		Underline: false,
	}
	toast.Theme().Color(theme.ColorNameBackground, theme.VariantLight)
	toast.Alignment = fyne.TextAlignCenter
	box := container.NewMax(bg, container.NewCenter(toast))
	// 放在右下角
	//size := win.Canvas().Size()
	box.Move(fyne.NewPos(300, 30))
	box.Resize(fyne.NewSize(200, 36))
	win.Canvas().Overlays().Add(box)
	go func() {
		time.Sleep(1500 * time.Millisecond)
		fyne.CurrentApp().Driver().DoFromGoroutine(func() {
			win.Canvas().Overlays().Remove(box)
		}, false)
	}()
}

// 工具函数：IP字符串比较
func ipLess(a, b string) bool {
	ipa := net.ParseIP(a)
	ipb := net.ParseIP(b)
	if ipa == nil || ipb == nil {
		return a < b
	}
	ba := ipa.To4()
	bb := ipb.To4()
	if ba == nil || bb == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ba[i] != bb[i] {
			return ba[i] < bb[i]
		}
	}
	return false
}
