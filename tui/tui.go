package main

import (
	"fmt"
	"io"
	"time"

	"github.com/mosajjal/dnspot/server"
	"github.com/rivo/tview"
)

type TuiIO struct {
	in     chan string
	out    chan string
	logger io.Writer
}

// todo: this needs to be a parameter
const loglevel = 5

func (io TuiIO) Logger(level uint8, format string, args ...interface{}) {
	if level > loglevel {
		fmt.Fprintf(io.logger, format+"\n", args...)
	}
}
func (io TuiIO) GetInputFeed() chan string {
	return io.in
}
func (io TuiIO) GetOutputFeed() chan string {
	return io.out
}

// type CommandFromUi struct {
// 	Cmd   string
// 	Agent string
// }

// var CmdAndAgent chan CommandFromUi

func uiUpdater(root *tview.Application) {
	timeticker := time.NewTicker(1 * time.Second)
	idleAgentRemovalTicker := time.NewTicker(60 * time.Second)
	// runCmdTicker := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-timeticker.C:
			root.Draw()

		case <-idleAgentRemovalTicker.C:
			// RemoveIdleAgents()
		}
	}
}

func (io TuiIO) Handler() {
	for out := range io.out {
		io.Logger(4, out)
	}
}

func main() {
	UiRoot := tview.NewApplication()
	uiAgentList := tview.NewList()
	uiAgentList.SetTitle("Agents").SetBorder(true)
	// todo: set log level somewhere
	uiLogger := tview.NewTextView()
	uiLogger.SetTitle("Log").SetBorder(true)
	uiCmdInput := tview.NewForm()
	uiCmdInput.SetTitle("Command").SetBorder(true)

	var io TuiIO
	io.in = make(chan string, 1)
	io.out = make(chan string, 1)
	io.logger = uiLogger

	uiConfig := tview.NewForm()
	uiConfig.SetBorder(true).SetTitle("config")
	uiConfig.
		AddInputField("Listen Address", "", 0, nil, nil).
		AddInputField("Private Key", "", 0, nil, nil).
		AddInputField("DNS Suffix", "", 0, nil, nil).
		AddDropDown("Mode", []string{"chat", "exec"}, 0, nil).
		AddButton("Start Server", func() {
			_, mode := uiConfig.GetFormItemByLabel("Mode").(*tview.DropDown).GetCurrentOption()
			server.Config.Mode = mode
			server.Config.ListenAddress = uiConfig.GetFormItemByLabel("Listen Address").(*tview.InputField).GetText()
			server.Config.PrivateKeyBase36 = uiConfig.GetFormItemByLabel("Private Key").(*tview.InputField).GetText()
			server.Config.DnsSuffix = uiConfig.GetFormItemByLabel("DNS Suffix").(*tview.InputField).GetText()
			server.RunServer(io)
			uiCmdInput.SetFocus(0)
		})
	// sideBar := newPrimitive("Side Bar")
	uiCmdInput.
		AddInputField("Command", "", 0, nil, nil).
		AddButton("run", func() {
			// if UiAgentList.GetItemCount() == 0 {
			// 	return
			// }
			// agent, _ := UiAgentList.GetItemText(UiAgentList.GetCurrentItem())
			// pubkey, _ := cryptography.PublicKeyFromString(agent)
			// //todo: change this to another function that takes into account which mode is being used
			// // _ = SendMessageToAgent(pubkey, UiCmd.GetFormItem(0).(*tview.InputField).GetText())
			// fmt.Fprint(UiLog, UiCmd.GetFormItem(0).(*tview.InputField).GetText()) //todo:remove
			io.GetInputFeed() <- uiCmdInput.GetFormItem(0).(*tview.InputField).GetText()
			uiCmdInput.GetFormItem(0).(*tview.InputField).SetText("")
		})

	grid := tview.NewGrid().
		SetRows(-5, -1, -2).
		SetColumns(0, -3).
		SetBorders(false)

	// Layout for screens wider than 100 cells.
	grid.AddItem(uiAgentList, 0, 0, 1, 1, 0, 100, false).
		AddItem(uiConfig, 1, 0, 2, 1, 0, 100, true).
		AddItem(uiLogger, 0, 1, 2, 1, 0, 100, false).
		AddItem(uiCmdInput, 2, 1, 1, 1, 0, 100, false)

	go io.Handler()
	// refresh UI and remove idle nodes as a goroutine
	go uiUpdater(UiRoot)

	// below is a blocking code
	if err := UiRoot.SetRoot(grid, true).SetFocus(grid).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
