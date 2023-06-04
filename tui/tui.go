package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/mosajjal/dnspot/cryptography"
	"github.com/mosajjal/dnspot/server"
	"github.com/rivo/tview"
)

type tuiIO struct {
	in        chan server.InMsg
	out       chan string
	logger    io.Writer
	logLvl    uint8
	ctx       context.Context
	ctxCancel context.CancelFunc
}

func (io tuiIO) Logger(level uint8, format string, args ...interface{}) {
	if level >= io.logLvl {
		fmt.Fprintf(io.logger, format+"\n", args...)
	}
}
func (io tuiIO) GetInputFeed() chan server.InMsg {
	return io.in
}
func (io tuiIO) GetOutputFeed() chan string {
	return io.out
}
func (io tuiIO) GetContext() context.Context {
	return io.ctx
}

// type CommandFromUi struct {
// 	Cmd   string
// 	Agent string
// }

// var CmdAndAgent chan CommandFromUi

func uiUpdater(s server.Server, root *tview.Application, agentList *tview.List) {
	timeticker := time.NewTicker(1 * time.Second)
	idleAgentRemovalTicker := time.NewTicker(60 * time.Second)
	// runCmdTicker := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-timeticker.C:
			root.Draw()
			// clear the list
			agentList = agentList.Clear()
			// add the agents
			for _, agent := range s.ListAgents() {
				agentList.AddItem(agent, "", 0, nil)
			}

		case <-idleAgentRemovalTicker.C:
			// RemoveIdleAgents()
		}
	}
}

func (io tuiIO) Handler() {
	for out := range io.out {
		io.Logger(server.INFO, out)
	}
}

func main() {

	s := server.New()

	UIRoot := tview.NewApplication()
	uiAgentList := tview.NewList()
	uiAgentList.SetTitle("Agents").SetBorder(true)
	uiLogger := tview.NewTextView()
	uiLogger.SetTitle("Log").SetBorder(true)
	uiCmdInput := tview.NewForm()
	uiCmdInput.SetTitle("Command").SetBorder(true)

	var io tuiIO
	io.in = make(chan server.InMsg, 1)
	io.out = make(chan string, 1)
	io.ctx, io.ctxCancel = context.WithCancel(context.Background())
	io.logger = uiLogger

	uiCmdInput.
		AddInputField("Command", "", 0, nil, nil).
		AddButton("run", func() {
			// if UiAgentList.GetItemCount() == 0 {
			// 	return
			// }
			agent, _ := uiAgentList.GetItemText(uiAgentList.GetCurrentItem())
			// pubkey, _ := cryptography.PublicKeyFromString(agent)
			// //todo: change this to another function that takes into account which mode is being used
			// // _ = SendMessageToAgent(pubkey, UiCmd.GetFormItem(0).(*tview.InputField).GetText())
			// fmt.Fprint(UiLog, UiCmd.GetFormItem(0).(*tview.InputField).GetText()) //todo:remove
			io.GetInputFeed() <- server.InMsg{Agent: agent, Prompt: uiCmdInput.GetFormItem(0).(*tview.InputField).GetText()}
			uiCmdInput.GetFormItem(0).(*tview.InputField).SetText("")
		})

	uiConfig := tview.NewForm()
	uiConfig.SetBorder(true).SetTitle("config")
	uiConfig.
		AddInputField("Listen Address", "0.0.0.0:53", 0, nil, nil).
		AddInputField("Private Key", func() string { s, _ := cryptography.GenerateKey(); return string(s.String()) }(), 0, nil, nil).
		AddInputField("DNS Suffix", "yourdomain.com", 0, nil, nil).
		AddDropDown("Mode", []string{"chat", "exec"}, 0, nil).
		AddDropDown("Log Level", []string{"debug", "info", "warn", "error", "fatal"}, 0, nil).
		AddButton("Start Server", func() {
			_, mode := uiConfig.GetFormItemByLabel("Mode").(*tview.DropDown).GetCurrentOption()
			s.Mode = mode
			s.ListenAddress = uiConfig.GetFormItemByLabel("Listen Address").(*tview.InputField).GetText()
			s.PrivateKeyBase36 = uiConfig.GetFormItemByLabel("Private Key").(*tview.InputField).GetText()
			s.DNSSuffix = uiConfig.GetFormItemByLabel("DNS Suffix").(*tview.InputField).GetText()
			logLevel, _ := uiConfig.GetFormItemByLabel("Log Level").(*tview.DropDown).GetCurrentOption()
			io.logLvl = uint8(logLevel)
			// do some basic validation
			if s.ListenAddress == "" || s.PrivateKeyBase36 == "" || s.DNSSuffix == "" {
				fmt.Fprintln(uiLogger, "Please fill all the fields")
				return
			}

			go func() {
				err := s.RunServer(io)
				if err != nil {
					fmt.Fprintln(uiLogger, err)
				}
				// re-enable start button
				uiConfig.GetButton(uiConfig.GetButtonIndex("Start Server")).SetDisabled(false)
				uiConfig.GetButton(uiConfig.GetButtonIndex("Stop Server")).SetDisabled(true)
			}()
			uiConfig.GetButton(uiConfig.GetButtonIndex("Start Server")).SetDisabled(true)
			uiConfig.GetButton(uiConfig.GetButtonIndex("Stop Server")).SetDisabled(false)
			UIRoot.SetFocus(uiCmdInput)
		}).
		AddButton("Stop Server", func() {
			io.ctxCancel()
			// sleep 200ms
			time.Sleep(200 * time.Millisecond)
			io.ctx, io.ctxCancel = context.WithCancel(context.Background())
			fmt.Fprintln(uiLogger, "stopping server")
			uiConfig.GetButton(uiConfig.GetButtonIndex("Stop Server")).SetDisabled(true)
			uiConfig.GetButton(uiConfig.GetButtonIndex("Start Server")).SetDisabled(false)
		})
	// sideBar := newPrimitive("Side Bar")
	// hide stop server button until server is started
	uiConfig.GetButton(uiConfig.GetButtonIndex("Stop Server")).SetDisabled(true)

	grid := tview.NewGrid().
		SetRows(-5, -1, -2).
		SetColumns(0, -3).
		SetBorders(false)

	// Layout for screens wider than 100 cells.
	grid.AddItem(uiAgentList, 0, 0, 1, 1, 0, 100, false).
		AddItem(uiConfig, 1, 0, 3, 1, 0, 100, true).
		AddItem(uiLogger, 0, 1, 2, 1, 0, 100, false).
		AddItem(uiCmdInput, 2, 1, 1, 1, 0, 100, false)

	go io.Handler()
	// refresh UI and remove idle nodes as a goroutine
	go uiUpdater(s, UIRoot, uiAgentList)

	// below is a blocking code
	if err := UIRoot.SetRoot(grid, true).SetFocus(grid).EnableMouse(true).Run(); err != nil {
		// show an error modal and continue
		m := tview.NewModal().
			SetText(fmt.Sprintf("Error: %s", err)).
			AddButtons([]string{"Ok"}).
			SetDoneFunc(func(buttonIndex int, buttonLabel string) {
				UIRoot.Stop()
			})
		UIRoot.SetRoot(m, false)
		// panic(err)
	}
}
