package server

// import (
// 	"time"

// 	"github.com/mosajjal/dnspot/cryptography"
// 	"github.com/rivo/tview"
// )

// type CommandFromUi struct {
// 	Cmd   string
// 	Agent string
// }

// var CmdAndAgent chan CommandFromUi

// // todo: potentially select and highlight this
// var UiAgentList = tview.NewList()

// // todo: submit button to clear and send output to another function
// var UiCmd = tview.NewForm()

// // todo: set log level somewhere
// var UiLog = tview.NewTextView()

// var UiRoot = tview.NewApplication()

// func uiUpdater() {
// 	timeticker := time.NewTicker(1 * time.Second)
// 	idleAgentRemovalTicker := time.NewTicker(60 * time.Second)
// 	// runCmdTicker := time.NewTicker(30 * time.Second)
// 	for {
// 		select {
// 		case <-timeticker.C:
// 			UiRoot.Draw()

// 		case <-idleAgentRemovalTicker.C:
// 			RemoveIdleAgents()
// 		}
// 	}
// }

// func RunTui() {
// 	UiAgentList.SetTitle("Agents").SetBorder(true)
// 	UiCmd.SetTitle("Command").SetBorder(true)
// 	UiLog.SetTitle("Log").SetBorder(true)
// 	// sideBar := newPrimitive("Side Bar")
// 	UiCmd.
// 		AddInputField("Command", "", 0, nil, nil).
// 		AddButton("Save", func() {
// 			if UiAgentList.GetItemCount() == 0 {
// 				return
// 			}
// 			agent, _ := UiAgentList.GetItemText(UiAgentList.GetCurrentItem())
// 			pubkey, _ := cryptography.PublicKeyFromString(agent)
// 			//todo: change this to another function that takes into account which mode is being used
// 			_ = SendMessageToAgent(pubkey, UiCmd.GetFormItem(0).(*tview.InputField).GetText())
// 			UiCmd.GetFormItem(0).(*tview.InputField).SetText("")
// 		})

// 	grid := tview.NewGrid().
// 		SetRows(-5, 0).
// 		SetColumns(0, -2).
// 		SetBorders(false)

// 	// Layout for screens wider than 100 cells.
// 	grid.AddItem(UiAgentList, 0, 0, 1, 1, 0, 100, false).
// 		AddItem(UiLog, 0, 1, 1, 1, 0, 100, false).
// 		AddItem(UiCmd, 1, 0, 1, 2, 0, 100, true)

// 	// refresh UI and remove idle nodes as a goroutine
// 	go uiUpdater()

// 	if err := UiRoot.SetRoot(grid, true).SetFocus(grid).EnableMouse(true).Run(); err != nil {
// 		panic(err)
// 	}

// }
