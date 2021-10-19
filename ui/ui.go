package ui

import (
	"context"

	"github.com/mum4k/termdash/terminal/tcell"

	"github.com/mum4k/termdash"
	"github.com/mum4k/termdash/container"
	"github.com/mum4k/termdash/linestyle"
	"github.com/mum4k/termdash/terminal/terminalapi"
	"github.com/mum4k/termdash/widgets/text"
	"github.com/mum4k/termdash/widgets/textinput"
)

func errorHandler(err error) {
	if err != nil {
		panic(err.Error())
	}
}

// todo: potentially select and highlight this
var UiAgentList, _ = text.New(text.RollContent(), text.WrapAtRunes())

// todo: submit button to clear and send output to another function
var UiCmd, _ = textinput.New()

// todo: set log level somewhere
var UiLog, _ = text.New(text.RollContent(), text.WrapAtWords())

func RunTui() {
	t, err := tcell.New()
	errorHandler(err)
	defer t.Close()

	ctx, cancel := context.WithCancel(context.Background())

	c, err := container.New(
		t,
		container.Border(linestyle.Light),
		container.BorderTitle("PRESS Q TO QUIT"),
		container.SplitHorizontal(
			container.Top(
				container.SplitVertical(
					container.Left(
						container.Border(linestyle.Light),
						container.BorderTitle("Agent List"),
						container.PlaceWidget(UiAgentList),
					),
					container.Right(
						container.Border(linestyle.Light),
						container.BorderTitle("Output"),
						container.PlaceWidget(UiLog),
					),
					container.SplitPercent(30),
				),
			),
			container.Bottom(
				container.Border(linestyle.Light),
				container.BorderTitle("Command to run"),
				container.PlaceWidget(UiCmd),
			),
			container.SplitPercent(90),
		),
	)
	errorHandler(err)

	quitter := func(k *terminalapi.Keyboard) {
		if k.Key == 'q' || k.Key == 'Q' {
			cancel()
		}
	}

	if err := termdash.Run(ctx, t, c, termdash.KeyboardSubscriber(quitter)); err != nil {
		panic(err)
	}
}
