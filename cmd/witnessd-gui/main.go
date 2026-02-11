package main

import (
	"log"
	"os"

	"gioui.org/app"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget/material"

	"witnessd/cmd/witnessd-gui/internal/theme"
	"witnessd/cmd/witnessd-gui/internal/ui"
)

func main() {
	go func() {
		w := new(app.Window)
		w.Option(app.Title("Witnessd"))
		w.Option(app.Size(unit.Dp(1024), unit.Dp(768)))
		
		if err := loop(w); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}()
	app.Main()
}

func loop(w *app.Window) error {
	t := theme.NewTheme(material.NewTheme())
	
	// App state and UI components
	dashboard := ui.NewDashboard(t)

	var ops op.Ops
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			
			// Main Layout
			dashboard.Layout(gtx)
			
			e.Frame(gtx.Ops)
		}
	}
}
