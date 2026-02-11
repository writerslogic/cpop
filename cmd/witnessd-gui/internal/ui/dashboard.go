package ui

import (
	"image"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"witnessd/cmd/witnessd-gui/internal/theme"
)

// Dashboard is the main UI component.
type Dashboard struct {
	theme *theme.Theme
	
	// State for sidebar/navigation
	navList widget.List
	activeTab int
}

// NewDashboard creates a new dashboard.
func NewDashboard(t *theme.Theme) *Dashboard {
	return &Dashboard{
		theme: t,
		navList: widget.List{
			List: layout.List{
				Axis: layout.Vertical,
			},
		},
	}
}

// Layout renders the dashboard.
func (d *Dashboard) Layout(gtx layout.Context) layout.Dimensions {
	// Fill background
	paint.Fill(gtx.Ops, d.theme.Palette.Background)

	return layout.Flex{
		Axis: layout.Horizontal,
	}.Layout(gtx,
		// Sidebar (Navigation)
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Dp(240)
			gtx.Constraints.Max.X = gtx.Dp(240)
			return d.layoutSidebar(gtx)
		}),
		
		// Vertical Divider
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			size := image.Pt(gtx.Dp(1), gtx.Constraints.Max.Y)
			rect := clip.Rect{Max: size}.Op()
			paint.FillShape(gtx.Ops, d.theme.Palette.Border, rect)
			return layout.Dimensions{Size: size}
		}),

		// Main Content Area
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return d.layoutContent(gtx)
		}),
	)
}

func (d *Dashboard) layoutSidebar(gtx layout.Context) layout.Dimensions {
	return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				title := material.H6(d.theme.Theme, "WITNESSD")
				title.Color = d.theme.Palette.Primary
				title.TextSize = d.theme.Config.FontTitle
				return title.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(32)}.Layout),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				// Sidebar items would go here
				return layout.Dimensions{Size: gtx.Constraints.Max}
			}),
		)
	})
}

func (d *Dashboard) layoutContent(gtx layout.Context) layout.Dimensions {
	return layout.UniformInset(d.theme.Config.Padding).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				h := material.H5(d.theme.Theme, "Evidence Timeline")
				h.Color = d.theme.Palette.Text
				return h.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				// Placeholder for Timeline / Explorer
				return d.drawPlaceholder(gtx, "Visual Explorer Placeholder")
			}),
		)
	})
}

func (d *Dashboard) drawPlaceholder(gtx layout.Context, label string) layout.Dimensions {
	size := gtx.Constraints.Max
	rect := clip.UniformRRect(image.Rect(0, 0, size.X, size.Y), int(gtx.Dp(d.theme.Config.CornerRadius))).Op(gtx.Ops)
	paint.FillShape(gtx.Ops, d.theme.Palette.Surface, rect)
	
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		l := material.Body1(d.theme.Theme, label)
		l.Color = d.theme.Palette.TextMuted
		return l.Layout(gtx)
	})
}
